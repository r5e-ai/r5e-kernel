defmodule R5e.Commit do
  @moduledoc """
  The compare-and-append half of the commit protocol (spec/05 §7).

  `authorize` runs optimistically, with no lock and no promise that what
  it read is still true. What makes that safe is this module: everything
  the pipeline *read* between `resolve` and `record` is captured, and the
  capture is re-checked under the append lock immediately before the
  event is written. If anything moved, nothing is appended and the
  admission retries from `resolve`.

  ## What is captured

  §7's three reads, under the three keys of the capture map:

  | capture | read by | compared against |
  |---|---|---|
  | `"policy"` | the policy engine, reported as `generations` on its meta (see `R5e.Policy`) | the store entry's `admissionSeq` now |
  | `"kinds"` | `resolve`, one per `kind`-class manifest entry | the same |
  | `"anchors"` | `resolve`, one per `sameAnchor` manifest entry | `R5e.Resolve.head/4` now |

  ## Why the store, and why that is exact

  The re-check reads the resource store, not the log, because the store
  is what `resolve` read and what §4 defines an admitted instance to be
  ("a granted admission whose substrate write succeeded"). That is only
  exact if no admission can be *between* its append and its store write
  while this check runs — so `R5e.Log` performs the substrate write
  inside the same `handle_call` that appends. One lock, and record and
  admit are on the same side of it. The order within it is unchanged and
  still the one the gap argument needs: the event is written to the log
  first, the substrate second.

  ## Cost

  Policy and `kind` generations are store lookups: O(1) each, and there
  are usually none or one. A `sameAnchor` head is not indexed and is
  recomputed from the chain — O(chain), inside the lock, on the small
  number of admissions that declare one. The log is read from disk rather
  than through `R5e.Log`, because this runs *inside* that GenServer.
  """

  @typedoc "Everything one admission read that a later admission could move."
  @type capture :: %{String.t() => term()}

  @doc """
  Capture what this admission read: the policy engine's `generations`,
  every `kind`-ref generation in the resolution manifest, and every
  `sameAnchor` head.

  Always returns a map — an empty one when the admission read nothing
  that can move. An empty capture is not the same as no capture: a
  granted admission always carries one (and so can be contended), while
  a denial record carries `nil` (and so can never be).
  """
  @spec capture(map(), map() | nil) :: capture()
  def capture(request, policy) do
    manifest = request[:resolved] || []

    %{
      "policy" => policy_generations(policy),
      "kinds" => kind_generations(manifest),
      "anchors" => anchors(manifest, request[:spec] || %{}),
      "expires" => request[:expires],
      # §6: the succession-graph version **as of the first read of the
      # relation** — with the stage that read it, because a mismatch
      # retries from there — and the events the authority walk visited.
      # The first is a **retry** (the relation moved, so the decision has
      # to be made again) and the second is **terminal** (a revocation and
      # an expiry cannot be undone by asking a second time). An admission
      # that never consulted the relation captures `nil` and cannot be
      # contended on it.
      "succession" => R5e.Succession.first_read(),
      "authority" => R5e.Authority.snapshot(request[:authority_visited] || [])
    }
  end

  @doc """
  §6's **terminal** re-checks: the facts that, having moved, cannot be
  made true again by re-running the pipeline. Returns `nil` or the reason
  the admission is denied at stage `record`.

  All three of §6's are here: `authority revoked at <seq>` and `authority
  out of term` (from `R5e.Authority.moved/2`, over the events the walk
  visited) and `expired`. Each is terminal because time does not move
  back and a Revocation is not undone by asking again — retrying would
  spend the budget and reach the same answer.

  It runs **inside the append lock**, against the clock the kernel is
  about to write with, which is the whole content of §6's sentence: a
  check made before the lock is a check about a moment that has passed.
  """
  @spec terminal(capture() | nil, String.t() | nil) :: nil | String.t()
  def terminal(capture, ts \\ nil)

  def terminal(nil, _ts), do: nil

  def terminal(capture, ts) when is_map(capture) do
    # §5/§6: the *truncated* instant this event will carry, so the term
    # re-check under the lock and the `ts` on the record are one value.
    # `R5e.Log` reads it once and hands it here and to `build_event/5`.
    ts = ts || R5e.Clock.ts()

    R5e.Authority.moved(capture["authority"] || [], ts) ||
      expired(capture["expires"])
  end

  def terminal(_capture, _ts), do: nil

  defp expired(expires) when not is_binary(expires), do: nil

  defp expired(expires) do
    with {:ok, at} <- RecurseVerify.Instant.parse(expires),
         horizon = DateTime.add(R5e.Clock.now(), -R5e.Admission.expiry_skew(), :second),
         :gt <- DateTime.compare(at, horizon) do
      nil
    else
      {:error, _reason} -> nil
      _not_after -> "expired"
    end
  end

  @doc "Does this capture read anything at all?"
  @spec empty?(capture()) :: boolean()
  def empty?(%{"policy" => p, "kinds" => k, "anchors" => a}),
    do: p == %{} and k == [] and a == []

  def empty?(_capture), do: true

  @doc """
  Re-check a capture against the kernel as it stands **now**. Returns
  `nil` when nothing moved, or a sentence naming what did — the string
  that becomes the `contended:` reason after the last retry, so it has to
  say which fact changed and from what to what.
  """
  @spec stale(capture() | nil) :: nil | String.t()
  def stale(nil), do: nil

  def stale(capture) do
    stale_policy(capture["policy"] || %{}) ||
      stale_kinds(capture["kinds"] || []) ||
      stale_anchors(capture["anchors"] || []) ||
      stale_succession(capture["succession"])
  end

  @doc """
  The stage a `{:retry, …}` should re-run from (§6).

  `resolve` for everything the commit protocol has always captured, and
  `validateStructure` when the fact that moved is the succession relation
  and it was first read there — by `admitBy` or `readmitBy`, which settle
  the instance's *name*. A name decided against a relation that has since
  changed has to be decided again, and re-running from `resolve` would
  keep it.
  """
  @spec retry_from(capture() | nil) :: String.t()
  def retry_from(%{"succession" => %{stage: stage, version: captured}}) do
    if R5e.Succession.version() == captured, do: "resolve", else: stage
  end

  def retry_from(_capture), do: "resolve"

  # §6: every admitted Succession and every Revocation of one moves this.
  # An admission that resolved `matches/3`, a `head`, or an authority
  # subject against the relation cannot commit against a different one.
  defp stale_succession(nil), do: nil

  defp stale_succession(%{stage: stage, version: captured}) do
    now = R5e.Succession.version()

    if now == captured,
      do: nil,
      else: "the succession relation moved (version #{captured} → #{now}, read at #{stage})"
  end

  # -- capture -----------------------------------------------------------

  # The one additive key in the policy meta contract (§7): a map of
  # `g/v/K/name` to the admission seq the engine read it at. An engine
  # that reads nothing returns `%{}`; an engine that predates the key is
  # treated as having read nothing, because a kernel that guessed
  # otherwise would deny admissions on a generation nobody captured.
  defp policy_generations(policy) when is_map(policy) do
    case policy["generations"] do
      map when is_map(map) ->
        Map.new(map, fn {ref, seq} -> {to_string(ref), seq} end)
        |> Map.filter(fn {_ref, seq} -> is_integer(seq) end)

      _ ->
        %{}
    end
  end

  defp policy_generations(_policy), do: %{}

  defp kind_generations(manifest) do
    for entry <- manifest,
        is_map(entry),
        entry["class"] == "kind",
        is_binary(entry["value"]),
        is_integer(entry["generation"]) do
      %{"ref" => entry["value"], "generation" => entry["generation"]}
    end
  end

  # A `sameAnchor` entry records the head it observed (§4, B3). What it
  # does not record is the anchor *value*, because that is in the
  # submitting spec at the field the entry names — so it is read back
  # from there rather than duplicated onto the record.
  defp anchors(manifest, spec) do
    for entry <- manifest,
        is_map(entry),
        entry["class"] == "event",
        is_binary(entry["anchorField"]),
        is_binary(entry["head"]) do
      %{
        "kind" => entry["targetKind"],
        "field" => entry["anchorField"],
        "anchor" => R5e.Canonical.encode(spec[entry["anchorField"]]),
        "head" => entry["head"]
      }
    end
  end

  # -- re-check ----------------------------------------------------------

  defp stale_policy(generations) do
    generations
    |> Enum.sort()
    |> Enum.find_value(fn {ref, seq} ->
      case generation_now(ref) do
        ^seq -> nil
        now -> "the policy engine read #{ref} at generation #{seq}; it is now #{now}"
      end
    end)
  end

  defp stale_kinds(kinds) do
    Enum.find_value(kinds, fn %{"ref" => ref, "generation" => seq} ->
      case generation_now(ref) do
        ^seq -> nil
        now -> "the kind ref #{ref} resolved at generation #{seq}; it is now #{now}"
      end
    end)
  end

  defp stale_anchors([]), do: nil

  defp stale_anchors(anchors) do
    events = granted_events()

    Enum.find_value(anchors, fn %{"kind" => kind, "field" => field, "head" => head} = anchor ->
      case head_now(events, kind, field, anchor["anchor"]) do
        ^head -> nil
        now -> "the #{kind} head for #{inspect(field)} was #{head}; it is now #{now}"
      end
    end)
  end

  # The current generation of a resource ref, as a string for the reason
  # line: the integer when there is a live entry, and a named absence
  # otherwise. "gone" is reachable in principle (a store the log has not
  # been replayed into) and is reported rather than crashed on.
  defp generation_now(ref) do
    with {:ok, group, version, kind, name} <- R5e.Refs.split_kind_ref(ref),
         {:ok, entry, _lineage} <- R5e.ResourceStore.get(group, version, kind, name) do
      case entry["supersededBy"] do
        nil -> entry["admissionSeq"]
        by -> "displaced (supersededBy #{by})"
      end
    else
      _ -> "gone — no admitted instance of that name is on the store"
    end
  end

  # §4's head, re-read: the same function `resolve` snapshotted it with
  # (`R5e.Resolve.head/4`), over the log on disk because this runs inside
  # the process that owns it.
  defp head_now(events, kind, field, anchor) do
    case R5e.Resolve.head(events, kind, field, anchor) do
      nil -> "gone — no admitted #{kind} anchors on that value"
      event -> "event:" <> event["hash"]
    end
  end

  defp granted_events do
    for event <- R5e.Log.read_events(),
        event["kind"] == "admission.granted",
        {:ok, payload} <- [R5e.Log.payload(event)],
        do: {event, payload}
  end
end
