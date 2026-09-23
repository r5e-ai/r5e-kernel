defmodule R5e.Policy do
  @moduledoc """
  Authorization hook for the admission pipeline (spec/02: authorize at
  admission, never merely after the fact). Configure the active module via
  `config :r5e, policy: MyPolicy`.

  A policy may return metadata about the decision it made. Admission records
  it verbatim under `"policy"` on the event payload and the receipt, so a
  reader of the log can tell which engine decided and — when the engine binds
  to an admitted policy resource — which policy text it decided under.
  Engine-specific metadata is copied without interpretation. The kernel validates
  shared receipt fields and merges the resource generations captured by Facts;
  a failure in those contracts wraps and retains the engine's evidence.

  `policy_meta` is a JSON-encodable map with string keys:

  | Key | Value |
  |---|---|
  | `"engine"` | required, e.g. `"allow-all"`, `"cedar"` |
  | `"decision"` | `"allow"`, `"deny"`, or `"error"` |
  | `"bundle"` | CAS address (`sha256:…`) of the admitted policy the decision was made under, or `nil` |
  | `"bundleRef"` | `group/version/Kind/name` of that resource, or `nil` |
  | `"matched"` | list of policy id strings that matched |
  | `"generations"` | map of `"group/version/Kind/name"` to the admission seq that resource was read at — see below |
  | `"derivedObjects"` | list of `bytes:sha256:…` addresses the engine wrote during this decision — see below |

  ## Reported and tracked reads

  `generations` (spec/05 §7) reports the mutable resources an engine read.
  Reads through `R5e.Policy.Facts` are captured by the kernel and merged
  into this map before commit, even when the engine omits its report.
  Conflicting generations or failed Facts reads refuse the decision with
  `"decision" => "error"`; adapters cannot ignore these failures and allow.
  Other reads must still be reported by the engine. `derivedObjects` (§5)
  reports objects it wrote; the kernel never infers authorship of bytes.
  `R5e.Policy.AllowAll` reports both empty because it reads and writes nothing.

  What each is *for* is in the section that defines it; what happens here:

    * `generations` — `R5e.Commit` re-checks each under the append lock
      and retries the decision if one moved. Entries whose value is not an
      integer are ignored, and an entry naming a resource that is no
      longer on the store counts as moved.
    * `derivedObjects` — `R5e.Admission` copies the list onto the event
      payload beside `"policy"`, and `R5e.RefIndex.observe/2` reads it
      back at every replay, which is what makes §5's class a fact the
      *chain* carries rather than one this process holds.
      `RefIndex.register_derived/2` alone does not survive a boot: an
      export taken after a restart listed `derivedObjects: []` and its
      verifier reported every evaluation citation as a finding.

  `decide/1` checks the **form** of each `derivedObjects` entry — a
  well-formed `bytes:sha256:<64 hex>` string — and nothing else. Whether
  the object is really in the CAS is the offline verifier's question
  (amendment C6), not the gate's; the kernel does not second-guess what an
  engine wrote. A malformed entry is not a claim at all, though — it
  cannot be cited, swept or replayed — so it is refused as a malformed
  answer and the admission is denied at `authorize`.

  ## What the request carries

  The request map is the one `R5e.Admission` documents, plus **four keys
  the gate settles before this stage runs**. All four are the kernel's
  own answers, not the caller's claims, and all four are on the record
  the receipt returns — so an engine decides on exactly the facts a
  reader of the chain will see.

  | Key | What it is |
  |---|---|
  | `:resolved` | the **resolution manifest** (spec/05 §4): `%{"path" => pointer, "class" => class, "value" => ref, …}` for every ref the spec cites, sorted by pointer — what the request *points at*, already looked up |
  | `:resolved_authority` | §5's `resolvedAuthority`: one entry per cited authority, each carrying the whole chain of links to its root. Handed over whole, so an engine never fetches — an engine that had to reach back into the chain to see what an actor was permitted would be reading a different record from the one the receipt shows |
  | `:authority_refs` | contract §11 (KS-7): the cited refs, sorted. **Always present**; `[]` says "acted as itself", which is a fact a rule may want, and an absent key would make it indistinguishable from an engine that forgot to look |
  | `:authority_roots` | §11: the distinct root actors of those chains, sorted — the keys a reader would have to have pinned for this act to resolve |

  Two more are set at the same point and are the kernel's own business:
  `:authority_visited` (§6's capture list, re-checked under the append
  lock) and `:depth` (the value `record` writes on an Endorsement or
  Badge). An engine may read them; nothing promises they will not move.

  `R5e.Policy.AllowAll` ignores all of it.

  Engines may add their own keys. Because `"bundle"` is a `sha256:` string
  inside the payload, `R5e.Export`'s ref sweep copies the cited policy text
  into the bundle's CAS with no export change.
  """

  @typedoc "JSON-encodable decision metadata, string keys. See the moduledoc."
  @type policy_meta :: %{required(String.t()) => term()}

  @doc """
  Decide whether `request` (see `R5e.Admission` for the shape) may proceed.
  Return `:ok` to allow or `{:deny, reason}` — the denial itself is recorded
  on the log; requests are acts. The three-element and metadata-carrying
  forms additionally say who decided and under what.
  """
  @callback authorize(request :: map()) ::
              :ok | {:ok, policy_meta} | {:deny, String.t()} | {:deny, String.t(), policy_meta}

  def active, do: Application.get_env(:r5e, :policy, R5e.Policy.AllowAll)

  @doc """
  Run the active policy and normalize its answer to a metadata-carrying form.

  A bare `:ok` / `{:deny, reason}` from a policy that predates the metadata
  contract is recorded as engine `"unknown"` — the kernel does not know what
  decided, and says so rather than guessing. Any answer outside the callback
  contract fails closed: the request is denied with `"decision" => "error"`,
  so a broken engine leaves a receipt rather than a silent allow. A policy
  that *raises* is left to raise — that is a bug in the engine, and rescuing
  it here would hide it behind a denial that looks deliberate.

  The one part of the metadata that is *checked* rather than copied is
  `derivedObjects` (see the moduledoc): its entries must be well-formed
  `bytes:sha256:…` addresses, because the kernel is about to write them
  onto the payload where replay, the export sweep and the verifier will
  all read them as addresses. A malformed one is a malformed answer, and
  is denied like any other.
  """
  @spec decide(map()) :: {:ok, policy_meta} | {:deny, String.t(), policy_meta}
  def decide(request) do
    R5e.Policy.Facts.run(fn -> active().authorize(request) end, fn answer, reads ->
      normalized =
        case answer do
          :ok ->
            {:ok, unknown_meta("allow")}

          {:ok, meta} when is_map(meta) ->
            checked(meta, {:ok, meta})

          {:deny, reason} when is_binary(reason) ->
            {:deny, reason, unknown_meta("deny")}

          {:deny, reason, meta} when is_binary(reason) and is_map(meta) ->
            checked(meta, {:deny, reason, meta})

          other ->
            {:deny, malformed(inspect(other, limit: 5)), unknown_meta("error")}
        end

      tracked(normalized, reads)
    end)
  end

  defp tracked(answer, reads) do
    meta = elem(answer, tuple_size(answer) - 1)
    reported = meta["generations"] || %{}

    conflict =
      if is_map(reported) do
        Enum.any?(reads.generations, fn {ref, seq} ->
          Map.has_key?(reported, ref) and reported[ref] != seq
        end)
      else
        map_size(reads.generations) > 0
      end

    cond do
      reads.error != nil ->
        {:deny, "kernel policy facts failed: " <> reads.error,
         facts_error_meta(answer, reads.generations, "factsInvalid")}

      conflict ->
        R5e.Policy.Facts.invalidate("conflicting policy fact generations")

        {:deny, "kernel policy facts failed: conflicting generations",
         facts_error_meta(answer, reads.generations, "conflictingGenerations")}

      map_size(reads.generations) == 0 ->
        answer

      true ->
        meta = Map.put(meta, "generations", Map.merge(reported, reads.generations))
        put_elem(answer, tuple_size(answer) - 1, meta)
    end
  end

  # A facts failure is a kernel composition failure, not a rewrite of an
  # evaluation that already happened. Keep its evidence beneath the wrapper.
  defp facts_error_meta(answer, captured, reason) do
    meta = elem(answer, tuple_size(answer) - 1)
    outcome = if elem(answer, 0) == :ok, do: "allow", else: "deny"
    upstream_reason = if tuple_size(answer) == 3, do: elem(answer, 1), else: nil
    reported = if is_map(meta["generations"]), do: meta["generations"], else: %{}

    nonconflicting =
      Map.reject(reported, fn {ref, seq} ->
        not is_integer(seq) or (Map.has_key?(captured, ref) and captured[ref] != seq)
      end)

    unknown_meta("error")
    |> Map.merge(%{
      "engine" => "kernel-policy-facts",
      "evaluated" => false,
      "reason" => reason,
      "upstreamPolicy" => meta,
      "upstreamOutcome" => outcome,
      "upstreamReason" => upstream_reason,
      "generations" => Map.merge(nonconflicting, captured),
      "derivedObjects" => Map.get(meta, "derivedObjects", [])
    })
  end

  # The engine's answer stands unless the form of `derivedObjects` is
  # wrong. Only the form: §5 puts the "are those bytes really there"
  # question in the verifier (amendment C6), and a gate that answered it
  # would be deciding what an engine wrote rather than recording it.
  defp checked(meta, answer) do
    case metadata_defect(meta) || derived_defect(meta) do
      nil ->
        answer

      defect ->
        # Keep usable evidence without promoting rejected derived-address claims.
        safe =
          try do
            if metadata_defect(meta), do: raise(ArgumentError, "invalid metadata")
            R5e.Canonical.encode(meta)

            valid =
              if is_list(meta["derivedObjects"]),
                do: Enum.filter(meta["derivedObjects"], &derived_address?/1),
                else: []

            Map.put(meta, "derivedObjects", valid)
          rescue
            _ -> unknown_meta("error")
          end

        upstream = put_elem(answer, tuple_size(answer) - 1, safe)

        wrapped =
          facts_error_meta(upstream, %{}, "malformedPolicyMetadata")
          |> Map.put("metadataDefect", defect)

        {:deny, malformed(defect), wrapped}
    end
  end

  defp metadata_defect(meta) do
    if json_term?(meta),
      do: nil,
      else: "metadata must contain canonical JSON values with string keys"
  rescue
    _ -> "metadata must contain canonical JSON values with string keys"
  end

  defp json_term?(term) when is_map(term),
    do:
      Enum.all?(term, fn {key, value} ->
        is_binary(key) and String.valid?(key) and json_term?(value)
      end)

  defp json_term?(term) when is_list(term), do: Enum.all?(term, &json_term?/1)
  defp json_term?(term) when is_binary(term), do: String.valid?(term)
  defp json_term?(term), do: is_integer(term) or term in [true, false, nil]

  defp derived_defect(meta) do
    case Map.fetch(meta, "derivedObjects") do
      :error ->
        nil

      {:ok, list} when is_list(list) ->
        case Enum.reject(list, &derived_address?/1) do
          [] -> nil
          bad -> "derivedObjects entries must be bytes:sha256:<hex>, " <> inspect(bad, limit: 5)
        end

      {:ok, other} ->
        "derivedObjects must be a list of addresses, got " <> inspect(other, limit: 5)
    end
  end

  defp derived_address?(address), do: R5e.Refs.bytes_address?(address)

  defp malformed(detail), do: "policy returned a malformed answer: " <> detail

  defp unknown_meta(decision) do
    %{
      "engine" => "unknown",
      "decision" => decision,
      "bundle" => nil,
      "bundleRef" => nil,
      "matched" => [],
      "generations" => %{},
      # spec/05 §5: an engine the kernel cannot name wrote nothing it can
      # account for either. Saying `[]` is saying so, rather than leaving
      # a reader to infer it from a missing key.
      "derivedObjects" => []
    }
  end
end

defmodule R5e.Policy.AllowAll do
  @moduledoc """
  Default policy: everything an authenticated actor asks for is allowed.
  It says so on every receipt — engine `"allow-all"`, no bundle — so the
  absence of a real policy is legible rather than silent.
  SLICE: a real deployment binds this to admitted policy resources
  (authority Kinds, endorsement chains per spec/03) instead of a constant.
  """
  @behaviour R5e.Policy

  @meta %{
    "engine" => "allow-all",
    "decision" => "allow",
    "bundle" => nil,
    "bundleRef" => nil,
    "matched" => [],
    # spec/05 §7: a constant is not a read, so there is nothing for
    # `record` to re-check and nothing this policy can be contended on.
    "generations" => %{},
    # spec/05 §5: and a constant writes nothing, so there is no derived
    # object for replay to rebuild or for an export to list.
    "derivedObjects" => []
  }

  @impl true
  def authorize(_request), do: {:ok, @meta}
end
