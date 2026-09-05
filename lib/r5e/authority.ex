defmodule R5e.Authority do
  @moduledoc """
  Endorsements and Badges: the walk that says whether one is **effective**
  (spec 011 contract §5), the checks an act citing one must pass, the
  checks an act *issuing* one must pass, and the `resolvedAuthority` block
  that puts the whole derivation on the record.

  ## Authority is a property of the act

  An actor citing nothing acts as itself, and no Kind test applies. An
  actor citing authority is claiming to act in somebody else's name, and
  every claim in that sentence is checked here: that the thing cited is an
  authority event, that its subject is this actor (or a key this actor
  succeeded), that it is effective now, and that the Kind being admitted
  is inside every authority cited. There is no class of badge keys — the
  same key can act as itself in one admission and under a badge in the
  next, and the record says which.

  ## One walk, not two (debt #42)

  **The rules are `RecurseVerify.Authority`'s.** This module holds the
  index — fed one event at a time as the chain grows, where a bundle
  reader folds the whole chain in one go — and the two things a running
  kernel has that a bundle does not: §6's capture, and the `resolve:`
  reason strings a denial carries. The recurrence itself, the `kinds`
  lattice, the succession relation and the link shape are the verifier's,
  by path dependency, exactly as `Canonical`, `DSSE` and `Instant` are.
  The verifier is the fixed point: if the kernel held its own copy, a
  chain could be admitted under one reading and reported under another.

  §5's recurrence, clause for clause, with the numbering as the reason
  precedence:

      1. E ∈ seen                          → cycle                (defensive)
      2. not an admitted authority event at seq < s
                                           → not an authority event
      3. revoked before s by an actor who matches its own
                                           → revoked at <seq>
      4. ts outside [notBefore, notAfter]  → out of term
      5. no parent                         → root <actor>
      7. parent's own facts re-checked     → parent subject
                                             parent may not issue
                                             kinds exceed parent
                                             term exceeds parent
      8. parent not effective              → parent: <why>
      9.                                   → chain to root <actor>

  Clause 7 re-checks facts issuance already enforced. It can fail only on
  a forged event, and it is here so the verifier needs no separate rule:
  the same function answers for a chain this kernel wrote and for a bundle
  somebody handed you.

  `ts` is §5's `ts(s)`: the timestamp the act will carry, as a string —
  the node's clock **truncated to the second exactly as the log writes
  it** (`R5e.Clock.ts/0`), never the untruncated clock. The kernel asks
  with it at `resolve` and again under the append lock (§6), because a
  term that expires between `resolve` and `record` must not produce a
  grant that says otherwise, and because a term boundary carrying a
  fraction of a second has to be decided the way every reader of the
  finished record will decide it.

  ## What is memoized, and why the seq is a parameter

  The memo key is `(E, s)`; `s` is fixed for the length of one call, so
  the memo is keyed by the event ref alone, and a chain that reaches the
  same ancestor twice within **one** `effective/3` call walks the shared
  part once.

  What that does **not** do, stated because the earlier wording claimed
  it: two *separate* cited authorities sharing an ancestor are two calls,
  and the memo does not survive between them
  (`RecurseVerify.Authority.effective/4` builds a fresh one per call). A
  request citing two entries with a common root therefore walks that root
  twice. Chains are at most 16 links and `authority` at most 16 entries
  (§1), so the bound is small and the simpler contract — a pure function
  of the index — is worth more than the saving.
  """

  use Agent

  alias RecurseVerify.Authority, as: Walk

  @succession "core.r5e.io/v1/Succession"
  @revocation "core.r5e.io/v1/Revocation"

  def start_link(_opts), do: Agent.start_link(fn -> empty() end, name: __MODULE__)

  defp empty,
    do: %{index: Walk.empty(), version: 0, first_signer: nil, last_seq: 0}

  @doc "Forget everything. `R5e.Bootstrap.replay/0` calls this before rebuilding."
  @spec reset() :: :ok
  def reset, do: Agent.update(__MODULE__, fn _ -> empty() end)

  @doc "The greatest issuance depth §5 admits."
  defdelegate max_depth, to: Walk

  @doc """
  Feed one recorded event in. §0's relation and §5's authority are one
  view of the chain, so they are fed from the chain — at `record`, and
  again for every event at replay — through
  `RecurseVerify.Authority.observe/3`, the same fold a bundle reader
  runs over a whole export.

  Beside the index this keeps the three facts only a *live* chain has:
  §6's succession-graph version, the tip (the `s` the kernel is about to
  write at), and the signer of event 1, which is where §0's node key
  starts.
  """
  @spec observe(map(), map()) :: :ok
  def observe(event, payload) do
    Agent.update(__MODULE__, fn state ->
      %{
        state
        | index: Walk.observe(state.index, event, payload),
          version: state.version + version_bump(payload),
          # Every event moves the tip, granted or denied.
          last_seq: max(state.last_seq, event["seq"] || 0),
          first_signer: first_signer(state.first_signer, event, payload)
      }
    end)
  end

  # §6: the version moves on every admitted Succession and every
  # Revocation of one, and on nothing else — so an admission that read
  # the relation can tell under the append lock whether it changed, and
  # one that read anything else is not disturbed.
  defp version_bump(%{"outcome" => "admitted"} = payload) do
    cond do
      R5e.Admission.target_path(payload) == @succession -> 1
      revokes_a_succession?(payload) -> 1
      true -> 0
    end
  end

  defp version_bump(_payload), do: 0

  # A `Revocation` whose target is a Succession. The target Kind is not on
  # the Revocation's own payload, so it is read from the resolution
  # manifest the kernel wrote beside it — the entry it produced for
  # `revokes`, which records the Kind the cited event admitted.
  defp revokes_a_succession?(payload) do
    R5e.Admission.target_path(payload) == @revocation and
      Enum.any?(payload["resolvedRefs"] || [], fn entry ->
        entry["path"] == "/revokes" and entry["targetKind"] == @succession
      end)
  end

  # Event 1's signer is where §0's node key starts, and it is read off the
  # chain rather than assumed to be the key this node currently holds.
  defp first_signer(nil, %{"seq" => 1}, %{"signers" => [signer | _]}), do: signer
  defp first_signer(current, _event, _payload), do: current

  @doc "The whole index, for the verifier's functions to be asked of."
  @spec index() :: map()
  def index, do: Agent.get(__MODULE__, & &1.index)

  @doc "§6's succession-graph version."
  @spec version() :: non_neg_integer()
  def version, do: Agent.get(__MODULE__, & &1.version)

  @doc "The seq the kernel is about to write."
  @spec next_seq() :: integer()
  def next_seq, do: Agent.get(__MODULE__, & &1.last_seq) + 1

  @doc "The key that signed event 1, or `nil` on a chain that predates signatures."
  @spec first_signer() :: String.t() | nil
  def first_signer, do: Agent.get(__MODULE__, & &1.first_signer)

  @doc "The authority record for an event ref, or `nil`."
  @spec event(String.t()) :: map() | nil
  def event(ref), do: index().events[ref]

  # -- §5's `kinds` lattice, the verifier's -------------------------------

  @doc """
  §5's normal form: deduplicated and sorted, and **exactly `["*"]`** when
  `*` is present. A list that says `["*", "x/v1/Y"]` says nothing the bare
  `*` did not, and leaving both spellings on the record would make two
  authorities that grant the same thing compare unequal.
  """
  defdelegate normal_form(kinds), to: Walk

  @doc "§5's `⊆` with `*` as top."
  defdelegate covered?(narrow, wide), to: Walk

  @doc "Whether an authority's `kinds` covers one Kind path."
  @spec covers_kind?(map(), String.t()) :: boolean()
  def covers_kind?(record, path), do: covered?([path], record["kinds"])

  # -- the walk (§5), the verifier's ---------------------------------------

  @doc """
  §5's `effective(E, s, ∅)` over this node's index. Returns

      %{ok: boolean, reason: String.t(), root: String.t() | nil, visited: [ref]}

  `visited` is every event the walk looked at, which §6 captures: the
  append lock re-checks each one's revocation state and term, because an
  authority that was effective at `resolve` and is not at `record` must
  not produce a grant that says it was.

  `ts` is §5's `ts(s)`: the second-truncated instant the log is about to
  write (`R5e.Clock.ts/0`), as a string, never the untruncated clock.
  """
  @spec effective(String.t(), integer(), String.t()) :: map()
  def effective(ref, s, ts), do: Walk.effective(index(), ref, s, ts)

  # -- resolution (§5), at `resolve` --------------------------------------

  @doc """
  Resolve the `authority` a request cites (§5). Returns
  `{:ok, resolved, visited}` where `resolved` is §5's `resolvedAuthority`
  — an entry per cited ref, in the order the request named them, each
  carrying the whole chain to its root — or `{:error, reason}` with one of
  §5's `resolve:` reasons.

  **Empty authority is not a failure.** An actor citing nothing acts as
  itself; there is no Kind test and no walk, and the recorded
  `resolvedAuthority` is `[]`. That is the ordinary case and it stays
  cheap.
  """
  @spec resolve(map(), R5e.Kind.t()) :: {:ok, [map()], [String.t()]} | {:error, String.t()}
  def resolve(request, kind) do
    refs = request[:authority] || []
    resolve_entries(refs, request, R5e.Kind.name(kind))
  end

  defp resolve_entries([], _request, _path), do: {:ok, [], []}

  defp resolve_entries(refs, request, path) do
    s = R5e.Succession.next_seq()
    ts = R5e.Clock.ts()
    actor = request[:actor]["id"]
    index = index()

    refs
    |> Enum.with_index()
    |> Enum.reduce_while({:ok, [], []}, fn {ref, i}, {:ok, entries, visited} ->
      case resolve_entry(ref, i, actor, path, s, ts, index) do
        {:ok, entry, seen} -> {:cont, {:ok, entries ++ [entry], visited ++ seen}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp resolve_entry(ref, i, actor, path, s, ts, index) do
    record = index.events[ref]
    walk = effective(ref, s, ts)

    cond do
      # An entry that names no authority event has no subject to compare,
      # so the walk's own clause 2 is what says what is wrong with it.
      record == nil or record["seq"] >= s ->
        {:error, "authority ineffective: not an authority event"}

      not R5e.Succession.matches(record["subject"], actor, s) ->
        {:error,
         "authority subject: #{ref} endorses #{inspect(record["subject"])}, " <>
           "and the actor is #{inspect(actor)}"}

      not walk.ok ->
        {:error, "authority ineffective: #{walk.reason}"}

      not covers_kind?(record, path) ->
        {:error,
         "kind outside authority: #{ref} covers #{inspect(record["kinds"])}, " <>
           "and this act admits #{path}"}

      true ->
        {:ok, %{"index" => i, "value" => ref, "chain" => chain_links(ref, index)}, walk.visited}
    end
  end

  @doc """
  §5's `resolvedAuthority` chain: the cited event first, each link exactly
  the thirteen fields §5 lists, up to the root.

  Policy receives it whole and needs no fetch — an engine that had to
  reach back into the chain to see what an actor was permitted would be
  reading a different record from the one the receipt shows. The verifier
  re-derives every link from the bundle and compares.
  """
  @spec chain_links(String.t(), map() | nil) :: [map()]
  def chain_links(ref, index \\ nil), do: Walk.links(index || index(), ref)

  # -- issuance (§5), at `resolve` ----------------------------------------

  @doc """
  §5's issuance checks: admitting an Endorsement or Badge that names a
  `parent`. Returns `{:ok, depth}` — the depth to record — or
  `{:error, reason}` with one of §5's `resolve:` reasons.

  Every check is about the *issuer*: that it exercised the parent in this
  very request, that the parent was granted to it, that the parent may
  issue at all, and that what it is granting is inside what it holds on
  the three axes spec/03 says narrow monotonically — the right to issue,
  the Kinds covered, and the term. An issuance that passes all of them
  cannot hand on more than it was given, which is the whole content of the
  promise.

  A root issuance — no `parent` — is depth 0 and needs none of this: a key
  vouching for another out of its own standing is not delegation, and it
  is **ungated by design** — any key may admit a parentless Endorsement or
  Badge naming itself, and nothing on the chain makes that authority. What
  makes a root worth anything is a reader who pinned it (§9's `--trust`);
  an unpinned root resolves to nothing.

  ## Two of §5's issuance checks are not here

  `matches(parent.subject, actor, s)` and `effective(parent, s)` are both
  established by the citing check a few lines earlier: `parent ∈ authority`
  is checked first, and `resolve/2` has already asked both questions of
  every cited entry. Contract r4.3 says so, and names `resolve: parent
  subject` as the **verifier's** reason for the same fact on a bundle it
  did not write — a splice therefore lands `resolve: authority subject`
  here. Keeping a second copy would mean two evaluations of one recurrence
  that could disagree if the clock ticked between them, and a reason
  string no input reaches.
  """
  @spec issuance(map(), R5e.Kind.t()) :: {:ok, non_neg_integer()} | {:error, String.t()}
  def issuance(request, kind) do
    path = R5e.Kind.name(kind)
    spec = request[:spec] || %{}

    cond do
      not Walk.authority_kind?(path) -> {:ok, nil}
      get_in(spec, ["parent", "$ref"]) == nil -> {:ok, 0}
      true -> issue_under(get_in(spec, ["parent", "$ref"]), request, spec)
    end
  end

  defp issue_under(parent_ref, request, spec) do
    p = event(parent_ref)

    child = %{
      "kinds" => normal_form(spec["kinds"]),
      "notBefore" => spec["notBefore"],
      "notAfter" => spec["notAfter"]
    }

    cond do
      parent_ref not in (request[:authority] || []) ->
        {:error,
         "parent not exercised: #{parent_ref} is named as the parent and is not in this " <>
           "request's authority; an issuance exercises the authority it hands on"}

      # Defensive, and unreachable for the same reason as the two checks
      # §5 (r4.3) marks as already established: the parent is in
      # `authority`, so `resolve_entry/7` has already looked it up and
      # refused the request if there was nothing there.
      p == nil ->
        {:error, "authority ineffective: not an authority event"}

      not p["mayIssue"] ->
        {:error, "parent may not issue: #{parent_ref} was granted without the right to issue"}

      not covered?(child["kinds"], p["kinds"]) ->
        {:error,
         "kinds exceed parent: #{inspect(child["kinds"])} is not within " <>
           "#{inspect(p["kinds"])}"}

      not Walk.term_within?(child, p) ->
        {:error,
         "term exceeds parent: #{child["notBefore"]}..#{child["notAfter"]} is not within " <>
           "#{p["notBefore"]}..#{p["notAfter"]}"}

      Walk.depth_of(p) + 1 > Walk.max_depth() ->
        {:error,
         "depth exceeded: a chain is at most #{Walk.max_depth()} links, and this would be " <>
           "#{Walk.depth_of(p) + 1}"}

      true ->
        {:ok, Walk.depth_of(p) + 1}
    end
  end

  # -- §6's capture -------------------------------------------------------

  @doc """
  §6's capture: **which events the walk visited**, so the append lock can
  ask them again.

  A grant is a statement that the authority was effective *at the seq the
  event carries*. Between `resolve` and `record` a Revocation can land and
  a term can end, and either would make that statement false.

  What is captured is the list of refs and nothing else. The events
  themselves are immutable — an admitted Endorsement's `notBefore` and
  `notAfter` are on the chain and cannot change — so carrying a copy of
  the term here would create a second version of a fact that has one, and
  the re-check would be comparing the capture against itself. What *does*
  change between `resolve` and `record` is the clock and the set of
  Revocations, and `moved/2` reads both afresh.
  """
  @spec snapshot([String.t()]) :: [String.t()]
  def snapshot(refs) do
    index = index()
    for ref <- Enum.uniq(refs), Map.has_key?(index.events, ref), do: ref
  end

  @doc """
  Re-check a `snapshot/1` now (§6). `nil` when nothing moved, or the
  terminal `record:` reason — `authority revoked at <seq>` naming the
  Revocation, or `authority out of term`.
  """
  @spec moved([String.t()], String.t()) :: nil | String.t()
  def moved(refs, ts) do
    index = index()
    s = next_seq()

    Enum.find_value(refs, fn ref ->
      record = index.events[ref]

      cond do
        record == nil -> nil
        (r = Walk.revocation(index, ref, s, record)) != nil -> "authority revoked at #{r.seq}"
        not Walk.in_term?(record, ts) -> "authority out of term"
        true -> nil
      end
    end)
  end
end
