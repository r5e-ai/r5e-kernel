defmodule R5e.Succession do
  @moduledoc """
  The succession relation (spec 011 contract §0), as this node sees it —
  **an adapter, not a second implementation**.

  Every rule here is `RecurseVerify.Authority`'s: `matches/4`, `head/3`,
  `ancestors/3`, `edges_at/2` and `check_edge/4` are the verifier's
  functions, asked of the index `R5e.Authority` keeps up to date from the
  chain. What this module adds is the three things a running kernel has
  and a bundle does not: the `s` to ask at (the seq about to be written),
  §6's capture point, and §0's node key.

  It owns no *chain* state — the index lives in `R5e.Authority`'s Agent,
  and every question here is asked of that one index. It does hold two
  entries in the **process dictionary**, and they are not chain state but
  the bookkeeping §6's capture needs: which stage the running admission
  has reached, and the version at its first read of the relation. They are
  per-process and per-admission, `rewind/0` clears them, and a process
  that never calls `reading/1` records nothing.

  That is deliberate and is the point of debt #42: the verifier is the
  fixed point, so the kernel does not get its own opinion about who
  succeeded whom. If the two disagreed, the chain would say one thing and
  a reader of it another.

  ## What the relation is

  Edges come from **admitted, unrevoked** `Succession` events at seq < s,
  one edge per event: predecessor → successor. Admission keeps the
  relation a set of **disjoint simple paths** — at most one outgoing edge
  per predecessor, at most one incoming per successor, no self-edge, no
  cycle — so `head(k, s)` is a single key and not a choice, and the whole
  point of the Kind survives: a reader can say who speaks for a former
  self without guessing. The four refusals that keep it that shape are
  `RecurseVerify.Authority.check_edge/4`'s.

  ## Revocation reopens both slots

  Revoking a Succession removes its edge for every seq **after** the
  Revocation's. The edge is still live *at* `R.seq` itself, and that is
  load-bearing rather than an off-by-one: §0 asks
  `matches(target.actor, revoker, R.seq)` of a Revocation, so a successor
  revoking the very edge that made it the successor is valid exactly
  because the edge it is revoking still stands at the position the
  Revocation occupies. Kill the edge one seq earlier and a successor
  could never withdraw its own succession — only the predecessor could,
  which is the opposite of what the holder of a compromised predecessor
  key needs. Nothing before `R.seq` changes, and *both* endpoints' slots
  reopen — the predecessor may name another successor, and the successor
  may be named by someone else. So a predecessor can have several edges
  on the chain of which at most one is live at any position, which is why
  edges are kept as a list with their seq and their revocation seq rather
  than as one map. The verifier prints `contested-succession` where it
  sees that; the kernel does not refuse it, because a stolen key and its
  rightful holder both leave a record and the record is what the
  endorsers read.

  ## As of a sequence

  Every question takes an `s`. The kernel always asks at `head + 1` — the
  seq it is about to write — and the verifier asks at the seq of the
  citing event, which is why the seq is a parameter rather than an
  assumption.
  """

  alias RecurseVerify.Authority, as: Walk

  @succession_kind "core.r5e.io/v1/Succession"

  # -- §6's capture point -------------------------------------------------

  @stage_key :r5e_succession_stage
  @read_key :r5e_succession_read

  @doc """
  §6: name the pipeline stage that is about to run, so the **first** read
  of the relation inside this admission can record where it happened.

  §6 says the succession-graph version is "captured at the first
  succession-dependent read (which may be `admitBy`/`readmitBy` at
  `validateStructure`)", and that a mismatch "retries from that stage".
  Both halves need the same fact — *where* the relation was first
  consulted — and neither the naming code nor the walk is in a position
  to hand it upwards, so it is recorded here, in the process running the
  admission, at the one funnel the kernel's own reads go through.

  What is captured is only a read **at a current seq**. The authority
  walk asks the relation at *past* seqs (clause 7 at `e.seq`, clause 3 at
  `R.seq`), and an edge admitted now has a seq greater than either, so it
  cannot change those answers — those reads run inside
  `RecurseVerify.Authority` and are not captured, which is right rather
  than an omission.

  Two more consequences. An admission that never consults the relation
  captures **nothing** and is therefore never contended by a Succession:
  a decision that did not depend on the graph cannot be invalidated by
  the graph moving. And a process that never calls this — `R5e.Log`'s
  own, which re-checks the capture — records nothing, so the re-check
  cannot capture itself.
  """
  @spec reading(String.t()) :: :ok
  def reading(stage) do
    Process.put(@stage_key, stage)
    :ok
  end

  @doc "Forget this admission's first read; the next read notes itself afresh."
  @spec rewind() :: :ok
  def rewind do
    Process.delete(@read_key)
    :ok
  end

  @doc """
  §6's capture: `%{stage: <stage name>, version: <graph version>}` for the
  first read of the relation in this admission, or `nil` if it was never
  read.
  """
  @spec first_read() :: %{stage: String.t(), version: non_neg_integer()} | nil
  def first_read, do: Process.get(@read_key)

  defp note_read do
    with stage when is_binary(stage) <- Process.get(@stage_key),
         nil <- Process.get(@read_key) do
      Process.put(@read_key, %{stage: stage, version: version()})
    end

    :ok
  end

  defp relation do
    note_read()
    R5e.Authority.index()
  end

  # -- the relation (RecurseVerify.Authority's rules) ---------------------

  @doc """
  §0's `matches(a, b, s)` — "a is b, or an ancestor of b".

  Every rule that lets a successor stand in for a predecessor is this one
  predicate: an authority's subject against the actor exercising it, an
  issuance parent's subject, `sameActor` on a Revocation,
  `readmitBy: actorOfRecordOrSuccessor`. Read it as: *is the key on the
  record still speaking, through this key?*

  It is deliberately **one-directional**. A predecessor does not match its
  successor: authority granted to a key flows forward to whoever the key
  named, never backward to whoever named the key.
  """
  @spec matches(String.t() | nil, String.t() | nil, integer()) :: boolean()
  def matches(a, b, _s) when a == b and a != nil, do: true
  def matches(nil, _b, _s), do: false
  def matches(_a, nil, _s), do: false
  def matches(a, b, s), do: Walk.matches(relation(), a, b, s)

  @doc "§0's `pred*(k, s)`: every key `k` succeeded, nearest first."
  @spec ancestors(String.t(), integer()) :: [String.t()]
  def ancestors(key, s), do: Walk.ancestors(relation(), key, s)

  @doc """
  §0's `head(k, s)`: the terminal successor of `k` — the key that speaks
  for it now. `k` itself when it has not been succeeded.
  """
  @spec head(String.t(), integer()) :: String.t()
  def head(key, s), do: Walk.head(relation(), key, s)

  @doc "Every live edge as of `s`, for a caller that wants to print the relation."
  @spec edges_at(integer()) :: [map()]
  def edges_at(s), do: Walk.edges_at(relation(), s)

  @doc """
  The four admission checks that keep the relation a set of disjoint
  simple paths (§0). `:ok`, or `{:error, reason}` naming which shape rule
  the edge would break.
  """
  @spec check_edge(String.t() | nil, String.t() | nil, integer()) :: :ok | {:error, String.t()}
  def check_edge(predecessor, successor, s),
    do: Walk.check_edge(relation(), predecessor, successor, s)

  @doc """
  §0's four shape rules, asked of a `Succession` instance at `resolve`.
  `:ok`, or `{:error, reason}` carrying one of the contract's four
  `resolve:` reasons.

  Nothing else in the kernel calls `check_edge/3` — this is the arm that
  keeps the relation a set of disjoint simple paths, and it runs where
  every other lookup-shaped refusal runs.
  """
  @spec check_admission(map(), R5e.Kind.t()) :: :ok | {:error, String.t()}
  def check_admission(request, kind) do
    if R5e.Kind.name(kind) == @succession_kind do
      spec = request[:spec] || %{}
      check_edge(spec["predecessor"], spec["successor"], next_seq())
    else
      :ok
    end
  end

  # -- what a running kernel has and a bundle does not --------------------

  @doc """
  §6's succession-graph version: incremented by every admitted
  `Succession` and every `Revocation` of one, and by nothing else.
  See `reading/1` for where it is captured and why.
  """
  @spec version() :: non_neg_integer()
  def version, do: R5e.Authority.version()

  @doc """
  The seq the kernel is about to write — the `s` every kernel-side
  question takes (§0: "at seq s", §5: `effective(entry, head + 1, ∅)`).

  Tracked from the events the view has observed rather than asked of
  `R5e.Log`, because §6's re-check runs inside that GenServer and a call
  back into it would be the process calling itself.
  """
  @spec next_seq() :: integer()
  def next_seq, do: R5e.Authority.next_seq()

  @doc """
  §0's node key: **the terminal successor of the key that signed event 1**.

  Read off the chain, so a deployment that has rotated its node key keeps
  the ability to admit its own `Deployment` and to transition its own
  seeds. A chain whose event 1 predates signatures (a pre-011 log) has no
  signer to start from, and the answer falls back to the key this node
  holds — which is what it was before succession existed.
  """
  @spec node_key() :: String.t()
  def node_key do
    case R5e.Authority.first_signer() do
      nil -> R5e.DSSE.local_key_id()
      signer -> head(signer, next_seq())
    end
  end
end
