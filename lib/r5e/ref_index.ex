defmodule R5e.RefIndex do
  @moduledoc """
  The reference index (spec/05 §5): for every object address, the set of
  **citations** the chain carries for it, plus the two facts that decide
  whether a `bytes:` ref may resolve at all — whether a `CasObject`
  admission put those bytes on the record, and whether the kernel itself
  derived them.

  It exists because two questions in §4 and §5 are otherwise O(chain) per
  admission, and one of them runs on every `bytes:` ref:

    * **the partition** (§4) — does this address coincide with an event
      payload address or an admitted `specAddress`? Before this index the
      answer cost a full log read and a decode of every granted payload
      (amendment B6);
    * **"unreferenced"** (§5) — is this address cited by *nothing*, so the
      retention sweeper may expire it?

  ## What counts as a citation

  Four sources, and they are exactly §5's four. Each is recorded with the
  seq that produced it, so a denial can name the citing event rather than
  saying "something cites this".

  | citation `kind` | from | recorded for |
  |---|---|---|
  | `payload` | an event's `payload` address | **every** event, granted or denied — the kernel wrote those bytes |
  | `specAddress` | the canonical hash of an **admitted** spec | granted admissions only — a denial stored no spec |
  | `manifest` | a `bytes:` entry of a resolution manifest | **every** event that carries one |
  | `spec` | a `bytes:sha256:…` string inside an **admitted** spec, at any depth | granted admissions only |

  Two of those rows are asymmetric on purpose, and §5's own wording is
  where the asymmetry comes from: it says "no *admitted* spec … and no
  *admitted* `specAddress`", and says "no resolution manifest" without the
  qualifier. A denied admission resolved its refs before policy refused
  it, and that manifest is part of the record of the asking; expiring an
  object a denial's manifest names would leave the record citing bytes
  that are gone. So manifests count whatever the outcome.

  ## What is deliberately not a citation

  A `CasObject`'s own spec carries the address as a plain string, and a
  `CasExpired`'s does too. Those are the **record of the object**, not
  references to it — counting them would make every object permanently
  unexpirable and §5's sweeper unreachable. So the inline-string scan
  skips those two Kinds' specs, and nothing else.

  ## Kernel-derived objects (§5)

  Bytes the kernel wrote *inside* an admission (§8's policy evaluation
  record is the first) have no `CasObject` admission of their own and must
  still resolve, so the class is kept here: `derived?/1` is what exempts
  them from the backing rule, and they are never unreferenced.

  Registration has two doors, and the second is the one that matters:
  `register_derived/2` for the writing path, and a `derivedObjects` list
  on the event payload, which `observe/2` reads. Only the second survives
  a boot — a class that lives in this process alone is a fact the chain
  does not carry, and an export taken after a restart would list none of
  them while every citation of one stayed on the log.

  Denials count here, for the same reason their manifests do: the record
  a refused decision produced is evidence of the refusal.

  ## Rebuilt by replay

  In-memory, like the resource store, and rebuilt the same way: the log is
  the record and this is a view of it (`R5e.Bootstrap.replay/0` feeds
  every event through `observe/2`, in order). Live admissions feed it from
  `R5e.Admission`'s `record` step, so the index is current before the
  `admit` step writes anything.

  Addresses are keyed **bare** — `sha256:<hex>`, the form `bytes:` and the
  kernel-written form share (§6) — so the partition question is a lookup
  in one key space rather than a comparison across two spellings.
  """

  use Agent

  @cas_kinds ~w(CasObject CasExpired)

  @empty %{citations: %{}, cas_objects: %{}, derived: %{}, expired: MapSet.new()}

  def start_link(_opts), do: Agent.start_link(fn -> @empty end, name: __MODULE__)

  @doc "Drop everything. Used by replay before it rebuilds, and by tests."
  def reset, do: Agent.update(__MODULE__, fn _ -> @empty end)

  # -- observation -------------------------------------------------------

  @doc """
  Record everything one event says about object addresses. Idempotent per
  event only in the sense that replay starts from `reset/0`; calling it
  twice for one event would double its citations, so exactly one of the
  two paths (live admission, or replay) ever runs for a given event.
  """
  @spec observe(map(), map()) :: :ok
  def observe(event, payload) when is_map(event) and is_map(payload) do
    Agent.update(__MODULE__, fn state ->
      state
      |> add_citations(citations_of(event, payload))
      |> note_cas_object(event, payload)
      |> note_cas_expired(payload)
      |> note_derived(payload)
    end)
  end

  def observe(_event, _payload), do: :ok

  @doc """
  Register a kernel-derived object: bytes the kernel wrote inside an
  admission, which therefore have no `CasObject` admission of their own.
  """
  @spec register_derived(String.t(), map()) :: :ok
  def register_derived(address, info \\ %{}) do
    bare = bare(address)

    Agent.update(__MODULE__, fn state ->
      put_in(state, [:derived, bare], Map.put(info, "address", "bytes:" <> bare))
    end)
  end

  # -- questions ---------------------------------------------------------

  @doc "Every citation of this address, oldest first."
  @spec citations(String.t()) :: [map()]
  def citations(address) do
    bare = bare(address)
    Agent.get(__MODULE__, &Map.get(&1.citations, bare, [])) |> Enum.sort_by(& &1["seq"])
  end

  @doc """
  The `CasObject` admission that **first** put this address on the record,
  if one did: `%{"eventRef" => …, "seq" => …, "ts" => …, "size" => …,
  "mediaType" => … | nil, "admissions" => n}`.

  The first, not the latest, and the choice is load-bearing. Re-putting
  bytes already present is a fresh admission (§2, `content` naming), so an
  address can carry several; what a citing manifest entry should name is
  the act that put the object *there*, since that is the act the object's
  existence is owed to. The later ones are recorded as a count — two
  actors putting the same bytes is two acts and the index does not
  pretend it was one — and a reader who wants them reads the chain.
  """
  @spec cas_object(String.t()) :: {:ok, map()} | :error
  def cas_object(address) do
    bare = bare(address)
    Agent.get(__MODULE__, &Map.fetch(&1.cas_objects, bare))
  end

  @doc "Every admitted `CasObject`, address (bare) to its admission facts."
  @spec cas_objects() :: %{String.t() => map()}
  def cas_objects, do: Agent.get(__MODULE__, & &1.cas_objects)

  @doc "Has a granted `CasExpired` already removed this address?"
  @spec expired?(String.t()) :: boolean()
  def expired?(address) do
    bare = bare(address)
    Agent.get(__MODULE__, &MapSet.member?(&1.expired, bare))
  end

  @doc "Is this address a kernel-derived object (§5)?"
  @spec derived?(String.t()) :: boolean()
  def derived?(address) do
    bare = bare(address)
    Agent.get(__MODULE__, &Map.has_key?(&1.derived, bare))
  end

  @doc "Every kernel-derived object, in `bytes:sha256:…` form, sorted."
  @spec derived_objects() :: [String.t()]
  def derived_objects do
    Agent.get(__MODULE__, & &1.derived)
    |> Map.values()
    |> Enum.map(& &1["address"])
    |> Enum.sort()
  end

  @doc """
  Is this address an event payload address or an admitted `specAddress`?
  §4's partition, answered in one lookup. Returns `:ok`, or `{:error,
  :payload}` / `{:error, :spec}` naming which side of the partition the
  address is already on. The wording of the refusal belongs to whoever
  refuses; what the index answers is which side.
  """
  @spec partition(String.t()) :: :ok | {:error, :payload | :spec}
  def partition(address) do
    kinds = citations(address) |> Enum.map(& &1["kind"])

    cond do
      "payload" in kinds -> {:error, :payload}
      "specAddress" in kinds -> {:error, :spec}
      true -> :ok
    end
  end

  @doc """
  §5's "unreferenced": no admitted spec, no resolution manifest, no event
  payload address and no admitted `specAddress` cites this object. A
  kernel-derived object is never unreferenced — the admission that wrote
  it is what cites it, and that admission is on the chain.
  """
  @spec unreferenced?(String.t()) :: boolean()
  def unreferenced?(address), do: citations(address) == [] and not derived?(address)

  @doc """
  The citations that declared `retention: "public-record"` (§4's bytes
  refdecl option, carried onto the manifest entry by `resolve` so the
  index can read it back from the record alone).
  """
  @spec public_record_citations(String.t()) :: [map()]
  def public_record_citations(address),
    do: Enum.filter(citations(address), &(&1["retention"] == "public-record"))

  # -- derivation --------------------------------------------------------

  defp citations_of(event, payload) do
    seq = event["seq"]
    ref = R5e.Admission.event_ref(event)
    admitted? = payload["outcome"] == "admitted"
    spec = payload["spec"]

    payload_citation(event, seq, ref) ++
      manifest_citations(payload, seq, ref) ++
      if admitted? and is_map(spec) do
        spec_address_citation(spec, seq, ref) ++ inline_citations(payload, spec, seq, ref)
      else
        []
      end
  end

  defp payload_citation(event, seq, ref) do
    case event["payload"] do
      address when is_binary(address) ->
        [{bare(address), citation("payload", seq, ref, nil, nil)}]

      _ ->
        []
    end
  end

  defp spec_address_citation(spec, seq, ref),
    do: [{bare(R5e.CAS.spec_address(spec)), citation("specAddress", seq, ref, nil, nil)}]

  # A manifest entry carries `retention` when its declaration did (§4), so
  # the public-record rule is answerable from the record and does not need
  # the Kind still to be in the registry.
  defp manifest_citations(payload, seq, ref) do
    for entry <- payload["resolvedRefs"] || [],
        is_map(entry),
        entry["class"] == "bytes",
        is_binary(entry["value"]) do
      {bare(entry["value"]), citation("manifest", seq, ref, entry["path"], entry["retention"])}
    end
  end

  # Every `bytes:sha256:…` string at any depth of an admitted spec, not
  # only the ones a ref declaration made typed. A `CasObject` or
  # `CasExpired` spec is skipped: its address is the record of the object,
  # not a citation of it.
  defp inline_citations(payload, spec, seq, ref) do
    if get_in(payload, ["target", "kind"]) in @cas_kinds do
      []
    else
      for address <- inline_addresses(spec) |> Enum.uniq() |> Enum.sort() do
        {bare(address), citation("spec", seq, ref, nil, nil)}
      end
    end
  end

  defp inline_addresses(%{} = map), do: Enum.flat_map(map, fn {_k, v} -> inline_addresses(v) end)
  defp inline_addresses(list) when is_list(list), do: Enum.flat_map(list, &inline_addresses/1)

  defp inline_addresses("bytes:" <> _ = value) do
    if R5e.CAS.object_address?(value), do: [value], else: []
  end

  defp inline_addresses(_value), do: []

  defp citation(kind, seq, ref, path, retention) do
    %{"kind" => kind, "seq" => seq, "eventRef" => ref, "path" => path, "retention" => retention}
  end

  defp add_citations(state, entries) do
    Enum.reduce(entries, state, fn {address, citation}, acc ->
      update_in(acc, [:citations, Access.key(address, [])], &(&1 ++ [citation]))
    end)
  end

  defp note_cas_object(state, event, %{"outcome" => "admitted", "spec" => spec} = payload) do
    if get_in(payload, ["target", "kind"]) == "CasObject" and is_map(spec) do
      address = bare(spec["address"] || "")

      case Map.fetch(state.cas_objects, address) do
        {:ok, first} ->
          put_in(state, [:cas_objects, address], Map.update!(first, "admissions", &(&1 + 1)))

        :error ->
          put_in(state, [:cas_objects, address], %{
            "eventRef" => R5e.Admission.event_ref(event),
            "seq" => event["seq"],
            "ts" => event["ts"],
            "size" => spec["size"],
            "mediaType" => spec["mediaType"],
            "admissions" => 1
          })
      end
    else
      state
    end
  end

  defp note_cas_object(state, _event, _payload), do: state

  defp note_cas_expired(state, %{"outcome" => "admitted", "spec" => spec} = payload) do
    if get_in(payload, ["target", "kind"]) == "CasExpired" and is_map(spec) do
      update_in(state, [:expired], &MapSet.put(&1, bare(spec["address"] || "")))
    else
      state
    end
  end

  defp note_cas_expired(state, _payload), do: state

  # Whatever the outcome: a denial's evaluation record is the evidence for
  # the refusal, and the act that wrote it is on the chain either way.
  defp note_derived(state, %{"derivedObjects" => list}) when is_list(list) do
    Enum.reduce(list, state, fn address, acc ->
      if is_binary(address) and R5e.CAS.object_address?(address) do
        put_in(acc, [:derived, bare(address)], %{"address" => "bytes:" <> bare(address)})
      else
        acc
      end
    end)
  end

  defp note_derived(state, _payload), do: state

  defp bare(address), do: R5e.CAS.object_hash(address)
end
