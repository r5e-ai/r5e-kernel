defmodule R5e.ResourceStore do
  @moduledoc """
  Refs-first store of admitted instances (spec/01 §1). The stored form is
  minimal: the spec exactly as admitted, holding refs — never materialized
  copies of referenced state. Hydration (`resolution: :deep`) is a computed
  view carrying lineage: the list of refs it was derived from.

  A ref value is `{"$ref": <string>}`, and the string's form is fixed by
  the declaring property's ref class (§4):

    * `{"$ref": "group/version/Kind/name"}` — another admitted resource
    * `{"$ref": "event:sha256:<hex>"}`      — an event on this chain
    * `{"$ref": "bytes:sha256:<hex>"}`      — an admitted raw object

  A name may itself contain `/` (schema-lite v2 §2), so a resource path is
  split **from the left** into `group/version/Kind` plus everything after
  as the name: `gateway.r5e.io/v1alpha1/AgentSession/event:sha256:…` and
  `core.r5e.io/v1/KindDefinition/gateway.r5e.io/v1alpha1/ToolCall` both
  resolve. Deep resolution hydrates each of the three per §6 — a resource
  to its stored entry, an event to its envelope plus decoded payload, an
  object to its JSON value where the declaration says `json` and to
  `{size, base64}` otherwise.

  Entries carry, beside the spec: the `actor` of record (the actor id on
  the admission), the `admissionEvent` that put them there, and — once
  superseded — `supersededBy` on the entry that was replaced. A supersession
  keeps the displaced entry: `superseded/4` returns them oldest-first, so
  "what stood here before, and what replaced it" is answerable from the
  derived view as well as from the log.

  In-memory only: the log is the authoritative record and the store is
  replayed from it at boot (`R5e.Bootstrap.replay/0`).
  """

  use Agent

  def start_link(_opts),
    do: Agent.start_link(fn -> %{entries: %{}, superseded: %{}} end, name: __MODULE__)

  @doc """
  The store entry one granted admission produces (spec/05 §4's "admitted
  instance"). Built here and nowhere else, because two callers must agree
  on it exactly: `R5e.Admission`'s `admit` step builds it from the request,
  and `R5e.Bootstrap.replay/0` rebuilds it from the recorded payload. A
  second spelling of this map is how a replayed store comes to differ from
  the store it replaced.

  `fields` names the seven things the two callers read differently:
  `:group`, `:version`, `:kind`, `:name`, `:substrate`, `:spec`, `:actor`
  (the actor id of record), `:event` (the appended admission event) and
  `:resolved` / `:derived_from` (the manifest and envelope, defaulting to
  `[]` and absent).
  """
  @spec entry(map()) :: map()
  def entry(fields) do
    entry = %{
      "group" => fields.group,
      "version" => fields.version,
      "kind" => fields.kind,
      "name" => fields.name,
      "substrate" => fields.substrate,
      "specAddress" => R5e.CAS.spec_address(fields.spec),
      "spec" => fields.spec,
      "actor" => fields.actor,
      "admissionEvent" => R5e.Admission.event_ref(fields.event),
      # The generation a `kind` ref captures (§4) and the number §7's
      # commit re-check compares under the append lock.
      "admissionSeq" => fields.event["seq"],
      # SLICE: replay copies the manifest from the record — it trusts what
      # was written. Re-deriving it offline is the verifier's job (KP-3).
      "resolvedRefs" => Map.get(fields, :resolved) || []
    }

    case Map.get(fields, :derived_from) do
      nil -> entry
      address -> Map.put(entry, "derivedFrom", address)
    end
  end

  @doc "Store an admitted instance entry (called by the admit step only)."
  def put(group, version, kind, name, entry) do
    key = key(group, version, kind, name)
    Agent.update(__MODULE__, &put_in(&1, [:entries, key], entry))
  end

  @doc """
  Replace an admitted instance with a superseding one (§2 `supersede` and
  `replace`). The displaced entry is stamped `supersededBy` — the new
  admission's `eventRef` — and kept; the new entry records `supersedes`,
  the displaced entry's own admission event.
  """
  def supersede(group, version, kind, name, entry) do
    key = key(group, version, kind, name)

    Agent.update(__MODULE__, fn state ->
      case get_in(state, [:entries, key]) do
        nil ->
          put_in(state, [:entries, key], entry)

        previous ->
          displaced = Map.put(previous, "supersededBy", entry["admissionEvent"])

          replacement =
            case previous["admissionEvent"] do
              nil -> entry
              event -> Map.put(entry, "supersedes", event)
            end

          state
          |> put_in([:entries, key], replacement)
          |> update_in([:superseded, key], fn
            nil -> [displaced]
            list -> list ++ [displaced]
          end)
      end
    end)
  end

  @doc """
  Fetch an instance. `resolution: :refs` (default) returns the stored form;
  `resolution: :deep` returns `{:ok, entry, lineage}` where the entry's
  `"spec"` has refs recursively resolved and `lineage` lists every ref the
  view was computed from.
  """
  def get(group, version, kind, name, resolution \\ :refs) do
    case Agent.get(__MODULE__, &get_in(&1, [:entries, key(group, version, kind, name)])) do
      nil ->
        {:error, :not_found}

      entry when resolution == :refs ->
        {:ok, entry, []}

      entry when resolution == :deep ->
        {hydrated, lineage} = hydrate(entry)
        {:ok, hydrated, lineage}
    end
  end

  @doc "Entries this name has displaced, oldest first, each stamped `supersededBy`."
  def superseded(group, version, kind, name) do
    Agent.get(__MODULE__, &get_in(&1, [:superseded, key(group, version, kind, name)])) || []
  end

  @doc "All instances of a Kind, name-sorted."
  def list(group, version, kind) do
    prefix = key(group, version, kind, "")

    Agent.get(__MODULE__, fn state ->
      state.entries
      |> Enum.filter(fn {k, _} -> String.starts_with?(k, prefix) end)
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.map(fn {_, entry} -> entry end)
    end)
  end

  # -- deep resolution (spec/05 §6) --------------------------------------
  #
  # Hydration is **declaration-aware**: it walks the stored spec against
  # the Kind's schema, so each ref is replaced by what its *class* says it
  # points at rather than by whatever the string happens to look like.
  # That is the difference between a view and a guess — a `bytes:` ref
  # comes back as a JSON value only where the declaration says `json`,
  # and as `{size, base64}` otherwise, because the declaration is what
  # makes the bytes readable as anything.
  #
  # An unresolvable ref is left in place, marked `$unresolved` with the
  # reason. The refs form is the record; a derived view that cannot be
  # computed says so where the value would have been, rather than
  # dropping the citation and reading as if nothing were missing.

  defp hydrate(entry) do
    {resolved, lineage} = hydrate_spec(schema_of(entry), entry["spec"], MapSet.new())
    {Map.put(entry, "spec", resolved), Enum.uniq(lineage)}
  end

  defp hydrate_spec(schema, spec, seen) do
    R5e.Refs.map_refs(schema, spec, fn decl, ref ->
      if MapSet.member?(seen, ref) do
        # Cycle: leave the ref in place, flagged, rather than looping.
        {%{"$ref" => ref, "$cycle" => true}, [ref]}
      else
        {value, sub} = dereference(decl, ref, MapSet.put(seen, ref))
        {value, [ref | sub]}
      end
    end)
  end

  # `event:sha256:…` — the event envelope plus its decoded payload (§6).
  defp dereference(_decl, "event:" <> hash = ref, _seen) do
    case Enum.find(R5e.Log.events(), &(&1["hash"] == hash)) do
      nil ->
        {unresolved(ref, "no event with that hash is on this chain"), []}

      event ->
        case R5e.CAS.get(event["payload"] || "") do
          {:ok, bytes} -> {%{"event" => event, "payload" => decode_payload(bytes)}, []}
          {:error, _} -> {unresolved(ref, "the event's payload is not in the CAS"), []}
        end
    end
  end

  # `bytes:sha256:…` — the JSON value when the declaring property says
  # `json`, otherwise the object itself, base64-encoded, with its size and
  # — per §6 and amendment B8 — `mediaType`, but only when a `CasObject`
  # admission recorded one. An object with no recorded label is returned
  # without the key rather than with a guessed value: `application/
  # octet-stream` on a view is an assertion about the bytes that nobody
  # made.
  defp dereference(decl, "bytes:" <> address = ref, _seen) do
    case R5e.CAS.get(address) do
      {:error, _} ->
        {unresolved(ref, "no object at that address in this deployment's CAS"), []}

      {:ok, bytes} ->
        case decl && decl["json"] do
          nil ->
            {%{"size" => byte_size(bytes), "base64" => Base.encode64(bytes)}
             |> with_media_type(address), []}

          _json ->
            case Jason.decode(bytes) do
              {:ok, decoded} ->
                {decoded, []}

              {:error, _} ->
                {unresolved(ref, "declared json, but the object is not valid JSON"), []}
            end
        end
    end
  end

  # `sha256:…` — a bare CAS object. Under v2 no ref class carries this
  # form, so it only ever appears in a spec admitted before v2; the old
  # behaviour is kept so an existing record stays readable.
  defp dereference(_decl, ref, seen) when is_binary(ref) do
    if R5e.CAS.object_address?(ref) do
      case R5e.CAS.get(ref) do
        {:ok, bytes} -> {decode_payload(bytes), []}
        {:error, _} -> {unresolved(ref, "payload not in CAS"), []}
      end
    else
      hydrate_resource(ref, seen)
    end
  end

  # `g/v/K/name` — the stored entry, itself hydrated against *its* Kind's
  # schema. Left-split: three segments of API path, then the whole
  # remainder is the name, because names may contain `/` (§2).
  defp hydrate_resource(ref, seen) do
    with {:ok, group, version, kind, name} <- R5e.Refs.split_kind_ref(ref),
         entry when not is_nil(entry) <-
           Agent.get(__MODULE__, &get_in(&1, [:entries, key(group, version, kind, name)])) do
      {spec, sub} = hydrate_spec(schema_of(entry), entry["spec"], seen)
      {Map.put(entry, "spec", spec), sub}
    else
      :error -> {unresolved(ref, "unrecognized ref shape"), []}
      nil -> {unresolved(ref, "no such admitted resource"), []}
    end
  end

  # The schema an entry's spec was admitted against. A Kind that is no
  # longer in the registry leaves `nil`, and the walk then hydrates by
  # form alone — one class's worth of knowledge less, and the `json`
  # facet of a `bytes:` ref lost with it.
  defp schema_of(entry) do
    case R5e.KindRegistry.get(entry["group"], entry["version"], entry["kind"]) do
      {:ok, %R5e.Kind{schema: schema}} -> schema
      _ -> nil
    end
  end

  defp with_media_type(view, address) do
    case R5e.RefIndex.cas_object(address) do
      {:ok, %{"mediaType" => type}} when is_binary(type) and type != "" ->
        Map.put(view, "mediaType", type)

      _ ->
        view
    end
  end

  defp unresolved(ref, reason), do: %{"$ref" => ref, "$unresolved" => reason}

  defp decode_payload(bytes) do
    case Jason.decode(bytes) do
      {:ok, decoded} -> decoded
      {:error, _} -> %{"$raw" => Base.encode64(bytes)}
    end
  end

  defp key(group, version, kind, name), do: "#{group}/#{version}/#{kind}/#{name}"
end
