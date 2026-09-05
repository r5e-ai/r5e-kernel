defmodule R5e.Refs do
  @moduledoc """
  Typed refs (spec/05 §4): the declaration grammar's *values*, the walk
  that finds them in a spec, and the RFC 6901 pointers that name them.

  Three classes, each with exactly one legal value form:

  | declaration | class | value |
  |---|---|---|
  | `{kind: "g/v/K"}` | `kind` | `g/v/K/name` |
  | `{event: "g/v/K", outcome?, sameAnchor?}` | `event` | `event:sha256:<64 hex>` |
  | `{bytes: true, json?, retention?}` | `bytes` | `bytes:sha256:<64 hex>` |

  Two consumers share this walk, so they cannot drift: `R5e.Resolve` (the
  `resolve` stage, which turns each site into a manifest entry) and
  `R5e.ResourceStore` (deep hydration, which replaces each site with what
  it points at). The declaration is what makes both *typed*: hydration
  knows a `bytes` ref carries JSON only because the declaration says
  `json`, and resolve knows what Kind an event must have admitted.

  A **site** is `{pointer, refdecl, value}`. The pointer is RFC 6901 into
  the spec (`/toolCalls/0`), with `~` and `/` escaped as `~0` and `~1`, so
  a property name containing a slash still names one location.

  Only a *declared* ref-typed property can hold a ref value — `$ref`
  anywhere else is refused at `validateStructure` (§3) — so walking the
  declaration finds every ref there is, and a ref the walk misses is a ref
  the validator would have refused.
  """

  @hex ~r/\A[0-9a-f]{64}\z/

  # -- the declaration ---------------------------------------------------

  @doc "The class a ref declaration names."
  @spec class(map()) :: :kind | :event | :bytes | :unknown
  def class(%{"kind" => _}), do: :kind
  def class(%{"event" => _}), do: :event
  def class(%{"bytes" => _}), do: :bytes
  def class(_), do: :unknown

  @doc "The declared target, for a denial message: an API path, or `raw bytes`."
  @spec declared_target(map()) :: String.t()
  def declared_target(%{"kind" => path}), do: "kind #{path}"

  def declared_target(%{"event" => path} = decl) do
    "event #{path |> List.wrap() |> Enum.join(" | ")} (outcome #{outcome(decl)})" <>
      case decl["sameAnchor"] do
        nil -> ""
        field -> ", sameAnchor #{field}"
      end
  end

  def declared_target(%{"bytes" => _} = decl) do
    "raw bytes" <>
      if(decl["json"], do: " (declared json)", else: "") <>
      case decl["retention"] do
        nil -> ""
        r -> " (retention #{r})"
      end
  end

  def declared_target(_), do: "an unrecognized ref declaration"

  @doc "The outcome facet of an event ref declaration; `admitted` by default (§4)."
  @spec outcome(map()) :: String.t()
  def outcome(decl), do: decl["outcome"] || "admitted"

  @doc "The value form this declaration requires, as prose for a denial."
  @spec value_form(map()) :: String.t()
  def value_form(%{"kind" => _}), do: "group/version/Kind/name"
  def value_form(%{"event" => _}), do: "event:sha256:<64 lowercase hex>"
  def value_form(%{"bytes" => _}), do: "bytes:sha256:<64 lowercase hex>"
  def value_form(_), do: "a ref value"

  @doc """
  Check a ref *value* against its declaration's class (§4). Form only —
  whether the thing it names exists is `resolve`'s question, one stage
  later. A form error is a structural defect and denies at
  `validateStructure`.
  """
  @spec check_value(map(), term()) :: :ok | {:error, String.t()}
  def check_value(decl, value) when is_binary(value) do
    if valid_value?(decl, value),
      do: :ok,
      else: {:error, "must be #{value_form(decl)}, got #{inspect(value)}"}
  end

  def check_value(_decl, value), do: {:error, "$ref must be a string, got #{inspect(value)}"}

  @doc "Is this the legal value form for the declaration's class?"
  @spec valid_value?(map(), String.t()) :: boolean()
  def valid_value?(decl, value) do
    case class(decl) do
      :kind -> match?({:ok, _, _, _, _}, split_kind_ref(value))
      :event -> hashed?("event:", value)
      :bytes -> bytes_address?(value)
      :unknown -> false
    end
  end

  @doc """
  Is this the `bytes:sha256:<64 lowercase hex>` form (§4)?

  The one predicate, because three places ask it and three spellings are
  three chances to disagree: a `bytes` ref value here, §1's envelope
  `derivedFrom` at `R5e.Admission`, and each `derivedObjects` entry a
  policy engine reports (§5, amendment C6) at `R5e.Policy`.
  """
  @spec bytes_address?(term()) :: boolean()
  def bytes_address?(value), do: hashed?("bytes:", value)

  @doc """
  Split a `kind` ref value into `{group, version, Kind, name}`. The split
  is **from the left** — three path segments, then the whole remainder is
  the name, because a name may itself contain `/` (§2).
  """
  @spec split_kind_ref(String.t()) ::
          {:ok, String.t(), String.t(), String.t(), String.t()} | :error
  def split_kind_ref(value) when is_binary(value) do
    case String.split(value, "/", parts: 4) do
      [g, v, k, name] when g != "" and v != "" and k != "" ->
        if R5e.Kind.valid_name?(name), do: {:ok, g, v, k, name}, else: :error

      _ ->
        :error
    end
  end

  def split_kind_ref(_), do: :error

  @doc "The CAS address an `event:`/`bytes:` ref value carries (§6: one tree)."
  @spec object_address(String.t()) :: String.t()
  def object_address("event:" <> addr), do: addr
  def object_address("bytes:" <> addr), do: addr
  def object_address(addr), do: addr

  @doc """
  Is this value a **ref value** (§3) — an object whose only key is `$ref`?
  `R5e.Kind.Validate` asks it to refuse a `$ref` anywhere else; the walks
  below ask it to find the ones that belong.
  """
  @spec ref_wrapper?(term()) :: boolean()
  def ref_wrapper?(v), do: is_map(v) and map_size(v) == 1 and Map.has_key?(v, "$ref")

  defp hashed?(prefix, value) do
    case value do
      ^prefix <> "sha256:" <> hex -> Regex.match?(@hex, hex)
      _ -> false
    end
  end

  # -- the walk ----------------------------------------------------------

  @doc """
  Every ref site in `spec`, in document order, as `{pointer, refdecl,
  value}`. `schema` is the Kind's `schema` (§3); a spec walked against a
  schema that declares no refs yields `[]`.
  """
  @spec sites(map(), map()) :: [{String.t(), map(), String.t()}]
  def sites(schema, spec) when is_map(schema) and is_map(spec),
    do: walk_object(schema, spec, "")

  def sites(_schema, _spec), do: []

  defp walk_object(level, value, path) when is_map(level) and is_map(value) do
    props = level["properties"] || %{}
    values = level["values"]

    value
    |> Enum.sort_by(fn {k, _} -> k end)
    |> Enum.flat_map(fn {key, sub} ->
      # `properties` and `values` are conjunctive (§3); one *location*
      # gets one manifest entry, so the named property wins where both
      # declare the same key.
      walk(Map.get(props, key) || values, sub, path <> "/" <> escape(key))
    end)
  end

  defp walk_object(_level, _value, _path), do: []

  defp walk(nil, _value, _path), do: []
  defp walk(_decl, nil, _path), do: []

  defp walk(decl, value, path) when is_map(decl) do
    cond do
      is_map(decl["ref"]) and ref_wrapper?(value) ->
        [{path, decl["ref"], value["$ref"]}]

      is_map(value) ->
        walk_object(decl, value, path)

      is_list(value) ->
        walk_items(decl["items"], value, path)

      true ->
        []
    end
  end

  defp walk(_decl, _value, _path), do: []

  defp walk_items(nil, _list, _path), do: []

  defp walk_items(items, list, path) do
    list
    |> Enum.with_index()
    |> Enum.flat_map(fn {v, i} -> walk(items, v, "#{path}/#{i}") end)
  end

  @doc """
  Rebuild `spec` with every ref value replaced by `fun.(refdecl, value)`.

  `refdecl` is `nil` where the walk has no declaration to offer — inside
  an object a pre-v2 definition left open, for instance. Such a node is
  still handed to `fun`, because a record admitted under the old rules is
  not retroactively unreadable; what the caller loses is the *type*, and
  it can see that from the `nil`.

  Returns `{rebuilt, [ref…]}`: the second element is the lineage, every
  ref this view was computed from, in the order encountered.
  """
  @spec map_refs(map() | nil, term(), (map() | nil, String.t() -> {term(), [String.t()]})) ::
          {term(), [String.t()]}
  def map_refs(level, value, fun), do: do_map(level, value, fun)

  defp do_map(level, value, fun) when is_map(value) do
    if ref_wrapper?(value) and is_binary(value["$ref"]) do
      fun.(level && level["ref"], value["$ref"])
    else
      props = (is_map(level) && level["properties"]) || %{}
      values = is_map(level) && level["values"]

      Enum.reduce(value, {%{}, []}, fn {k, v}, {acc, lineage} ->
        {mapped, sub} = do_map(Map.get(props, k) || values, v, fun)
        {Map.put(acc, k, mapped), lineage ++ sub}
      end)
    end
  end

  defp do_map(level, value, fun) when is_list(value) do
    items = is_map(level) && level["items"]

    Enum.reduce(value, {[], []}, fn v, {acc, lineage} ->
      {mapped, sub} = do_map(items, v, fun)
      {acc ++ [mapped], lineage ++ sub}
    end)
  end

  defp do_map(_level, value, _fun), do: {value, []}

  @doc "RFC 6901 escaping for one pointer segment: `~` → `~0`, `/` → `~1`."
  @spec escape(String.t()) :: String.t()
  def escape(segment) do
    segment |> String.replace("~", "~0") |> String.replace("/", "~1")
  end

  @doc """
  Every `{pointer, value}` a spec carries as a bare ref wrapper, found
  without consulting any schema. `sites/2` is the typed walk; this is the
  untyped one, used to ask whether a manifest accounts for every ref in a
  spec (§10). The two agree by construction, because `$ref` is admissible
  only at a declared ref-typed property.
  """
  @spec bare_sites(term()) :: [{String.t(), String.t()}]
  def bare_sites(value), do: bare(value, "")

  defp bare(value, path) when is_map(value) do
    if ref_wrapper?(value) and is_binary(value["$ref"]) do
      [{path, value["$ref"]}]
    else
      value
      |> Enum.sort_by(fn {k, _} -> k end)
      |> Enum.flat_map(fn {k, v} -> bare(v, path <> "/" <> escape(k)) end)
    end
  end

  defp bare(value, path) when is_list(value) do
    value
    |> Enum.with_index()
    |> Enum.flat_map(fn {v, i} -> bare(v, "#{path}/#{i}") end)
  end

  defp bare(_value, _path), do: []
end
