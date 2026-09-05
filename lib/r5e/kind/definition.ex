defmodule R5e.Kind.Definition do
  @moduledoc """
  §1's meta-checks on a *submitted* KindDefinition: the top-level keys,
  §3's schema grammar, §4's ref declarations, and §2's naming block.

  The rule the whole module exists for is §1's first line — **nothing a
  KindDefinition may declare is accepted-but-ignored**. A definition that
  says something the gate would not act on is a lie the record would carry
  forever, so every keyword is either enforced or refused here, and the
  refusal names the offending keyword, name or combination. `check/1`
  returns `:ok` or `{:error, reason}`, and `R5e.Admission` denies at
  `validateStructure` with it.

  The list of refusals is spec/05 §1 and is not restated here; what the
  code adds is the message.
  """

  alias R5e.Kind

  @top_level_keys ~w(group kind version substrate naming schema epistemicScope description predicates signatures requiresAuthority)
  @schema_keywords ~w(required nonEmpty properties exactlyOne atMostOne ordered requires additionalProperties)
  @prop_keywords ~w(type enum pattern minimum maximum items properties required additionalProperties values ref matchesSigner derives keyBytes)
  @types ~w(string integer boolean object array ref)

  @doc "The §1 meta-checks. `:ok`, or `{:error, reason}`."
  @spec check(term()) :: :ok | {:error, String.t()}
  def check(spec) when is_map(spec) do
    with :ok <- check_top_level_keys(spec),
         :ok <- Kind.require_strings(spec, ~w(group kind version substrate)),
         :ok <- Kind.check_substrate(spec["substrate"]),
         :ok <- Kind.check_description(spec["description"]),
         :ok <- check_predicates(spec["predicates"]),
         {:ok, signatures} <- Kind.check_signatures(spec["signatures"]),
         {:ok, _requires_authority} <- Kind.check_requires_authority(spec["requiresAuthority"]),
         {:ok, _scope, _defaulted} <- Kind.scope_or_default(spec["epistemicScope"]),
         :ok <- check_schema(spec["schema"], signatures),
         :ok <- check_same_anchor_placement(spec),
         :ok <- Kind.Naming.check(spec["naming"], spec["schema"]) do
      :ok
    end
  end

  def check(_), do: {:error, "KindDefinition must be a JSON object"}

  defp check_top_level_keys(spec) do
    case Enum.find(Map.keys(spec), &(&1 not in @top_level_keys)) do
      nil -> :ok
      key -> {:error, "undeclared top-level key #{inspect(key)}"}
    end
  end

  defp check_predicates(list) when is_list(list), do: :ok
  defp check_predicates(nil), do: {:error, "predicates is required (it may be [])"}

  defp check_predicates(other),
    do: {:error, "predicates must be an array, got #{Kind.kindof(other)}"}

  # -- sameAnchor placement (§4) -----------------------------------------

  # §4: `sameAnchor` is legal only on a property named `supersedes` whose
  # declared event Kind is the enclosing Kind. It is checked as a
  # placement rule, over the whole schema, because the constraint is about
  # *where* the keyword sits — a `sameAnchor` anywhere else would be
  # accepted-but-unenforceable, and v2 admits no such keyword.
  defp check_same_anchor_placement(spec) do
    schema = spec["schema"]
    props = (is_map(schema) && schema["properties"]) || %{}
    enclosing = "#{spec["group"]}/#{spec["version"]}/#{spec["kind"]}"

    schema
    |> anchored_sites("schema")
    |> Enum.sort_by(fn {where, _decl} -> where end)
    |> Enum.reduce_while(:ok, fn {where, ref}, _ ->
      field = ref["sameAnchor"]

      cond do
        where != "schema.properties.supersedes" ->
          {:halt,
           {:error,
            "#{where}.ref declares sameAnchor; it is legal only on a top-level property named \"supersedes\""}}

        ref["event"] != enclosing ->
          {:halt,
           {:error,
            "schema.properties.supersedes.ref declares sameAnchor on event Kind #{inspect(ref["event"])}; " <>
              "sameAnchor is legal only where the event Kind is the enclosing Kind #{enclosing}"}}

        not Map.has_key?(props, field) ->
          {:halt,
           {:error,
            "schema.properties.supersedes.ref.sameAnchor names #{inspect(field)}, which is not a declared property"}}

        true ->
          {:cont, :ok}
      end
    end)
  end

  # Every `ref` block carrying `sameAnchor`, with the schema path it sits
  # at. The walk is over the declaration, not the instance: nested
  # `properties`, `items` and `values` all count.
  defp anchored_sites(node, where) when is_map(node) do
    here =
      case node["ref"] do
        %{"sameAnchor" => field} = ref when is_binary(field) -> [{where, ref}]
        _ -> []
      end

    here ++
      anchored_children(node["properties"], "#{where}.properties") ++
      anchored_sites(node["items"], "#{where}.items") ++
      anchored_sites(node["values"], "#{where}.values")
  end

  defp anchored_sites(_node, _where), do: []

  defp anchored_children(props, where) when is_map(props) do
    props
    |> Enum.sort_by(fn {name, _} -> name end)
    |> Enum.flat_map(fn {name, prop} -> anchored_sites(prop, "#{where}.#{name}") end)
  end

  defp anchored_children(_props, _where), do: []

  # -- schema grammar (§3) ----------------------------------------------

  defp check_schema(schema, signatures) when is_map(schema) do
    with :ok <- Kind.check_keywords(schema, @schema_keywords, "schema"),
         :ok <- check_required_list(schema["required"], "schema.required"),
         :ok <- check_optional_list(schema["nonEmpty"], "schema.nonEmpty"),
         :ok <- check_additional_properties(schema["additionalProperties"]),
         :ok <- check_properties_map(schema["properties"], "schema.properties"),
         :ok <- check_group_lists(schema["exactlyOne"], schema["properties"], "exactlyOne"),
         :ok <- check_group_lists(schema["atMostOne"], schema["properties"], "atMostOne"),
         :ok <- check_ordered(schema["ordered"], schema["properties"]),
         :ok <- check_requires(schema["requires"], schema["properties"]),
         :ok <- declared?(schema["required"], schema["properties"], "required"),
         :ok <- declared?(schema["nonEmpty"], schema["properties"], "nonEmpty"),
         :ok <- check_props(schema["properties"], "schema.properties", signatures) do
      :ok
    end
  end

  defp check_schema(nil, _signatures), do: {:error, "schema is required"}

  defp check_schema(other, _signatures),
    do: {:error, "schema must be a JSON object, got #{Kind.kindof(other)}"}

  # v2 requires the closed form at the top level of a schema: undeclared
  # instance keys are denied, always.
  defp check_additional_properties(false), do: :ok

  defp check_additional_properties(nil),
    do: {:error, "schema.additionalProperties is required in schema-lite v2 and must be false"}

  defp check_additional_properties(other),
    do: {:error, "schema.additionalProperties must be false, got #{inspect(other)}"}

  defp check_required_list(list, where) when is_list(list) do
    if Enum.all?(list, &is_binary/1),
      do: :ok,
      else: {:error, "#{where} must be an array of field names"}
  end

  defp check_required_list(nil, where), do: {:error, "#{where} is required (it may be [])"}
  defp check_required_list(_, where), do: {:error, "#{where} must be an array of field names"}

  defp check_optional_list(nil, _where), do: :ok
  defp check_optional_list(list, where), do: check_required_list(list, where)

  defp check_properties_map(props, _where) when is_map(props) do
    limit = Kind.limit(:properties)

    cond do
      map_size(props) > limit ->
        {:error, "properties limit exceeded: #{map_size(props)} > #{limit}"}

      not Enum.all?(Map.keys(props), &is_binary/1) ->
        {:error, "property names must be strings"}

      true ->
        :ok
    end
  end

  defp check_properties_map(nil, where), do: {:error, "#{where} is required (it may be {})"}
  defp check_properties_map(_, where), do: {:error, "#{where} must be a JSON object"}

  # §3: `exactlyOne` and `atMostOne` share a shape — a list of non-empty
  # groups of declared fields — and differ only in the count they demand
  # of an instance, so the declaration check is one function.
  defp check_group_lists(nil, _props, _where), do: :ok

  defp check_group_lists(groups, props, where) when is_list(groups) do
    Enum.reduce_while(groups, :ok, fn group, _ ->
      cond do
        not is_list(group) or not Enum.all?(group, &is_binary/1) ->
          {:halt, {:error, "#{where} groups must be arrays of field names"}}

        group == [] ->
          {:halt, {:error, "empty #{where} group — a group must name at least one field"}}

        true ->
          case declared?(group, props, where) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end
      end
    end)
  end

  defp check_group_lists(_, _props, where),
    do: {:error, "#{where} must be an array of groups"}

  # §3/KS-3: `ordered` is pairs of two **distinct** declared **string**
  # properties. Not a list of fields to sort — a pair is a claim that one
  # instant is before the other, and a pair naming one field twice or a
  # non-string field is a claim the gate could not test.
  defp check_ordered(nil, _props), do: :ok

  defp check_ordered(pairs, props) when is_list(pairs) do
    Enum.reduce_while(pairs, :ok, fn pair, _ ->
      case ordered_pair(pair, props) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp check_ordered(_, _props), do: {:error, "ordered must be an array of pairs"}

  defp ordered_pair([a, b], props) when is_binary(a) and is_binary(b) do
    cond do
      a == b ->
        {:error, "ordered pair names #{inspect(a)} twice; a pair is two distinct fields"}

      true ->
        Enum.reduce_while([a, b], :ok, fn field, _ ->
          case props[field] do
            %{"type" => "string"} ->
              {:cont, :ok}

            nil ->
              {:halt,
               {:error, "ordered names #{inspect(field)}, which is not a declared property"}}

            _ ->
              {:halt, {:error, "ordered names #{inspect(field)}, which is not a string property"}}
          end
        end)
    end
  end

  defp ordered_pair(other, _props),
    do: {:error, "each ordered entry is a pair of two field names, got #{inspect(other)}"}

  defp check_requires(nil, _props), do: :ok

  defp check_requires(rules, props) when is_list(rules) do
    Enum.reduce_while(rules, :ok, fn rule, _ ->
      case check_requires_rule(rule, props) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp check_requires(_, _props), do: {:error, "requires must be an array of rules"}

  defp check_requires_rule(%{"when" => cond_, "then" => then_} = rule, props)
       when is_list(then_) do
    with :ok <- Kind.check_keywords(rule, ~w(when then), "requires rule"),
         :ok <- check_then(then_, props),
         :ok <- check_condition(cond_, props) do
      :ok
    end
  end

  defp check_requires_rule(_, _props),
    do: {:error, "each requires rule must be {when: ..., then: [field...]}"}

  # §3/KS-3: `then` is a list of fields, or a list of **groups** — a
  # nested group means "at least one of these". Both forms are checked
  # here; an empty `then`, an empty group, or an undeclared field in
  # either is a declaration the gate could not act on.
  defp check_then([], _props), do: {:error, "requires.then must name at least one field"}

  defp check_then(then_, props) when is_list(then_) do
    Enum.reduce_while(then_, :ok, fn
      field, _ when is_binary(field) ->
        continue(declared?([field], props, "requires.then"))

      [], _ ->
        {:halt, {:error, "empty requires.then group — a group must name at least one field"}}

      group, _ when is_list(group) ->
        if Enum.all?(group, &is_binary/1),
          do: continue(declared?(group, props, "requires.then")),
          else: {:halt, {:error, "a requires.then group must be an array of field names"}}

      other, _ ->
        {:halt,
         {:error, "requires.then takes field names or groups of them, got #{inspect(other)}"}}
    end)
  end

  defp continue(:ok), do: {:cont, :ok}
  defp continue(error), do: {:halt, error}

  defp check_condition(%{"field" => f, "equals" => v} = c, props) when is_binary(f) do
    cond do
      map_size(c) != 2 -> {:error, "requires.when {field, equals} takes no other keys"}
      not scalar?(v) -> {:error, "requires.when equals must be a scalar"}
      true -> declared?([f], props, "requires.when.field")
    end
  end

  defp check_condition(%{"present" => f} = c, props) when is_binary(f) do
    if map_size(c) != 1,
      do: {:error, "requires.when {present} takes no other keys"},
      else: declared?([f], props, "requires.when.present")
  end

  # §3/KS-3: the envelope condition. It reads the *request*, not the spec,
  # which is why it is the one condition whose field is not a declared
  # property: `authority` is a fact about the act, and a Kind that says
  # "if you exercised authority, name the parent you exercised" is making
  # a rule about the act rather than about the document.
  defp check_condition(%{"envelope" => field, "present" => present} = c, _props) do
    cond do
      map_size(c) != 2 ->
        {:error, "requires.when {envelope, present} takes no other keys"}

      field != "authority" ->
        {:error, "requires.when.envelope must be \"authority\", got #{inspect(field)}"}

      not is_boolean(present) ->
        {:error, "requires.when.present must be a boolean"}

      true ->
        :ok
    end
  end

  defp check_condition(_, _props),
    do: {:error, "requires.when must be {field, equals}, {present}, or {envelope, present}"}

  defp declared?(nil, _props, _where), do: :ok

  defp declared?(names, props, where) when is_list(names) and is_map(props) do
    case Enum.find(names, &(not Map.has_key?(props, &1))) do
      nil -> :ok
      name -> {:error, "#{where} names #{inspect(name)}, which is not a declared property"}
    end
  end

  defp declared?(names, _props, where) when is_list(names) and names != [],
    do: {:error, "#{where} names fields but no properties are declared"}

  defp declared?(_, _, _), do: :ok

  # -- one property (§3), and its ref declaration (§4) -------------------

  defp check_props(props, where, signatures) when is_map(props) do
    props
    |> Enum.sort_by(fn {k, _} -> k end)
    |> Enum.reduce_while(:ok, fn {name, prop}, _ ->
      case check_prop(prop, "#{where}.#{name}", signatures, props) do
        :ok -> {:cont, :ok}
        error -> {:halt, error}
      end
    end)
  end

  defp check_props(_, _, _), do: :ok

  defp check_prop(prop, where, signatures, siblings) when is_map(prop) do
    with :ok <- Kind.check_keywords(prop, @prop_keywords, "#{where} property"),
         {:ok, types} <- check_types(prop["type"], where),
         :ok <- check_enum(prop["enum"], where),
         :ok <- check_pattern_decl(prop["pattern"], types, where),
         :ok <- check_bounds(prop, types, where),
         :ok <- check_items(prop, types, where, signatures),
         :ok <- check_object_keywords(prop, types, where, signatures),
         :ok <- check_matches_signer(prop, types, where, signatures),
         :ok <- check_derives(prop, types, where, siblings),
         :ok <- check_key_bytes(prop, types, where),
         :ok <- check_ref_decl(prop, types, where, signatures) do
      :ok
    end
  end

  defp check_prop(_, where, _signatures, _siblings),
    do: {:error, "#{where} must be a JSON object"}

  # -- KS-3's three key-shaped keywords ----------------------------------

  # `matchesSigner: N` — the value must equal signer N's keyid. Refused
  # on anything but a string, refused for an N the envelope cannot have,
  # and refused for an N this Kind does not take: a Kind declaring
  # `matchesSigner: 2` with one signature would be declaring a check that
  # can never run, which §1 forbids.
  defp check_matches_signer(prop, types, where, signatures) do
    case Map.fetch(prop, "matchesSigner") do
      :error ->
        :ok

      {:ok, n} when n in [1, 2] ->
        cond do
          "string" not in types ->
            {:error, "#{where} declares matchesSigner without \"string\" in type"}

          n > signatures ->
            {:error,
             "#{where} declares matchesSigner #{n}, but this Kind is admitted on " <>
               "#{signatures} signature(s)"}

          true ->
            :ok
        end

      {:ok, other} ->
        {:error, "#{where} matchesSigner must be 1 or 2, got #{inspect(other)}"}
    end
  end

  # `derives: {keyIdOf: field}` — the value must equal the key id of a
  # sibling `keyBytes` property. Naming anything else would be a
  # derivation the gate cannot perform.
  defp check_derives(prop, types, where, siblings) do
    case Map.fetch(prop, "derives") do
      :error ->
        :ok

      {:ok, %{"keyIdOf" => field} = decl} when is_binary(field) ->
        cond do
          map_size(decl) != 1 ->
            {:error, "#{where}.derives takes only keyIdOf"}

          "string" not in types ->
            {:error, "#{where} declares derives without \"string\" in type"}

          not key_bytes_prop?(siblings[field]) ->
            {:error,
             "#{where}.derives.keyIdOf names #{inspect(field)}, which is not a keyBytes property"}

          true ->
            :ok
        end

      {:ok, other} ->
        {:error, "#{where}.derives must be {keyIdOf: <field>}, got #{inspect(other)}"}
    end
  end

  defp key_bytes_prop?(%{"keyBytes" => true}), do: true
  defp key_bytes_prop?(_), do: false

  # `keyBytes: true` — an object with exactly `algorithm` and `bytes`,
  # both required, closed, and an `algorithm` enum inside §0's registry.
  # The shape is fixed here so the instance check is a length test and
  # nothing more.
  defp check_key_bytes(prop, types, where) do
    case Map.fetch(prop, "keyBytes") do
      :error ->
        :ok

      {:ok, true} ->
        props = prop["properties"]

        cond do
          "object" not in types ->
            {:error, "#{where} declares keyBytes without \"object\" in type"}

          not is_map(props) or Enum.sort(Map.keys(props)) != ["algorithm", "bytes"] ->
            {:error,
             "#{where} declares keyBytes, so its properties are exactly algorithm and bytes"}

          Enum.sort(prop["required"] || []) != ["algorithm", "bytes"] ->
            {:error, "#{where} declares keyBytes, so algorithm and bytes are both required"}

          prop["additionalProperties"] != false ->
            {:error, "#{where} declares keyBytes, so additionalProperties must be false"}

          true ->
            registry_subset(props["algorithm"], where)
        end

      {:ok, other} ->
        {:error, "#{where}.keyBytes must be true, got #{inspect(other)}"}
    end
  end

  defp registry_subset(%{"enum" => enum}, where) when is_list(enum) and enum != [] do
    case Enum.find(enum, &(RecurseVerify.DSSE.algorithm(&1) == :error)) do
      nil ->
        :ok

      unknown ->
        {:error,
         "#{where}.properties.algorithm enum names #{inspect(unknown)}, " <>
           "which is not in the §0 algorithm registry"}
    end
  end

  defp registry_subset(_algorithm, where),
    do:
      {:error,
       "#{where} declares keyBytes, so its algorithm property carries an enum inside the " <>
         "§0 registry"}

  defp check_types(nil, where), do: {:error, "#{where} declares no type"}

  defp check_types(t, where) when is_binary(t) do
    if t in @types,
      do: {:ok, [t]},
      else: {:error, "#{where} declares unknown type #{inspect(t)}"}
  end

  defp check_types(list, where) when is_list(list) do
    unknown = Enum.find(list, &(&1 not in @types))

    cond do
      list == [] ->
        {:error, "#{where} declares an empty type union"}

      Enum.uniq(list) != list ->
        {:error, "#{where} declares a duplicate member in its type union"}

      unknown ->
        {:error, "#{where} declares unknown type #{inspect(unknown)}"}

      length(list) > 1 and "ref" in list ->
        {:error, "#{where}: \"ref\" may not appear in a type union"}

      true ->
        {:ok, list}
    end
  end

  defp check_types(other, where),
    do: {:error, "#{where} type must be a string or an array, got #{Kind.kindof(other)}"}

  defp check_enum(nil, _where), do: :ok

  defp check_enum(list, where) when is_list(list) do
    cond do
      list == [] -> {:error, "#{where} declares an empty enum"}
      not Enum.all?(list, &scalar?/1) -> {:error, "#{where} enum members must be scalars"}
      true -> :ok
    end
  end

  defp check_enum(_, where), do: {:error, "#{where} enum must be an array"}

  defp check_pattern_decl(nil, _types, _where), do: :ok

  defp check_pattern_decl(pattern, types, where) when is_binary(pattern) do
    limit = Kind.limit(:pattern)

    cond do
      "string" not in types ->
        {:error, "#{where} declares pattern without \"string\" in type"}

      byte_size(pattern) > limit ->
        {:error, "#{where} pattern exceeds #{limit} bytes"}

      true ->
        with :ok <- Kind.re2_subset(pattern),
             {:ok, _} <- Kind.compile_pattern(pattern) do
          :ok
        else
          {:error, reason} -> {:error, "#{where} pattern #{reason}"}
        end
    end
  end

  defp check_pattern_decl(_, _types, where), do: {:error, "#{where} pattern must be a string"}

  defp check_bounds(prop, types, where) do
    Enum.reduce_while(~w(minimum maximum), :ok, fn key, _ ->
      case Map.fetch(prop, key) do
        :error ->
          {:cont, :ok}

        {:ok, v} when is_integer(v) ->
          if "integer" in types,
            do: {:cont, :ok},
            else: {:halt, {:error, "#{where} declares #{key} without \"integer\" in type"}}

        {:ok, _} ->
          {:halt, {:error, "#{where} #{key} must be an integer"}}
      end
    end)
  end

  # `items` is legal only where the declared type is exactly "array", and
  # required there. A union containing "array" passes arrays whole (§3), so
  # `items` beside one would be accepted-but-ignored — which v2 forbids.
  defp check_items(prop, types, where, signatures) do
    case {types, Map.fetch(prop, "items")} do
      {["array"], :error} -> {:error, "#{where} declares type \"array\" without items"}
      {["array"], {:ok, items}} -> check_prop(items, "#{where}.items", signatures, %{})
      {_, {:ok, _}} -> {:error, "#{where} declares items but its type is not exactly \"array\""}
      {_, :error} -> :ok
    end
  end

  defp check_object_keywords(prop, types, where, signatures) do
    present =
      Enum.filter(~w(properties required additionalProperties values), &Map.has_key?(prop, &1))

    if present != [] and "object" not in types do
      {:error, "#{where} declares #{inspect(hd(present))} without \"object\" in type"}
    else
      with :ok <- check_nested_additional(prop, where),
           :ok <- check_nested_properties(prop, where, signatures),
           :ok <- declared?(prop["required"], prop["properties"], "#{where}.required"),
           :ok <- check_optional_list(prop["required"], "#{where}.required"),
           :ok <- check_nested_values(prop, where, signatures) do
        :ok
      end
    end
  end

  defp check_nested_additional(prop, where) do
    case Map.fetch(prop, "additionalProperties") do
      :error ->
        :ok

      {:ok, false} ->
        :ok

      {:ok, other} ->
        {:error, "#{where}.additionalProperties must be false, got #{inspect(other)}"}
    end
  end

  defp check_nested_properties(prop, where, signatures) do
    case Map.fetch(prop, "properties") do
      :error ->
        :ok

      {:ok, props} ->
        with :ok <- check_properties_map(props, "#{where}.properties"),
             :ok <- check_props(props, "#{where}.properties", signatures) do
          :ok
        end
    end
  end

  defp check_nested_values(prop, where, signatures) do
    case Map.fetch(prop, "values") do
      :error -> :ok
      {:ok, values} -> check_prop(values, "#{where}.values", signatures, %{})
    end
  end

  # The refdecl grammar of §4. What the value must point at, and the
  # manifest it produces, are `R5e.Resolve`'s; what is checked here is the
  # declaration.
  defp check_ref_decl(prop, types, where, signatures) do
    case {types, Map.fetch(prop, "ref")} do
      {["ref"], :error} -> {:error, "#{where} declares type \"ref\" without a ref declaration"}
      {["ref"], {:ok, ref}} -> check_refdecl(ref, where, signatures)
      {_, {:ok, _}} -> {:error, "#{where} declares ref without \"ref\" in type"}
      {_, :error} -> :ok
    end
  end

  defp check_refdecl(%{"kind" => path} = ref, where, _signatures) when is_binary(path) do
    with :ok <- Kind.check_keywords(ref, ~w(kind), "#{where}.ref"),
         :ok <- api_path(path, "#{where}.ref.kind") do
      :ok
    end
  end

  defp check_refdecl(%{"event" => path} = ref, where, _signatures) do
    with :ok <- Kind.check_keywords(ref, ~w(event outcome sameAnchor sameActor), "#{where}.ref"),
         :ok <- check_event_paths(path, where),
         :ok <- check_outcome(ref["outcome"], where),
         :ok <- check_same_anchor(ref["sameAnchor"], where),
         :ok <- check_same_actor(ref["sameActor"], where) do
      :ok
    end
  end

  defp check_refdecl(%{"bytes" => true} = ref, where, signatures) do
    with :ok <- Kind.check_keywords(ref, ~w(bytes json retention), "#{where}.ref"),
         :ok <- check_retention(ref["retention"], where),
         :ok <- check_ref_json(ref, where, signatures) do
      :ok
    end
  end

  defp check_refdecl(_, where, _signatures),
    do:
      {:error,
       "#{where}.ref must be {kind: \"g/v/K\"} | {event: \"g/v/K\", ...} | {bytes: true, ...}"}

  defp check_ref_json(ref, where, signatures) do
    case Map.fetch(ref, "json") do
      :error -> :ok
      {:ok, json} -> check_prop(json, "#{where}.ref.json", signatures, %{})
    end
  end

  defp check_outcome(nil, _where), do: :ok
  defp check_outcome(o, _where) when o in ~w(admitted any), do: :ok

  defp check_outcome(o, where),
    do: {:error, "#{where}.ref.outcome must be \"admitted\" or \"any\", got #{inspect(o)}"}

  # §5/KS-5: an `event` refdecl accepts a Kind **list** — a Revocation
  # cites an Endorsement, a Badge or a Succession, and three declarations
  # would be three properties for one citation. An empty list, a malformed
  # path or a duplicate is refused: each would be a declaration naming
  # something the gate cannot test.
  defp check_event_paths(path, where) when is_binary(path),
    do: api_path(path, "#{where}.ref.event")

  defp check_event_paths(paths, where) when is_list(paths) do
    cond do
      paths == [] ->
        {:error, "#{where}.ref.event is an empty list; a citation must name a Kind"}

      Enum.uniq(paths) != paths ->
        {:error, "#{where}.ref.event names the same Kind twice"}

      true ->
        Enum.reduce_while(paths, :ok, fn path, _ ->
          continue(api_path(path, "#{where}.ref.event"))
        end)
    end
  end

  defp check_event_paths(other, where),
    do:
      {:error,
       "#{where}.ref.event must be \"group/version/Kind\" or a list of them, got #{inspect(other)}"}

  # §5/KS-5: `sameActor` is legal only on an event refdecl and only as
  # `true` — it is a rule about who may cite the target, and `false` would
  # declare a check that never runs.
  defp check_same_actor(nil, _where), do: :ok
  defp check_same_actor(true, _where), do: :ok

  defp check_same_actor(other, where),
    do: {:error, "#{where}.ref.sameActor must be true when present, got #{inspect(other)}"}

  defp check_same_anchor(nil, _where), do: :ok
  defp check_same_anchor(f, _where) when is_binary(f), do: :ok
  defp check_same_anchor(_, where), do: {:error, "#{where}.ref.sameAnchor must be a field name"}

  defp check_retention(nil, _where), do: :ok
  defp check_retention("public-record", _where), do: :ok

  defp check_retention(r, where),
    do: {:error, "#{where}.ref.retention must be \"public-record\", got #{inspect(r)}"}

  defp api_path(path, where) do
    case String.split(path, "/") do
      [g, v, k] when g != "" and v != "" and k != "" -> :ok
      _ -> {:error, "#{where} must be \"group/version/Kind\", got #{inspect(path)}"}
    end
  end

  defp scalar?(v), do: is_binary(v) or is_integer(v) or is_boolean(v)
end
