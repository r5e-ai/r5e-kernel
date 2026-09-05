defmodule R5e.Kind.Validate do
  @moduledoc """
  §3 applied to an *instance*, in the two halves the §4 pipeline runs
  either side of policy.

  `structure/2` is `validateStructure`: the recursive no-float scan, §3's
  limits, `type` (including unions), the ref-wrapper form and
  `additionalProperties`. Kind lookup and naming belong to
  `R5e.Admission`, not here.

  `constraints/2` is `validateConstraints`: `required`, `nonEmpty`,
  `enum`, `pattern`, `minimum`/`maximum`, `exactlyOne`, `requires`, and
  the same set nested through `properties`/`items`/`values`.

  The split is the pipeline's, and the reason is `R5e.Admission`'s: policy
  must see a structurally sound request and must decide before the
  request's constraints are judged. Both halves return `{:error, [message]}`
  — a list, because the gate joins them into one denial reason.

  `exists` and `nonEmpty` are §0's two predicates and live on `R5e.Kind`,
  because `R5e.Resolve` and `R5e.Commit` ask them of specs too.
  """

  alias R5e.Kind

  # -- validateStructure -------------------------------------------------

  @doc "The structural half. Runs *before* the policy stage."
  @spec structure(Kind.t(), term()) :: :ok | {:error, [String.t()]}
  def structure(%Kind{schema: schema}, instance) do
    with :ok <- must_be_object(instance),
         :ok <- scan_no_floats(instance, ""),
         :ok <- check_limits(instance),
         :ok <- struct_object(schema, instance, "") do
      :ok
    else
      {:error, message} -> {:error, [message]}
    end
  end

  defp must_be_object(instance) when is_map(instance), do: :ok
  defp must_be_object(_), do: {:error, "instance must be a JSON object"}

  # No JSON float anywhere in a spec, at any depth, declared or not.
  defp scan_no_floats(v, path) when is_float(v),
    do: {:error, "#{at(path)}: floats are not admissible anywhere in a spec (got #{v})"}

  defp scan_no_floats(map, path) when is_map(map),
    do: reduce_ok(map, fn {k, v} -> scan_no_floats(v, "#{path}/#{k}") end)

  defp scan_no_floats(list, path) when is_list(list),
    do: indexed_ok(list, fn v, i -> scan_no_floats(v, "#{path}/#{i}") end)

  defp scan_no_floats(_, _), do: :ok

  defp check_limits(instance) do
    with :ok <- walk_limits(instance, 1, "") do
      size = byte_size(R5e.Canonical.encode(instance))

      if size > Kind.limit(:spec),
        do: {:error, "spec limit exceeded: #{size} bytes > #{Kind.limit(:spec)}"},
        else: :ok
    end
  end

  defp walk_limits(map, depth, path) when is_map(map) do
    cond do
      depth > Kind.limit(:depth) ->
        {:error, "#{at(path)}: depth limit exceeded (> #{Kind.limit(:depth)})"}

      map_size(map) > Kind.limit(:properties) ->
        {:error,
         "#{at(path)}: properties limit exceeded (#{map_size(map)} > #{Kind.limit(:properties)})"}

      true ->
        reduce_ok(map, fn {k, v} -> walk_limits(v, depth + 1, "#{path}/#{k}") end)
    end
  end

  defp walk_limits(list, depth, path) when is_list(list) do
    cond do
      depth > Kind.limit(:depth) ->
        {:error, "#{at(path)}: depth limit exceeded (> #{Kind.limit(:depth)})"}

      length(list) > Kind.limit(:array) ->
        {:error,
         "#{at(path)}: array length limit exceeded (#{length(list)} > #{Kind.limit(:array)})"}

      true ->
        indexed_ok(list, fn v, i -> walk_limits(v, depth + 1, "#{path}/#{i}") end)
    end
  end

  defp walk_limits(_, _, _), do: :ok

  # An object level: the top-level schema and any object-typed property
  # with `properties`/`values`/`additionalProperties` share this shape.
  # `properties` and `values` are conjunctive (§3), so a key governed by
  # both is checked against both.
  defp struct_object(level, value, path) do
    props = level["properties"] || %{}
    values = level["values"]
    closed? = level["additionalProperties"] == false

    reduce_ok(value, fn {key, sub} ->
      declared = Map.get(props, key)
      here = "#{path}/#{key}"

      cond do
        declared == nil and closed? ->
          {:error, "#{at(path)}: undeclared key #{inspect(key)} (additionalProperties is false)"}

        declared == nil and values == nil ->
          # Governed by neither, so not walked — but it still may not
          # smuggle a `$ref` (§3: a `$ref` key anywhere else is an error).
          scan_no_refs(sub, here)

        true ->
          with :ok <- struct_maybe(declared, sub, here),
               :ok <- struct_maybe(values, sub, here) do
            :ok
          end
      end
    end)
  end

  defp struct_maybe(nil, _sub, _path), do: :ok
  defp struct_maybe(prop, sub, path), do: struct_value(prop, sub, path)

  defp struct_value(prop, value, path) do
    types = types(prop)

    cond do
      # An explicit null on a declared property is not-exists: not type-checked.
      value == nil ->
        :ok

      R5e.Refs.ref_wrapper?(value) ->
        struct_ref(prop, types, value["$ref"], path)

      is_map(value) and Map.has_key?(value, "$ref") ->
        {:error, "#{at(path)}: a ref value must have $ref as its only key"}

      "ref" in types ->
        {:error, "#{at(path)}: declared type is \"ref\", so the value must be {\"$ref\": ...}"}

      types != [] and not Enum.any?(types, &type_match?(&1, value)) ->
        {:error,
         "#{at(path)}: must be of type #{Enum.join(types, "|")}, got #{Kind.kindof(value)}"}

      true ->
        struct_descend(prop, value, path)
    end
  end

  # §4: each class has exactly one legal value form, and a malformed one
  # is a structural defect — refused here, before `resolve` is asked to
  # look anything up. A definition replayed from before v2 can declare
  # `"ref"` with no `ref` block; there is no class to check its value
  # against, and it is left as it was rather than denied.
  defp struct_ref(prop, types, ref, path) do
    cond do
      "ref" not in types ->
        {:error, "#{at(path)}: a ref value is admissible only where the declared type is \"ref\""}

      not is_binary(ref) ->
        {:error, "#{at(path)}: $ref must be a string"}

      not is_map(prop["ref"]) ->
        :ok

      true ->
        case R5e.Refs.check_value(prop["ref"], ref) do
          :ok -> :ok
          {:error, reason} -> {:error, "#{at(path)}: $ref #{reason}"}
        end
    end
  end

  defp struct_descend(prop, value, path) when is_map(value) do
    if Map.has_key?(prop, "properties") or Map.has_key?(prop, "values") or
         Map.has_key?(prop, "additionalProperties") do
      struct_object(prop, value, path)
    else
      # An open object is passed whole — but never with a ref inside it.
      scan_no_refs(value, path)
    end
  end

  defp struct_descend(prop, value, path) when is_list(value) do
    case Map.fetch(prop, "items") do
      {:ok, items} -> indexed_ok(value, fn v, i -> struct_value(items, v, "#{path}/#{i}") end)
      :error -> scan_no_refs(value, path)
    end
  end

  defp struct_descend(_prop, _value, _path), do: :ok

  defp scan_no_refs(map, path) when is_map(map) do
    if Map.has_key?(map, "$ref") do
      {:error, "#{at(path)}: $ref is admissible only where the declared type is \"ref\""}
    else
      reduce_ok(map, fn {k, v} -> scan_no_refs(v, "#{path}/#{k}") end)
    end
  end

  defp scan_no_refs(list, path) when is_list(list),
    do: indexed_ok(list, fn v, i -> scan_no_refs(v, "#{path}/#{i}") end)

  defp scan_no_refs(_, _), do: :ok

  # -- validateConstraints -----------------------------------------------

  @doc """
  The constraint half. Runs *after* the policy stage — a request the
  policy refused never reaches it.

  §2 fixes the order the keywords are asked in:

      required, nonEmpty, keyBytes, enum, pattern, minimum/maximum,
      derives, matchesSigner, ordered, exactlyOne, atMostOne, requires

  and **the first failing keyword names the reason**. That is a
  statement about the record, not about efficiency: two kernels that
  check the same instance must produce the same denial, so the order is
  one pass per keyword over the whole instance rather than one pass over
  the instance asking every keyword. An instance that breaks two rules is
  refused for the earlier one, always, on every implementation.

  `context` carries what a keyword needs from outside the spec —
  `signers` for `matchesSigner`. It defaults to empty, and a keyword
  whose context is missing is skipped rather than guessed at: a legacy
  caller validating a spec on its own is not making a claim about who
  signed it.
  """
  @spec constraints(Kind.t(), term(), map()) :: :ok | {:error, [String.t()]}
  def constraints(kind, instance, context \\ %{})

  def constraints(%Kind{schema: schema}, instance, context) do
    with :ok <- must_be_object(instance) do
      levels = levels(schema, instance)
      sites = sites(schema, instance)

      result =
        Enum.reduce_while(passes(), :ok, fn pass, _ ->
          case pass.(schema, instance, levels, sites, context) do
            :ok -> {:cont, :ok}
            error -> {:halt, error}
          end
        end)

      case result do
        :ok -> :ok
        {:error, message} -> {:error, [message]}
      end
    else
      {:error, message} -> {:error, [message]}
    end
  end

  # §2's order, written down once and run in it.
  defp passes do
    [
      &pass_required/5,
      &pass_non_empty/5,
      &pass_key_bytes/5,
      &pass_enum/5,
      &pass_pattern/5,
      &pass_bounds/5,
      &pass_derives/5,
      &pass_matches_signer/5,
      &pass_ordered/5,
      &pass_exactly_one/5,
      &pass_at_most_one/5,
      &pass_requires/5
    ]
  end

  defp pass_required(_schema, _instance, levels, _sites, _context) do
    reduce_ok(levels, fn {level, value, path} ->
      check_required(level["required"], value, path)
    end)
  end

  defp pass_non_empty(schema, instance, _levels, _sites, _context),
    do: check_non_empty(schema["nonEmpty"], instance, "")

  defp pass_key_bytes(_schema, _instance, _levels, sites, _context) do
    reduce_ok(sites, fn {decl, value, path, _parent} ->
      if decl["keyBytes"] == true, do: check_key_bytes(value, path), else: :ok
    end)
  end

  defp pass_enum(_schema, _instance, _levels, sites, _context) do
    reduce_ok(sites, fn {decl, value, path, _parent} ->
      check_enum(decl["enum"], value, path)
    end)
  end

  defp pass_pattern(_schema, _instance, _levels, sites, _context) do
    reduce_ok(sites, fn {decl, value, path, _parent} ->
      check_pattern(decl["pattern"], value, path)
    end)
  end

  defp pass_bounds(_schema, _instance, _levels, sites, _context) do
    reduce_ok(sites, fn {decl, value, path, _parent} -> check_bounds(decl, value, path) end)
  end

  defp pass_derives(_schema, _instance, _levels, sites, _context) do
    reduce_ok(sites, fn {decl, value, path, parent} ->
      check_derives(decl["derives"], value, path, parent)
    end)
  end

  defp pass_matches_signer(_schema, _instance, _levels, sites, context) do
    reduce_ok(sites, fn {decl, value, path, _parent} ->
      check_matches_signer(decl["matchesSigner"], value, path, context[:signers])
    end)
  end

  defp pass_ordered(schema, instance, _levels, _sites, _context),
    do: check_ordered(schema["ordered"], instance, "")

  defp pass_exactly_one(schema, instance, _levels, _sites, _context),
    do: check_exactly_one(schema["exactlyOne"], instance, "")

  defp pass_at_most_one(schema, instance, _levels, _sites, _context),
    do: check_at_most_one(schema["atMostOne"], instance, "")

  defp pass_requires(schema, instance, _levels, _sites, context),
    do: check_requires(schema["requires"], instance, "", context)

  # -- the two walks -----------------------------------------------------
  #
  # `sites/2` is every declared property site in the instance, with the
  # object it sits in — `derives` names a sibling, so a site without its
  # parent could not answer. `levels/2` is the schema plus every nested
  # object level, which is where `required` nests to.
  #
  # Both are sorted by key at every level, so the order a denial is
  # chosen in is the instance's shape and never a map's iteration order.

  defp sites(schema, instance), do: descend(schema, instance, "")

  defp levels(schema, instance) do
    [{schema, instance, ""}] ++
      for {decl, value, path, _parent} <- sites(schema, instance),
          is_map(value),
          object_level?(decl),
          do: {decl, value, path}
  end

  defp object_level?(decl),
    do:
      Map.has_key?(decl, "properties") or Map.has_key?(decl, "values") or
        Map.has_key?(decl, "required")

  defp descend(level, value, path) when is_map(value) do
    props = level["properties"] || %{}
    values = level["values"]

    value
    |> Enum.sort_by(fn {key, _} -> key end)
    |> Enum.flat_map(fn {key, sub} ->
      here = "#{path}/#{key}"

      # An explicit null is not-exists (§0), and not constrained.
      if sub == nil do
        []
      else
        for decl <- [Map.get(props, key), values], decl != nil do
          [{decl, sub, here, value} | descend_child(decl, sub, here)]
        end
        |> List.flatten()
      end
    end)
  end

  defp descend(_level, _value, _path), do: []

  defp descend_child(decl, value, path) when is_map(value) do
    if object_level?(decl), do: descend(decl, value, path), else: []
  end

  defp descend_child(decl, value, path) when is_list(value) do
    case Map.fetch(decl, "items") do
      {:ok, items} ->
        value
        |> Enum.with_index()
        |> Enum.flat_map(fn
          {nil, _index} ->
            []

          {sub, index} ->
            [
              {items, sub, "#{path}/#{index}", value}
              | descend_child(items, sub, "#{path}/#{index}")
            ]
        end)

      :error ->
        []
    end
  end

  defp descend_child(_decl, _value, _path), do: []

  # -- one keyword at a time ---------------------------------------------

  defp check_required(nil, _value, _path), do: :ok

  defp check_required(fields, value, path) do
    case Enum.find(fields, &(not Kind.exists?(value, &1))) do
      nil -> :ok
      f -> {:error, "#{at(path)}: required field #{inspect(f)} does not exist"}
    end
  end

  defp check_non_empty(fields, value, path) when is_list(fields) do
    empty? = fn f -> Kind.exists?(value, f) and not Kind.non_empty?(Map.get(value, f)) end

    case Enum.find(fields, empty?) do
      nil -> :ok
      f -> {:error, "#{at(path)}: field #{inspect(f)} is declared nonEmpty but is empty"}
    end
  end

  defp check_non_empty(_, _value, _path), do: :ok

  # KS-3: the declaration fixed the shape, so what is left is that the
  # algorithm is one this kernel holds and the bytes are a key of the
  # length that algorithm's registry entry states.
  defp check_key_bytes(%{"algorithm" => algorithm, "bytes" => bytes}, path)
       when is_binary(bytes) do
    case RecurseVerify.DSSE.algorithm(algorithm) do
      {:ok, %{public_key_bytes: size}} ->
        case RecurseVerify.DSSE.decode64(bytes) do
          {:ok, decoded} when byte_size(decoded) == size ->
            :ok

          {:ok, decoded} ->
            {:error,
             "#{at(path)}: keyBytes: an #{algorithm} public key is #{size} bytes, " <>
               "got #{byte_size(decoded)}"}

          :error ->
            {:error, "#{at(path)}: keyBytes: bytes must be canonical padded base64"}
        end

      :error ->
        {:error,
         "#{at(path)}: keyBytes: #{inspect(algorithm)} is not in the §0 algorithm registry"}
    end
  end

  defp check_key_bytes(_value, path),
    do: {:error, "#{at(path)}: keyBytes: expected {algorithm, bytes} with a string bytes"}

  # KS-3: the value is the key id of a sibling `keyBytes` property, so a
  # subject and the key material it names cannot drift apart on the record.
  defp check_derives(nil, _value, _path, _parent), do: :ok

  defp check_derives(%{"keyIdOf" => field}, value, path, parent) do
    case parent[field] do
      %{"algorithm" => algorithm, "bytes" => bytes} when is_binary(bytes) ->
        with {:ok, decoded} <- RecurseVerify.DSSE.decode64(bytes),
             {:ok, derived} <- RecurseVerify.DSSE.key_id(algorithm, decoded) do
          if value == derived do
            :ok
          else
            {:error,
             "#{at(path)}: derives: must be the key id of #{inspect(field)} (#{derived}), " <>
               "got #{inspect(value)}"}
          end
        else
          _ ->
            {:error, "#{at(path)}: derives: #{inspect(field)} does not carry usable key material"}
        end

      _ ->
        {:error, "#{at(path)}: derives: #{inspect(field)} does not exist"}
    end
  end

  # KS-3: the value equals signer N's keyid — 1-based, as everywhere in
  # the contract. With no signers in context the keyword is not asked.
  defp check_matches_signer(nil, _value, _path, _signers), do: :ok
  defp check_matches_signer(_n, _value, _path, nil), do: :ok

  defp check_matches_signer(n, value, path, signers) do
    case Enum.at(signers, n - 1) do
      ^value ->
        :ok

      nil ->
        {:error, "#{at(path)}: matchesSigner: this envelope carries no signer #{n}"}

      keyid ->
        {:error,
         "#{at(path)}: matchesSigner: must equal signer #{n} (#{keyid}), got #{inspect(value)}"}
    end
  end

  defp check_exactly_one(groups, value, path) when is_list(groups) do
    Enum.reduce_while(groups, :ok, fn group, _ ->
      case Enum.count(group, &Kind.exists?(value, &1)) do
        1 ->
          {:cont, :ok}

        n ->
          {:halt, {:error, "#{at(path)}: exactly one of #{inspect(group)} must exist, #{n} do"}}
      end
    end)
  end

  defp check_exactly_one(_, _value, _path), do: :ok

  # §3/KS-3: at most one member of each group exists. Zero is fine —
  # that is the difference from `exactlyOne`, and it is the shape a Kind
  # needs when two fields are alternatives and neither is required.
  defp check_at_most_one(groups, value, path) when is_list(groups) do
    Enum.reduce_while(groups, :ok, fn group, _ ->
      case Enum.count(group, &Kind.exists?(value, &1)) do
        n when n <= 1 ->
          {:cont, :ok}

        n ->
          {:halt,
           {:error, "#{at(path)}: atMostOne: at most one of #{inspect(group)} may exist, #{n} do"}}
      end
    end)
  end

  defp check_at_most_one(_, _value, _path), do: :ok

  # §3/KS-3: each pair is `a` before `b`, compared as §0 instants after
  # normalization — so `Z` and `+00:00` are the same moment and are
  # **denied as equal**, because `ordered` is strict. Either side missing
  # or null is vacuous: `ordered` orders two instants and says nothing
  # about one.
  defp check_ordered(pairs, value, path) when is_list(pairs) do
    Enum.reduce_while(pairs, :ok, fn [a, b], _ ->
      cond do
        not Kind.exists?(value, a) or not Kind.exists?(value, b) ->
          {:cont, :ok}

        true ->
          case RecurseVerify.Instant.compare(Map.get(value, a), Map.get(value, b)) do
            {:ok, :lt} -> {:cont, :ok}
            {:ok, _} -> {:halt, {:error, "#{at(path)}: ordered: #{a} must be before #{b}"}}
            {:error, :left} -> {:halt, {:error, "#{at(path)}: ordered: unparseable #{a}"}}
            {:error, :right} -> {:halt, {:error, "#{at(path)}: ordered: unparseable #{b}"}}
          end
      end
    end)
  end

  defp check_ordered(_, _value, _path), do: :ok

  defp check_requires(rules, value, path, context) when is_list(rules) do
    Enum.reduce_while(rules, :ok, fn %{"when" => cond_, "then" => then_}, _ ->
      if condition_holds?(cond_, value, context) do
        case unmet(then_, value) do
          nil ->
            {:cont, :ok}

          missing ->
            {:halt,
             {:error,
              "#{at(path)}: #{describe_condition(cond_)} requires #{inspect(missing)}, which does not exist"}}
        end
      else
        {:cont, :ok}
      end
    end)
  end

  defp check_requires(_, _value, _path, _context), do: :ok

  # A `then` entry is a field, or a **group** — at least one of which
  # must exist. The unmet entry is reported as written, so a denial names
  # the group rather than an arbitrary member of it.
  defp unmet(then_, value) do
    Enum.find(then_, fn
      group when is_list(group) -> not Enum.any?(group, &Kind.exists?(value, &1))
      field -> not Kind.exists?(value, field)
    end)
  end

  defp condition_holds?(%{"field" => f, "equals" => v}, obj, _context),
    do: Kind.exists?(obj, f) and Map.get(obj, f) == v

  defp condition_holds?(%{"present" => f}, obj, _context) when is_binary(f),
    do: Kind.exists?(obj, f)

  # §3/KS-3: the envelope condition reads the *act*, not the document.
  # With no authority in context the condition is not asked — a caller
  # validating a spec on its own is making no claim about what authority
  # was exercised.
  defp condition_holds?(%{"envelope" => "authority", "present" => present}, _obj, context) do
    case context[:authority] do
      nil -> false
      authority -> authority != [] == present
    end
  end

  defp condition_holds?(_, _, _), do: false

  defp describe_condition(%{"field" => f, "equals" => v}), do: "#{f} == #{inspect(v)}"
  defp describe_condition(%{"present" => f}) when is_binary(f), do: "#{f} present"

  defp describe_condition(%{"envelope" => "authority", "present" => true}),
    do: "an act exercising authority"

  defp describe_condition(%{"envelope" => "authority", "present" => false}),
    do: "an act exercising no authority"

  defp describe_condition(other), do: inspect(other)

  defp check_enum(nil, _value, _path), do: :ok

  defp check_enum(enum, value, path) do
    if value in enum,
      do: :ok,
      else: {:error, "#{at(path)}: #{inspect(value)} is not one of #{inspect(enum)}"}
  end

  # On a non-string value, `pattern` is a no-op (§3).
  defp check_pattern(nil, _value, _path), do: :ok

  defp check_pattern(pattern, value, path) when is_binary(value) do
    case Kind.compile_pattern(pattern) do
      {:ok, re} ->
        if :re.run(value, re, [{:capture, :none}]) == :match,
          do: :ok,
          else:
            {:error, "#{at(path)}: #{inspect(value)} does not match pattern #{inspect(pattern)}"}

      {:error, reason} ->
        {:error, "#{at(path)}: pattern #{reason}"}
    end
  end

  defp check_pattern(_pattern, _value, _path), do: :ok

  defp check_bounds(prop, value, path) when is_integer(value) do
    cond do
      is_integer(prop["minimum"]) and value < prop["minimum"] ->
        {:error, "#{at(path)}: #{value} is below minimum #{prop["minimum"]}"}

      is_integer(prop["maximum"]) and value > prop["maximum"] ->
        {:error, "#{at(path)}: #{value} is above maximum #{prop["maximum"]}"}

      true ->
        :ok
    end
  end

  defp check_bounds(_prop, _value, _path), do: :ok

  # -- shared ------------------------------------------------------------

  defp types(%{"type" => t}) when is_binary(t), do: [t]
  defp types(%{"type" => t}) when is_list(t), do: t
  defp types(_), do: []

  defp type_match?("string", v), do: is_binary(v)
  defp type_match?("integer", v), do: is_integer(v)
  defp type_match?("boolean", v), do: is_boolean(v)
  defp type_match?("object", v), do: is_map(v)
  defp type_match?("array", v), do: is_list(v)
  defp type_match?("ref", _v), do: false
  # A type a v1 definition declared and v2 dropped (e.g. "number") is not
  # re-interpreted on replay: the legacy schema keeps its old permissiveness.
  defp type_match?(_unknown, _v), do: true

  defp at(""), do: "/"
  defp at(path), do: path

  defp reduce_ok(enum, fun) do
    Enum.reduce_while(enum, :ok, fn item, _ ->
      case fun.(item) do
        :ok -> {:cont, :ok}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp indexed_ok(list, fun) do
    list
    |> Enum.with_index()
    |> reduce_ok(fn {v, i} -> fun.(v, i) end)
  end
end
