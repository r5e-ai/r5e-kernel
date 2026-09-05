defmodule R5e.Kind do
  @moduledoc """
  A KindDefinition (core spec/02; spec/05 is the normative meta-schema):
  identity, substrate, **naming mode**, schema, epistemic scope, answerable
  predicates. KindDefinitions are themselves admitted instances — see
  `R5e.Bootstrap` for how the core Kinds enter through their own door.

  This module is the struct and the front door. The checks live in three
  modules, cut along the contract's own sections and delegated from here,
  so a caller never has to know which one answers:

    * `R5e.Kind.Naming` — §2's six modes, the legal-name rule and the
      `derived` template: `valid_name?/1`, `render_derived/2`.
    * `R5e.Kind.Definition` — §1's meta-checks on a *submitted*
      definition, over §3's schema grammar and §4's ref declarations:
      `check_definition/1`.
    * `R5e.Kind.Validate` — §0 and §3 applied to an *instance*, in the two
      halves the §4 pipeline runs either side of policy:
      `validate_structure/2`, `validate_constraints/2`.

  `from_map/2` parses a definition into the struct. Strict by default;
  `replay: true` loads one recorded *before* schema-lite v2 (no `naming`)
  as `%{"mode" => "caller"}` with `legacy: true`, so an existing log is
  never retroactively denied (§11).

  ## Regex dialect

  §3 asks for RE2 syntax, UTF-8, whole-string match. This kernel compiles
  patterns with Erlang `:re` — `:re.compile("\\\\A(?:" <> pattern <> ")\\\\z",
  [:unicode, :ucp])` — and runs them with `[{:capture, :none}]`. The
  wrapping is what makes the match *whole*: an anchored run alone would
  full-match only the first branch of an alternation. `\\\\A`/`\\\\z` are used
  rather than `^`/`$` so a trailing newline cannot pass.

  `:re` is PCRE, which accepts *more* than RE2. A pattern that only PCRE
  understands would mean two conformant kernels reading one Kind
  differently and neither saying so, which is why `re2_subset/1` refuses
  the five constructs RE2 does not have — backreferences, lookaround,
  atomic groups, possessive quantifiers, recursion — at KindDefinition
  admission (§1, amendment A11). It is a syntactic scan on those five, not
  a full RE2 parser, and the remaining gap is stated in its own doc. One
  honest cost stands: patterns are compiled per check rather than cached.
  """

  @enforce_keys [:group, :kind, :version, :substrate, :schema]
  defstruct [
    :group,
    :kind,
    :version,
    :substrate,
    :schema,
    :naming,
    :epistemic_scope,
    :description,
    :derived_from,
    :spec_address,
    predicates: [],
    signatures: 1,
    requires_authority: false,
    scope_defaulted: false,
    legacy: false
  ]

  @type t :: %__MODULE__{}

  @substrates ~w(resource event artifact)

  # §3's limits, kept together because §3 states them together and both
  # halves of the check read them: the declaration's property count and
  # pattern size at definition time, the instance's depth, array length,
  # property count and encoded size at admission, the name's at naming.
  @limits %{depth: 16, array: 4096, properties: 256, pattern: 1024, spec: 1_048_576, name: 255}

  # Spec/02: an omitted epistemic scope receives the modest default and is
  # labeled `scope: defaulted` wherever it is displayed.
  @default_scope %{
    "claims" => ["signed by author", "matches schema"],
    "doesNotClaim" => ["anything else"]
  }

  def substrates, do: @substrates

  @doc false
  @spec limit(atom()) :: non_neg_integer()
  def limit(which), do: Map.fetch!(@limits, which)

  # -- the delegated checks ----------------------------------------------

  @doc "§2: the six naming modes."
  defdelegate naming_modes(), to: R5e.Kind.Naming, as: :modes

  @doc "§2: is this a legal rendered name? See `R5e.Kind.Naming.valid_name?/1`."
  defdelegate valid_name?(name), to: R5e.Kind.Naming

  @doc "§2: render a `derived` naming template. See `R5e.Kind.Naming.render_derived/2`."
  defdelegate render_derived(template, spec), to: R5e.Kind.Naming

  @doc false
  defdelegate parse_template(template), to: R5e.Kind.Naming

  @doc "§1: the meta-checks on a submitted definition. See `R5e.Kind.Definition`."
  defdelegate check_definition(spec), to: R5e.Kind.Definition, as: :check

  @doc "§3: the structural half of instance validation. See `R5e.Kind.Validate`."
  defdelegate validate_structure(kind, instance), to: R5e.Kind.Validate, as: :structure

  @doc "§3: the constraint half of instance validation. See `R5e.Kind.Validate`."
  defdelegate validate_constraints(kind, instance), to: R5e.Kind.Validate, as: :constraints

  @doc "The constraint half, with `context` for the keywords that need one (§2)."
  defdelegate validate_constraints(kind, instance, context),
    to: R5e.Kind.Validate,
    as: :constraints

  # -- parsing -----------------------------------------------------------

  @doc """
  Build a Kind from a decoded JSON map, applying scope defaulting.

  Strict by default: `naming` is required, and a malformed `naming` or
  `epistemicScope` is an error rather than a silent default. Pass
  `replay: true` for definitions read back off the log: one recorded
  before schema-lite v2 has no `naming`, and is loaded as
  `%{"mode" => "caller"}` with `legacy: true` — the v1 kernel's behaviour,
  named as such, never denied.
  """
  @spec from_map(map(), keyword()) :: {:ok, t()} | {:error, String.t()}
  def from_map(map, opts \\ [])

  def from_map(map, opts) when is_map(map) do
    replay? = Keyword.get(opts, :replay, false)

    with :ok <- require_strings(map, ~w(group kind version substrate)),
         :ok <- check_substrate(map["substrate"]),
         :ok <- check_schema_is_object(map["schema"]),
         :ok <- check_description(map["description"]),
         {:ok, scope, defaulted} <- scope_or_default(map["epistemicScope"]),
         {:ok, signatures} <- check_signatures(map["signatures"]),
         {:ok, requires_authority} <- check_requires_authority(map["requiresAuthority"]),
         {:ok, naming, legacy} <- R5e.Kind.Naming.parse(map["naming"], replay?) do
      {:ok,
       %__MODULE__{
         group: map["group"],
         kind: map["kind"],
         version: map["version"],
         substrate: map["substrate"],
         schema: map["schema"],
         naming: naming,
         epistemic_scope: scope,
         description: map["description"],
         derived_from: nil,
         spec_address: R5e.CAS.spec_address(map),
         predicates: map["predicates"] || [],
         signatures: signatures,
         requires_authority: requires_authority,
         scope_defaulted: defaulted,
         legacy: legacy
       }}
    end
  end

  def from_map(_, _), do: {:error, "KindDefinition must be a JSON object"}

  @doc "Load a KindDefinition from a JSON file."
  @spec load_file(Path.t()) :: {:ok, t()} | {:error, String.t()}
  def load_file(path) do
    with {:ok, bytes} <- File.read(path),
         {:ok, map} <- Jason.decode(bytes) do
      from_map(map)
    else
      {:error, reason} -> {:error, "#{path}: #{inspect(reason)}"}
    end
  end

  @doc """
  §4/KS-4: how many signatures an admission of this Kind carries — 1 by
  default, 2 for a countersigned act. Anything else is refused at
  KindDefinition admission, because a Kind that asked for three would be
  asking for something the envelope cannot express (§1: one or two).
  """
  @spec check_signatures(term()) :: {:ok, 1 | 2} | {:error, String.t()}
  def check_signatures(nil), do: {:ok, 1}
  def check_signatures(n) when n in [1, 2], do: {:ok, n}

  def check_signatures(other),
    do: {:error, "signatures must be 1 or 2, got #{inspect(other)}"}

  @doc """
  §4/KS-4: `requiresAuthority: true` means every admission of this Kind
  carries non-empty `authority`. Only `true` is admissible — a `false`
  would be a declaration that says nothing, and §1 admits no keyword whose
  presence changes nothing.
  """
  @spec check_requires_authority(term()) :: {:ok, boolean()} | {:error, String.t()}
  def check_requires_authority(nil), do: {:ok, false}
  def check_requires_authority(true), do: {:ok, true}

  def check_requires_authority(other),
    do: {:error, "requiresAuthority must be true when present, got #{inspect(other)}"}

  @doc "Instance name of a KindDefinition: the API path of the Kind it defines."
  @spec name(t()) :: String.t()
  def name(%__MODULE__{} = k), do: "#{k.group}/#{k.version}/#{k.kind}"

  @doc "The Kind's naming mode (§2)."
  @spec naming_mode(t()) :: String.t()
  def naming_mode(%__MODULE__{naming: %{"mode" => mode}}), do: mode
  def naming_mode(%__MODULE__{}), do: "caller"

  @doc """
  Serialize back to the admitted JSON shape (plus the defaulted flag).

  `naming`, `description` and `derivedFrom` appear only for definitions
  that have them: a legacy definition (admitted before schema-lite v2,
  carrying no `naming` of its own) serializes exactly as it did under v1,
  so an export of an existing log is unchanged. This map is both
  `GET /apis` and the export's `kinds/*.json`.
  """
  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = k) do
    %{
      "group" => k.group,
      "kind" => k.kind,
      "version" => k.version,
      "substrate" => k.substrate,
      "schema" => k.schema,
      "epistemicScope" => k.epistemic_scope,
      "predicates" => k.predicates,
      "scopeDefaulted" => k.scope_defaulted
    }
    |> put_if(k.signatures != 1, "signatures", k.signatures)
    |> put_if(k.requires_authority, "requiresAuthority", true)
    |> put_if(k.naming != nil and not k.legacy, "naming", k.naming)
    |> put_if(k.description != nil, "description", k.description)
    |> put_if(k.derived_from != nil, "derivedFrom", k.derived_from)
  end

  # -- §0 predicates -----------------------------------------------------

  @doc """
  §0 `exists`: an own key whose value is not null. An explicit `null` on a
  declared property is not-exists — it fails `required`, does not count for
  `exactlyOne`/`present`, and is not type-checked.
  """
  @spec exists?(term(), String.t()) :: boolean()
  def exists?(obj, field) when is_map(obj),
    do: Map.has_key?(obj, field) and Map.get(obj, field) != nil

  def exists?(_, _), do: false

  @doc "§0 `nonEmpty`: not `\"\"`, not `{}`, not `[]`; null is never nonEmpty."
  @spec non_empty?(term()) :: boolean()
  def non_empty?(nil), do: false
  def non_empty?(""), do: false
  def non_empty?([]), do: false
  def non_empty?(v) when is_map(v) and map_size(v) == 0, do: false
  def non_empty?(_), do: true

  # -- regex (§3) --------------------------------------------------------

  @doc """
  Compile a schema `pattern` for whole-string matching. See the moduledoc
  for the dialect: `:re` under `[:unicode, :ucp]`, wrapped `\\A(?:…)\\z`.
  """
  @spec compile_pattern(term()) :: {:ok, term()} | {:error, String.t()}
  def compile_pattern(pattern) when is_binary(pattern) do
    case :re.compile("\\A(?:" <> pattern <> ")\\z", [:unicode, :ucp]) do
      {:ok, re} -> {:ok, re}
      {:error, {reason, at}} -> {:error, "does not compile: #{reason} at offset #{at}"}
      {:error, reason} -> {:error, "does not compile: #{inspect(reason)}"}
    end
  end

  def compile_pattern(_), do: {:error, "must be a string"}

  @doc """
  Refuse the PCRE constructs that are outside RE2 (§1, amendment A11).

  A pattern using a backreference, lookaround, an atomic group, a
  possessive quantifier or recursion compiles under `:re` and would be
  *rejected* by a true RE2 engine — so admitting one would mean two
  conformant kernels disagreeing about what the same KindDefinition means,
  silently. The subset is enforced at KindDefinition admission instead,
  where the disagreement is a denial with a reason rather than a
  divergence with none.

  The scan tracks backslash escapes and character classes, so `\\+` and
  `[+*]` are ordinary text and only real constructs are refused. It is a
  syntactic check on the five named constructs, not a full RE2 parser: a
  pattern it accepts is not thereby proven RE2-clean, and that gap is
  stated rather than papered over.
  """
  @spec re2_subset(String.t()) :: :ok | {:error, String.t()}
  def re2_subset(pattern) when is_binary(pattern),
    do: scan_re2(pattern, %{escaped: false, class: false, prev: nil})

  defp scan_re2("", _state), do: :ok

  defp scan_re2(<<"\\", rest::binary>>, %{escaped: false} = state) do
    case rest do
      <<d, _::binary>> when d in ?1..?9 and not state.class ->
        outside_re2("a backreference (\\#{<<d>>})")

      <<"k", _::binary>> when not state.class ->
        outside_re2("a named backreference (\\k)")

      <<"g", _::binary>> when not state.class ->
        outside_re2("a subroutine or backreference call (\\g)")

      _ ->
        scan_re2(rest, %{state | escaped: true, prev: nil})
    end
  end

  # The character after a backslash is literal, whatever it is.
  defp scan_re2(<<_::utf8, rest::binary>>, %{escaped: true} = state),
    do: scan_re2(rest, %{state | escaped: false, prev: :literal})

  defp scan_re2(<<"[", rest::binary>>, %{class: false} = state),
    do: scan_re2(rest, %{state | class: true, prev: :literal})

  defp scan_re2(<<"]", rest::binary>>, %{class: true} = state),
    do: scan_re2(rest, %{state | class: false, prev: :atom})

  # Inside a class nothing below is a construct.
  defp scan_re2(<<_::utf8, rest::binary>>, %{class: true} = state),
    do: scan_re2(rest, state)

  defp scan_re2(<<"(?", rest::binary>>, state) do
    cond do
      String.starts_with?(rest, ["=", "!"]) ->
        outside_re2("lookahead ((?= or (?!)")

      String.starts_with?(rest, ["<=", "<!"]) ->
        outside_re2("lookbehind ((?<= or (?<!)")

      String.starts_with?(rest, ">") ->
        outside_re2("an atomic group ((?>)")

      String.starts_with?(rest, ["R)", "&", "P>", "0)"]) or recursive_call?(rest) ->
        outside_re2("recursion ((?R), (?N) or (?&name))")

      true ->
        scan_re2(rest, %{state | prev: nil})
    end
  end

  defp scan_re2(<<"+", _rest::binary>>, %{prev: :quantifier}),
    do: outside_re2("a possessive quantifier")

  defp scan_re2(<<c::utf8, rest::binary>>, state) do
    prev = if c in [?*, ?+, ??, ?}], do: :quantifier, else: :atom
    scan_re2(rest, %{state | prev: prev})
  end

  # `(?1)`, `(?-1)`, `(?+1)` — a recursive subpattern call.
  defp recursive_call?(rest), do: Regex.match?(~r/\A[+-]?[0-9]+\)/, rest)

  defp outside_re2(construct),
    do: {:error, "uses #{construct}, which is outside the RE2 subset (§1)"}

  # -- vocabulary shared with the three check modules --------------------

  @doc false
  @spec kindof(term()) :: String.t()
  def kindof(v) when is_binary(v), do: "string"
  def kindof(v) when is_boolean(v), do: "boolean"
  def kindof(v) when is_integer(v), do: "integer"
  def kindof(v) when is_float(v), do: "float"
  def kindof(v) when is_map(v), do: "object"
  def kindof(v) when is_list(v), do: "array"
  def kindof(nil), do: "null"
  def kindof(_), do: "value"

  @doc false
  @spec check_keywords(map(), [String.t()], String.t()) :: :ok | {:error, String.t()}
  def check_keywords(map, allowed, where) do
    case Enum.find(Map.keys(map), &(&1 not in allowed)) do
      nil -> :ok
      key -> {:error, "undeclared #{where} keyword #{inspect(key)}"}
    end
  end

  @doc false
  @spec require_strings(map(), [String.t()]) :: :ok | {:error, String.t()}
  def require_strings(map, fields) do
    case Enum.find(fields, fn f -> not is_binary(map[f]) or map[f] == "" end) do
      nil -> :ok
      field -> {:error, "KindDefinition field #{inspect(field)} must be a non-empty string"}
    end
  end

  @doc false
  def check_substrate(s) when s in @substrates, do: :ok

  def check_substrate(s),
    do: {:error, "substrate must be one of #{Enum.join(@substrates, "|")}, got #{inspect(s)}"}

  @doc false
  def check_description(nil), do: :ok
  def check_description(d) when is_binary(d), do: :ok

  def check_description(other),
    do: {:error, "description must be a string, got #{kindof(other)}"}

  @doc false
  # §1: absent → the modest default, flagged. Present but not that shape →
  # denied, rather than silently defaulted over.
  def scope_or_default(nil), do: {:ok, @default_scope, true}

  def scope_or_default(%{"claims" => claims, "doesNotClaim" => does_not} = scope)
      when is_list(claims) and is_list(does_not) do
    cond do
      map_size(scope) != 2 ->
        {:error, "epistemicScope takes exactly claims and doesNotClaim"}

      not Enum.all?(claims ++ does_not, &is_binary/1) ->
        {:error, "epistemicScope claims and doesNotClaim must be arrays of strings"}

      true ->
        {:ok, %{"claims" => claims, "doesNotClaim" => does_not}, false}
    end
  end

  def scope_or_default(_malformed),
    do: {:error, "epistemicScope must be {claims: [string...], doesNotClaim: [string...]}"}

  defp check_schema_is_object(schema) when is_map(schema), do: :ok
  defp check_schema_is_object(_), do: {:error, "schema must be a JSON object"}

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map
end
