defmodule R5e.Kind.Naming do
  @moduledoc """
  §2: who names an instance, and what a legal name is.

  The table of six modes — `content`, `path`, `literal`, `derived`,
  `server`, `caller` — and their create/readmit rules is spec/05 §2, and
  `R5e.Admission` is where it is applied. What lives here is the part a
  *definition* declares and the kernel can check without a request:

    * the shape of the `naming` block, per mode (`parse/2`, `check/2`);
    * the legal-name rule (`valid_name?/1`);
    * the `derived` template — literal text plus `{field}` of declared
      top-level *string* properties, `{{`/`}}` for a brace, no operators
      and no escapes (`parse_template/1`, `render_derived/2`). Rendering
      must be total, which is why the fields have to be declared strings:
      a union type could yield a non-string at render time.
  """

  @modes ~w(content path literal derived server caller)
  @keys ~w(mode value derive admitBy readmitBy)
  @readmit ~w(actorOfRecord actorOfRecordOrSuccessor nodeKey none)

  # §2/KS-4: a `content`-named instance's name **is** its spec, so a
  # re-admission of the same name is the same document and there is
  # nothing for a readmit rule to gate; a `path`-named one is settled by
  # §1's duplicate rule and the §11 transition. Declaring `readmitBy` on
  # either would be a keyword that never runs.
  @no_readmit ~w(content path)

  # Rendered names, §2. `*` is legal so the fallback shape `cedar.*` can be
  # named; `/` separates segments, so a name may itself look like an API path.
  @name_re ~r{\A[A-Za-z0-9._:@*\-]+(?:/[A-Za-z0-9._:@*\-]+)*\z}

  @doc "The six naming modes of §2."
  @spec modes() :: [String.t()]
  def modes, do: @modes

  @doc """
  Read a definition's `naming` block: `{:ok, naming, legacy?}`.

  `replay?` is the §11 concession and the only way `legacy?` is true: a
  definition recorded before schema-lite v2 has no `naming` and is loaded
  as `%{"mode" => "caller"}` rather than denied.
  """
  @spec parse(term(), boolean()) :: {:ok, map(), boolean()} | {:error, String.t()}
  def parse(nil, true), do: {:ok, %{"mode" => "caller"}, true}

  def parse(nil, false),
    do: {:error, "naming is required (schema-lite v2 §2): one of #{Enum.join(@modes, "|")}"}

  def parse(naming, _replay?) when is_map(naming) do
    with :ok <- R5e.Kind.check_keywords(naming, @keys, "naming"),
         :ok <- check_mode(naming["mode"]),
         :ok <- check_payload(naming),
         :ok <- check_gates(naming) do
      {:ok, naming, false}
    end
  end

  def parse(other, _replay?),
    do: {:error, "naming must be a JSON object, got #{R5e.Kind.kindof(other)}"}

  @doc """
  The §1 meta-check on a submitted definition's `naming`: the block's own
  shape, and — under `derived` — that every `{field}` the template names is
  a declared top-level `string` property.
  """
  @spec check(term(), term()) :: :ok | {:error, String.t()}
  def check(naming, schema) do
    with {:ok, parsed, _legacy} <- parse(naming, false) do
      case parsed do
        %{"mode" => "derived", "derive" => template} -> check_template(template, schema)
        _ -> :ok
      end
    end
  end

  @doc """
  Is this a legal rendered name (§2)? Full match of
  `[A-Za-z0-9._:@*-]+(/[A-Za-z0-9._:@*-]+)*`, at most 255 bytes.
  """
  @spec valid_name?(term()) :: boolean()
  def valid_name?(name) when is_binary(name),
    do: byte_size(name) <= R5e.Kind.limit(:name) and Regex.match?(@name_re, name)

  def valid_name?(_), do: false

  @doc """
  Render a `derived` naming template against a spec. Literal text plus
  `{field}` of declared top-level string properties; `{{`/`}}` escape
  braces; no operators.
  """
  @spec render_derived(String.t(), map()) :: {:ok, String.t()} | {:error, String.t()}
  def render_derived(template, spec) do
    with {:ok, parts} <- parse_template(template) do
      Enum.reduce_while(parts, {:ok, ""}, fn
        {:lit, text}, {:ok, acc} ->
          {:cont, {:ok, acc <> text}}

        {:field, f}, {:ok, acc} ->
          case Map.get(spec, f) do
            v when is_binary(v) -> {:cont, {:ok, acc <> v}}
            nil -> {:halt, {:error, "template field #{inspect(f)} is absent from the spec"}}
            _ -> {:halt, {:error, "template field #{inspect(f)} is not a string"}}
          end
      end)
    end
  end

  @doc false
  @spec parse_template(term()) ::
          {:ok, [{:lit, String.t()} | {:field, String.t()}]} | {:error, String.t()}
  def parse_template(t) when is_binary(t), do: scan_template(t, [], "")
  def parse_template(_), do: {:error, "must be a string"}

  # -- the naming block --------------------------------------------------

  defp check_mode(mode) when mode in @modes, do: :ok

  defp check_mode(mode),
    do: {:error, "naming.mode must be one of #{Enum.join(@modes, "|")}, got #{inspect(mode)}"}

  defp check_payload(%{"mode" => "literal"} = naming) do
    cond do
      not is_binary(naming["value"]) ->
        {:error, "naming mode \"literal\" requires a string value"}

      not valid_name?(naming["value"]) ->
        {:error, "naming.value is not a legal name (§2)"}

      Map.has_key?(naming, "derive") ->
        {:error, "naming mode \"literal\" takes no derive"}

      true ->
        :ok
    end
  end

  defp check_payload(%{"mode" => "derived"} = naming) do
    cond do
      not is_binary(naming["derive"]) ->
        {:error, "naming mode \"derived\" requires a string derive template"}

      Map.has_key?(naming, "value") ->
        {:error, "naming mode \"derived\" takes no value"}

      true ->
        case parse_template(naming["derive"]) do
          {:ok, _} -> :ok
          {:error, reason} -> {:error, "naming.derive #{reason}"}
        end
    end
  end

  defp check_payload(%{"mode" => mode} = naming) do
    case Enum.find(~w(value derive), &Map.has_key?(naming, &1)) do
      nil -> :ok
      key -> {:error, "naming mode #{inspect(mode)} takes no #{key}"}
    end
  end

  defp check_payload(_), do: :ok

  @doc """
  §4/KS-4's two additions to the naming block, checked wherever the block
  is parsed: `admitBy: "nodeKey"` (only the node key may *create* an
  instance of this Kind) and `readmitBy`, which overrides the mode's
  readmit column.
  """
  @spec check_gates(map()) :: :ok | {:error, String.t()}
  def check_gates(naming) do
    with :ok <- check_admit_by(Map.fetch(naming, "admitBy")) do
      check_readmit_by(Map.fetch(naming, "readmitBy"), naming["mode"])
    end
  end

  defp check_admit_by(:error), do: :ok
  defp check_admit_by({:ok, "nodeKey"}), do: :ok

  defp check_admit_by({:ok, other}),
    do: {:error, "naming.admitBy takes only \"nodeKey\", got #{inspect(other)}"}

  defp check_readmit_by(:error, _mode), do: :ok

  defp check_readmit_by({:ok, value}, mode) do
    cond do
      value not in @readmit ->
        {:error,
         "naming.readmitBy must be one of #{Enum.join(@readmit, "|")}, got #{inspect(value)}"}

      mode in @no_readmit ->
        {:error, "naming.readmitBy is not admissible on naming mode #{inspect(mode)}"}

      true ->
        :ok
    end
  end

  @doc "The readmit rule this Kind declares, or `nil` — the mode's column then stands (§2)."
  @spec readmit_by(map() | nil) :: String.t() | nil
  def readmit_by(%{"readmitBy" => value}), do: value
  def readmit_by(_naming), do: nil

  @doc "Whether only the node key may create an instance of this Kind (§4)."
  @spec node_key_only?(map() | nil) :: boolean()
  def node_key_only?(%{"admitBy" => "nodeKey"}), do: true
  def node_key_only?(_naming), do: false

  defp check_template(template, schema) do
    {:ok, parts} = parse_template(template)
    props = (is_map(schema) && schema["properties"]) || %{}

    Enum.reduce_while(parts, :ok, fn
      {:lit, _}, _ ->
        {:cont, :ok}

      {:field, f}, _ ->
        case props[f] do
          %{"type" => "string"} ->
            {:cont, :ok}

          nil ->
            {:halt,
             {:error, "naming.derive names #{inspect(f)}, which is not a declared property"}}

          _ ->
            {:halt, {:error, "naming.derive names #{inspect(f)}, which is not a string property"}}
        end
    end)
  end

  # -- the template scanner ----------------------------------------------

  defp scan_template("", parts, lit), do: {:ok, flush(parts, lit)}
  defp scan_template("{{" <> rest, parts, lit), do: scan_template(rest, parts, lit <> "{")
  defp scan_template("}}" <> rest, parts, lit), do: scan_template(rest, parts, lit <> "}")

  defp scan_template("{" <> rest, parts, lit) do
    case String.split(rest, "}", parts: 2) do
      [field, tail] ->
        cond do
          field == "" -> {:error, "contains an empty {} placeholder"}
          String.contains?(field, "{") -> {:error, "contains a nested { in a placeholder"}
          true -> scan_template(tail, flush(parts, lit) ++ [{:field, field}], "")
        end

      _ ->
        {:error, "contains an unterminated {"}
    end
  end

  defp scan_template("}" <> _rest, _parts, _lit), do: {:error, "contains an unescaped }"}

  defp scan_template(<<c::utf8, rest::binary>>, parts, lit),
    do: scan_template(rest, parts, lit <> <<c::utf8>>)

  defp flush(parts, ""), do: parts
  defp flush(parts, lit), do: parts ++ [{:lit, lit}]
end
