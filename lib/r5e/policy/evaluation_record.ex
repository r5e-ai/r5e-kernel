defmodule R5e.Policy.EvaluationRecord do
  @moduledoc """
  The canonical record of one Cedar question and answer.

  These bytes are kernel-derived during the admission they describe. The
  enclosing event cites the resulting address through `derivedObjects`, so
  replay and export retain the classification without inventing a recursive
  admission for the evaluation itself.
  """

  @format "r5e.policy-evaluation/1"

  @spec fetch(String.t()) :: {:ok, map()} | {:error, term()}
  def fetch(address) when is_binary(address) do
    with {:ok, bytes} <- R5e.CAS.get(address),
         {:ok, %{"format" => @format} = record} <- R5e.Canonical.decode_json(bytes) do
      {:ok, record}
    else
      {:ok, _other} -> {:error, :invalid_evaluation_record}
      error -> error
    end
  end

  @spec write(map()) :: String.t()
  def write(fields) do
    bytes = fields |> build() |> R5e.Canonical.encode()
    address = "bytes:" <> R5e.CAS.put(bytes)
    :ok = R5e.RefIndex.register_derived(address)
    address
  end

  @spec build(map()) :: map()
  def build(fields) do
    %{
      "format" => @format,
      "engine" => fields.engine,
      "engineBuild" => fields.engine_build,
      "kindDefinition" => fields.kind_definition,
      "bundle" => fields.bundle,
      "source" => fields.source,
      "shape" => nil,
      "requestBytes" => Base.encode64(fields.request_bytes),
      "entitiesBytes" => Base.encode64(fields.entities_bytes),
      "resolution" => Enum.sort_by(fields.resolution, & &1["path"]),
      "decision" => fields.decision,
      "matched" => Enum.sort(fields.matched),
      "resolvedAuthority" => Map.get(fields, :resolved_authority, [])
    }
  end
end
