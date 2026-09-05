defmodule R5e.Cedar do
  @moduledoc """
  Cedar operations provided by the kernel's pinned Rust NIF.

  Evaluation accepts the policy source, the exact Cedar request JSON and
  the exact Cedar entity JSON. The caller can therefore record those bytes
  beside the decision and replay the same question later.
  """

  alias R5e.Cedar.Nif

  @spec canonical_hash(binary()) :: {:ok, binary()} | {:error, binary()}
  def canonical_hash(source) when is_binary(source), do: Nif.canonical_hash(source)

  @spec validate_policy_syntax(binary()) :: :ok | {:error, binary()}
  def validate_policy_syntax(source) when is_binary(source) do
    case Nif.validate_policy_syntax(source) do
      :ok -> :ok
      {:ok, _unit} -> :ok
      {:error, _reason} = error -> error
    end
  end

  @spec evaluate(binary(), binary(), binary()) ::
          {:ok, %{decision: :allow | :deny, matched_policies: [String.t()]}}
          | {:error, binary()}
  def evaluate(source, request_json, entities_json)
      when is_binary(source) and is_binary(request_json) and is_binary(entities_json) do
    with {:ok, json} <- Nif.evaluate_with_entities(source, request_json, entities_json),
         {:ok, value} <- Jason.decode(json) do
      decode(value)
    else
      {:error, reason} -> {:error, to_string(reason)}
    end
  end

  defp decode(%{"decision" => "allow", "matched_policies" => matched}) when is_list(matched),
    do: {:ok, %{decision: :allow, matched_policies: Enum.sort(matched)}}

  defp decode(%{"decision" => "deny", "matched_policies" => matched}) when is_list(matched),
    do: {:ok, %{decision: :deny, matched_policies: Enum.sort(matched)}}

  defp decode(other), do: {:error, "unexpected Cedar response: #{inspect(other, limit: 5)}"}
end
