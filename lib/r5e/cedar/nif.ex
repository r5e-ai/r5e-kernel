defmodule R5e.Cedar.Nif do
  @moduledoc false

  use Rustler,
    otp_app: :r5e,
    crate: :r5e_cedar,
    path: "native/r5e_cedar"

  def canonical_hash(_source), do: :erlang.nif_error(:nif_not_loaded)
  def validate_policy_syntax(_source), do: :erlang.nif_error(:nif_not_loaded)

  def evaluate_with_entities(_source, _request_json, _entities_json),
    do: :erlang.nif_error(:nif_not_loaded)
end
