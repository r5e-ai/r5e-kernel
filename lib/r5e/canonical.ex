defmodule R5e.Canonical do
  @moduledoc """
  Kernel-side alias for `RecurseVerify.Canonical` — the canonical JSON
  encoding lives in the standalone verifier package (r5e-core/verifier,
  Apache Tier 1) so that writer and checker share one implementation by
  construction. See that module for the encoding rules.
  """

  defdelegate encode(term), to: RecurseVerify.Canonical
  defdelegate hash(term), to: RecurseVerify.Canonical
  defdelegate hash_bytes(bytes), to: RecurseVerify.Canonical

  @doc "Canonicalize raw JSON bytes (contract §8's input half)."
  defdelegate encode_json(bytes), to: RecurseVerify.Canonical

  @doc "Parse raw JSON bytes under §8's input rules."
  defdelegate decode_json(bytes), to: RecurseVerify.Canonical
end
