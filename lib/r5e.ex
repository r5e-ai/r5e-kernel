defmodule R5e do
  @moduledoc """
  The r5e protocol kernel — first working slice.

  Everything enters through one gate (`R5e.Admission`) and lands on one of
  three substrates (spec/01): the resource graph (`R5e.ResourceStore`), the
  hash-chained, Merkle-anchored event log (`R5e.Log` / `R5e.Chain`), and
  the content-addressed store (`R5e.CAS`). Vocabulary is extended by
  admitting `R5e.Kind` definitions — including the core's own, at
  bootstrap, through the same door (`R5e.Bootstrap`).

  Receipts are checked offline by the standalone `recurse_verify` project
  (r5e-core/verifier; `mix r5e.verify` here is a thin delegate), whose
  output states what was checked and what was not — never a bare "valid".

  The chain records claims, attestations and receipts; it never records
  truth. Validity is established here; soundness bottoms out at anchors
  outside the system.
  """
end
