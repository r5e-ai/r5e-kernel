defmodule R5e.Chain do
  @moduledoc """
  Write side of the hash-chained event log (spec/01 §2): building the
  next event. Verification (hash recompute, link and seq checks, log
  parsing) lives in `RecurseVerify.Chain` — the standalone verifier
  package — and is delegated, so the writer and the checker share one
  implementation by construction.
  """

  defdelegate genesis, to: RecurseVerify.Chain
  defdelegate recompute_hash(event), to: RecurseVerify.Chain
  defdelegate verify_events(events), to: RecurseVerify.Chain
  defdelegate read_log(path), to: RecurseVerify.Chain

  @doc """
  Build event n+1. `prev` is the hash of the last event (or genesis).

  `ts` is §5's `ts(s)` and defaults to `R5e.Clock.ts/0` — the node's clock
  in one place, truncated to the second. A caller that has **already**
  asked for it passes it in, and `R5e.Log`'s commit does: §6's terminal
  re-check compares every visited authority term against `ts(s)` and this
  function writes it, so reading the clock twice would let the two land on
  either side of a second boundary and put a `ts` on the record that the
  term check never saw. One value, threaded.
  """
  @spec build_event(non_neg_integer(), String.t(), String.t(), String.t(), String.t()) :: map()
  def build_event(seq, prev, kind, payload_addr, ts \\ nil) do
    event = %{
      "seq" => seq,
      "ts" => ts || R5e.Clock.ts(),
      "kind" => kind,
      "payload" => payload_addr,
      "prev" => prev
    }

    Map.put(event, "hash", RecurseVerify.Chain.recompute_hash(event))
  end
end
