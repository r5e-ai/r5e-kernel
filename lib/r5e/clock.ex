defmodule R5e.Clock do
  @moduledoc """
  The node's clock, in one place.

  Everything the identity contract compares against wall-clock time —
  `expires` at `authenticate` and again at `record`, an authority term,
  the nonce index's pruning horizon — reads it here rather than calling
  `DateTime.utc_now/0` at the call site. Two reasons, and only the second
  is about tests:

    * the contract's §6 re-check is *the `ts` the kernel is about to
      write*, so "now" has to be a value the kernel can name, not an
      expression scattered through the pipeline;
    * `config :r5e, :clock` lets a conformance vector set it, which is
      the only way a vector can pin an expiry boundary without sleeping.

  The override is a `DateTime`, or a zero-arity function returning one.
  It is `nil` in every shipped config.
  """

  @doc "The node's current instant, UTC."
  @spec now() :: DateTime.t()
  def now do
    case Application.get_env(:r5e, :clock) do
      %DateTime{} = fixed -> fixed
      fun when is_function(fun, 0) -> fun.()
      _ -> DateTime.utc_now()
    end
  end

  @doc "The node's current instant as an §0 instant string (UTC, second precision)."
  @spec now_string() :: String.t()
  def now_string, do: RecurseVerify.Instant.to_string(now())

  @doc """
  §5's `ts(s)`: **the instant the log will write for the event this act is
  about to become** — `now/0` truncated to the second, exactly as
  `R5e.Chain.build_event/4` renders it.

  Every term comparison the kernel makes is against this and never against
  the untruncated clock: §5 clause 4 at `resolve`, and §6's re-check of
  every visited term under the append lock. A term whose `notBefore`
  carries a fraction of a second is otherwise decided one way by the gate
  and the other way by every reader of the chain, because the record only
  ever carries whole seconds — and an authority that the record says was
  out of term must not have produced a grant.
  """
  @spec ts() :: String.t()
  def ts, do: now_string()

  @doc "`now/0` shifted by `seconds`, as an §0 instant string."
  @spec in_seconds(integer()) :: String.t()
  def in_seconds(seconds) do
    now() |> DateTime.add(seconds, :second) |> RecurseVerify.Instant.to_string()
  end
end
