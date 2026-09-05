defmodule R5e.NonceIndex do
  @moduledoc """
  The replay index (spec 011 contract §2, §6): the set of `(signer 1,
  nonce)` pairs this chain has already seen, with the `expires` each was
  claimed under.

  ## The claim is atomic and it stands

  `claim/3` is a single `Agent.get_and_update/2`, so two identical
  requests arriving at once cannot both win. The claim is taken at
  `authenticate`, **after** `actor mismatch` and before every other
  check, and it **stands through every later outcome, denials included**:
  a request denied at `resolve` has still spent its nonce, and resubmitting
  the same envelope is `authenticate: nonce replayed`. Anything weaker
  would let a caller retry a refused envelope until the world moved under
  it, which is precisely what a nonce is for.

  The two refusals that come *before* the claim — a malformed envelope and
  an invalid signature — claim nothing, because they are not attributable
  and an unattributable request is not an act (§12). So a caller whose
  signature was mangled in transit may sign the same request again with
  the same nonce and be admitted.

  ## Rebuilt from the chain, pruned by the clock

  The index is a view, so it is rebuilt at every boot from the recorded
  payloads (`R5e.Bootstrap.replay/0`) — every recorded act carries its
  `actor.id`, `nonce` and `expires`, granted or denied, and those three
  are the whole of an entry.

  §6 allows pruning an entry once its `expires` plus the 300-second
  `authenticate` skew has passed: after that moment the request it
  protects is refused as `expired` anyway, so remembering it proves
  nothing. `prune/0` is called on each claim, which keeps the index
  bounded without a timer.
  """

  use Agent

  @skew_seconds 300

  def start_link(_opts), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

  @doc "Forget everything. `R5e.Bootstrap.replay/0` calls this before rebuilding."
  @spec reset() :: :ok
  def reset, do: Agent.update(__MODULE__, fn _ -> %{} end)

  @doc """
  Claim `(signer, nonce)` atomically. `:ok` when this chain had not seen
  it; `{:error, :replayed}` when it had — and the earlier claim stands.
  """
  @spec claim(String.t(), String.t(), String.t()) :: :ok | {:error, :replayed}
  def claim(signer, nonce, expires) do
    horizon = horizon()

    Agent.get_and_update(__MODULE__, fn state ->
      state = prune_state(state, horizon)

      case Map.fetch(state, {signer, nonce}) do
        {:ok, _expires} -> {{:error, :replayed}, state}
        :error -> {:ok, Map.put(state, {signer, nonce}, expires)}
      end
    end)
  end

  @doc "Whether `(signer, nonce)` is claimed on this chain right now."
  @spec claimed?(String.t(), String.t()) :: boolean()
  def claimed?(signer, nonce), do: Agent.get(__MODULE__, &Map.has_key?(&1, {signer, nonce}))

  @doc "Re-take a claim while rebuilding from the chain (replay). Never refuses."
  @spec observe(String.t(), String.t(), String.t()) :: :ok
  def observe(signer, nonce, expires)
      when is_binary(signer) and is_binary(nonce) and is_binary(expires) do
    Agent.update(__MODULE__, &Map.put(&1, {signer, nonce}, expires))
  end

  def observe(_signer, _nonce, _expires), do: :ok

  @doc "Drop entries whose `expires` + 300 s has passed (§6)."
  @spec prune() :: :ok
  def prune do
    horizon = horizon()
    Agent.update(__MODULE__, &prune_state(&1, horizon))
  end

  @doc "How many claims are held. For tests and for an operator asking."
  @spec size() :: non_neg_integer()
  def size, do: Agent.get(__MODULE__, &map_size/1)

  # An entry whose `expires` will not parse is kept: it was recorded, and
  # the index is not the place to decide a recorded act was malformed.
  defp prune_state(state, horizon) do
    :maps.filter(
      fn _key, expires ->
        case RecurseVerify.Instant.parse(expires) do
          {:ok, at} -> DateTime.compare(at, horizon) != :lt
          {:error, _} -> true
        end
      end,
      state
    )
  end

  defp horizon, do: DateTime.add(R5e.Clock.now(), -@skew_seconds, :second)

  @doc "The `authenticate` skew, in seconds — 300 (§2)."
  def skew_seconds, do: @skew_seconds
end
