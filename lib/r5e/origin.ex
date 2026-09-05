defmodule R5e.Origin do
  @moduledoc """
  The chain's origin (spec 011 contract §10).

  Before event 1 a node generates 32 bytes of `random` and derives

      origin = sha256(uvarint(32) || random || uvarint(32) || nodePublicKey)

  Every signed request names the origin it is for, and a request naming
  another chain's origin is refused at `authenticate: wrong origin`. That
  is what stops an envelope admitted here from being replayed onto a
  different deployment: the signature covers the origin, so a request is
  addressed to one chain and to no other.

  `random` is on the record — event 1's payload carries it — so a reader
  with the node public key re-derives the origin and checks that the
  deployment did not pick its own. The bytes are generated once and kept
  under the data directory beside the node key; the chain is the record
  and wins on any disagreement.
  """

  use Agent

  @random_bytes 32

  def start_link(_opts), do: Agent.start_link(&load_or_generate!/0, name: __MODULE__)

  @doc """
  Is this chain's origin **on the chain** — that is, has some recorded
  payload carried the `random` it was derived from?

  `false` on a fresh chain, and on a legacy one until the first act this
  contract causes. `R5e.Bootstrap` uses it to decide which act carries
  `random`: exactly one does, and which one it is differs between a fresh
  chain (event 1) and a legacy one (the meta-Kind transition).
  """
  @spec adopted?() :: boolean()
  def adopted?, do: Agent.get(__MODULE__, &Map.get(&1, :adopted, false))

  @doc "This chain's origin, as `sha256:<64 hex>`."
  @spec current() :: String.t()
  def current, do: Agent.get(__MODULE__, & &1.origin)

  @doc "The 32 random bytes the origin was derived from, base64."
  @spec random() :: String.t()
  def random, do: Agent.get(__MODULE__, & &1.random)

  @doc """
  Adopt the origin and random a chain already carries (event 1's
  payload). The record is authoritative: a data directory whose key file
  disagrees with its own log is following the log.
  """
  @spec adopt(String.t(), String.t()) :: :ok
  def adopt(origin, random) when is_binary(origin) and is_binary(random) do
    Agent.update(__MODULE__, fn state ->
      if state.origin != origin or state.random != random do
        write!(%{origin: origin, random: random})
      end

      %{origin: origin, random: random, adopted: true}
    end)
  end

  @doc """
  Forget that the chain carries the origin — `R5e.Bootstrap.replay/0`
  calls this before re-reading the log, so `adopted?/0` answers about the
  chain as it is now rather than as it was at some earlier boot.
  """
  @spec reset_adoption() :: :ok
  def reset_adoption, do: Agent.update(__MODULE__, &Map.put(&1, :adopted, false))

  @doc "The §10 derivation, exposed so a verifier-side re-derivation reads the same."
  @spec derive(binary(), binary()) :: String.t()
  def derive(random_bytes, node_public_key) do
    uvarint = &RecurseVerify.DSSE.uvarint/1

    R5e.Canonical.hash_bytes(
      uvarint.(byte_size(random_bytes)) <>
        random_bytes <> uvarint.(byte_size(node_public_key)) <> node_public_key
    )
  end

  defp load_or_generate! do
    path = path()

    if File.exists?(path) do
      %{"origin" => origin, "random" => random} = path |> File.read!() |> Jason.decode!()
      %{origin: origin, random: random, adopted: false}
    else
      random_bytes = :crypto.strong_rand_bytes(@random_bytes)

      state = %{
        origin: derive(random_bytes, R5e.SignerProvider.public_key()),
        random: Base.encode64(random_bytes),
        adopted: false
      }

      write!(state)
      state
    end
  end

  defp write!(state) do
    path = path()
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, Jason.encode!(%{"origin" => state.origin, "random" => state.random}))
  end

  defp path,
    do: Path.join([Application.fetch_env!(:r5e, :data_dir), "keys", "origin.json"])
end
