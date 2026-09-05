defmodule R5e.KindRegistry do
  @moduledoc """
  In-memory index of admitted Kinds, keyed by `group/version/Kind`. The
  authoritative record is the event log; this registry is rebuilt from it at
  boot (`R5e.Bootstrap.replay/0`) — a derived view, never the stored form.

  Identity is entrenched (schema-lite v2 §1): a second definition with the
  same `(group, version, kind)` is refused by `put/1` unless it is
  byte-identical, compared on the canonical encoding of the definition as
  submitted (`R5e.Kind.spec_address`). `force_put/1` is the deliberate
  bypass, and there are exactly three callers: replay (the log is the
  record, and it replays in order), the bootstrap pre-registration of the
  meta-Kind (scaffolding the first event retroactively covers), and the
  admit step, which reaches it only after admission has already applied the
  §2 readmit rule.
  """

  use Agent

  def start_link(_opts), do: Agent.start_link(fn -> %{} end, name: __MODULE__)

  @doc """
  Register a Kind. Refuses a different definition of an identity already
  registered; a byte-identical one is a no-op.
  """
  @spec put(R5e.Kind.t()) :: :ok | {:error, {:duplicate, R5e.Kind.t()}}
  def put(%R5e.Kind{} = kind) do
    name = R5e.Kind.name(kind)

    Agent.get_and_update(__MODULE__, fn state ->
      case Map.get(state, name) do
        nil ->
          {:ok, Map.put(state, name, kind)}

        %R5e.Kind{spec_address: address} = existing ->
          if address != nil and address == kind.spec_address,
            do: {:ok, state},
            else: {{:error, {:duplicate, existing}}, state}
      end
    end)
  end

  @doc "Register unconditionally. See the moduledoc for who may."
  @spec force_put(R5e.Kind.t()) :: :ok
  def force_put(%R5e.Kind{} = kind) do
    Agent.update(__MODULE__, &Map.put(&1, R5e.Kind.name(kind), kind))
  end

  @spec get(String.t(), String.t(), String.t()) :: {:ok, R5e.Kind.t()} | {:error, :unknown_kind}
  def get(group, version, kind) do
    case Agent.get(__MODULE__, &Map.get(&1, "#{group}/#{version}/#{kind}")) do
      nil -> {:error, :unknown_kind}
      found -> {:ok, found}
    end
  end

  @spec list() :: [R5e.Kind.t()]
  def list do
    Agent.get(__MODULE__, &Map.values/1)
    |> Enum.sort_by(&R5e.Kind.name/1)
  end
end
