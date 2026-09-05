defmodule R5e.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    R5e.Persistence.ensure_dir!(Application.fetch_env!(:r5e, :data_dir))
    R5e.Log.validate_storage_presence!()

    # Provision the node signing key on first boot (a no-op afterwards).
    _ = R5e.SignerProvider.public_key()

    children =
      [
        R5e.KindRegistry,
        R5e.ResourceStore,
        R5e.RefIndex,
        # The log checks for evidence of an initialized data directory before
        # Origin is allowed to create origin.json for a genuinely fresh one.
        {R5e.Log, []},
        # The origin is generated before event 1 (contract §10) and the
        # nonce index is rebuilt from the chain at replay, so both start
        # before `R5e.Bootstrap` — which signs the seeds and therefore
        # needs an origin to address them to.
        R5e.Origin,
        R5e.NonceIndex,
        # §0's succession relation and §5's authority are **one** view of
        # the chain (`RecurseVerify.Authority`'s index), rebuilt at replay
        # like the reference index and for the same reason: it is what the
        # log says, never a second record beside it. `R5e.Succession` is
        # an adapter over the same index and holds no state of its own.
        R5e.Authority,
        R5e.Bootstrap
      ] ++ http_children()

    Supervisor.start_link(children, strategy: :rest_for_one, name: R5e.Supervisor)
  end

  defp http_children do
    if Application.get_env(:r5e, :start_server, true) do
      port = Application.get_env(:r5e, :http_port, 4545)
      [{Bandit, plug: R5e.HTTP.Router, port: port}]
    else
      []
    end
  end
end
