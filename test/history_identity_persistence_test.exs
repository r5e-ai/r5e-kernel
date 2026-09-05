defmodule R5e.HistoryIdentityPersistenceTest do
  use ExUnit.Case, async: false

  defmodule ExternalSigner do
    @behaviour R5e.SignerProvider

    @impl true
    def sign(key, message),
      do: :crypto.sign(:eddsa, :none, message, [key.private, :ed25519])

    @impl true
    def public_key(key), do: key.public

    @impl true
    def key_id(key), do: R5e.Signer.Local.fingerprint(key.public)
  end

  test "first role creation remains valid after core seeds make the log nonempty" do
    with_data_dir(fn dir ->
      start_kernel!()

      assert length(R5e.Log.events()) >= 10
      assert File.exists?(Path.join([dir, "keys", "retention_ed25519.key"]))
      assert R5e.Retention.authority() != []
    end)
  end

  test "a missing role pair over its node-endorsed history refuses restart" do
    with_started_kernel(fn dir ->
      log = Path.join(dir, "log.jsonl")
      acknowledged = File.read!(log)
      stop_kernel()
      File.rm!(Path.join([dir, "keys", "retention_ed25519.key"]))
      File.rm!(Path.join([dir, "keys", "retention_ed25519.pub"]))

      assert_start_refused("existing node-endorsed role identity")
      assert File.read!(log) == acknowledged
      refute File.exists?(Path.join([dir, "keys", "retention_ed25519.key"]))
      refute File.exists?(Path.join([dir, "keys", "retention_ed25519.pub"]))
    end)
  end

  test "a substituted valid role pair cannot acquire the historical role" do
    with_started_kernel(fn dir ->
      log = Path.join(dir, "log.jsonl")
      acknowledged = File.read!(log)
      stop_kernel()

      {public, private} = :crypto.generate_key(:eddsa, :ed25519)
      File.write!(Path.join([dir, "keys", "retention_ed25519.key"]), private)
      File.write!(Path.join([dir, "keys", "retention_ed25519.pub"]), public)

      assert_start_refused("does not match node-endorsed role identity history")
      assert File.read!(log) == acknowledged
    end)
  end

  test "an Endorsement admitted through the general bootstrap API binds its role immediately" do
    with_started_kernel(fn dir ->
      role = "generic-api"
      key = R5e.Signer.Local.role_keypair(role)

      assert {:ok, _receipt} =
               R5e.Bootstrap.admit_as_node(
                 "core.r5e.io",
                 "v1",
                 "Endorsement",
                 nil,
                 endorsement_spec(role, key.public)
               )

      File.rm!(Path.join([dir, "keys", "#{role}_ed25519.key"]))
      File.rm!(Path.join([dir, "keys", "#{role}_ed25519.pub"]))

      assert_raise RuntimeError, ~r/existing node-endorsed role identity/, fn ->
        R5e.Signer.Local.role_keypair(role)
      end
    end)
  end

  test "a predecessor node's role binding survives legitimate node succession" do
    with_started_kernel(fn dir ->
      before = R5e.Bootstrap.retention_key().public
      successor = R5e.Request.generate_key()

      assert {:ok, _receipt} =
               R5e.TestHelpers.admit_request(%{
                 keys: [:node, successor],
                 group: "core.r5e.io",
                 version: "v1",
                 kind: "Succession",
                 name: nil,
                 spec: %{
                   "predecessor" => R5e.DSSE.node_key_id(),
                   "successor" => R5e.Request.key_id(successor),
                   "successorKey" => %{
                     "algorithm" => "ed25519",
                     "bytes" => Base.encode64(successor.public)
                   }
                 }
               })

      stop_kernel()
      Application.put_env(:r5e, :signer, {ExternalSigner, successor})
      start_kernel!()

      assert R5e.DSSE.node_key_id() == R5e.Request.key_id(successor)
      assert R5e.Bootstrap.retention_key().public == before

      File.rm!(Path.join([dir, "keys", "retention_ed25519.key"]))
      File.rm!(Path.join([dir, "keys", "retention_ed25519.pub"]))

      assert_raise RuntimeError, ~r/existing node-endorsed role identity/, fn ->
        R5e.Bootstrap.retention_key()
      end

      refute File.exists?(Path.join([dir, "keys", "retention_ed25519.key"]))
      refute File.exists?(Path.join([dir, "keys", "retention_ed25519.pub"]))
    end)
  end

  test "deleting an acknowledged log while its CAS and origin survive refuses restart" do
    with_started_kernel(fn dir ->
      stop_kernel()
      log = Path.join(dir, "log.jsonl")
      node_private = File.read!(Path.join([dir, "keys", "node_ed25519.key"]))
      File.rm!(log)

      assert_start_refused("event log is missing while persistent history evidence remains")
      refute File.exists?(log)
      assert File.read!(Path.join([dir, "keys", "node_ed25519.key"])) == node_private
      assert File.exists?(Path.join([dir, "keys", "origin.json"]))
      assert File.ls!(Path.join(dir, "cas")) != []
    end)
  end

  test "zeroing an acknowledged log refuses restart" do
    with_started_kernel(fn dir ->
      stop_kernel()
      log = Path.join(dir, "log.jsonl")
      File.write!(log, "")

      assert_start_refused("event log is zero-length while persistent history evidence remains")
      assert File.read!(log) == ""
    end)
  end

  test "missing history refuses before a missing node key can be regenerated" do
    with_started_kernel(fn dir ->
      stop_kernel()
      log = Path.join(dir, "log.jsonl")
      private = Path.join([dir, "keys", "node_ed25519.key"])
      public = Path.join([dir, "keys", "node_ed25519.pub"])
      File.rm!(log)
      File.rm!(private)
      File.rm!(public)

      assert_start_refused("event log is missing while persistent history evidence remains")
      refute File.exists?(log)
      refute File.exists?(private)
      refute File.exists?(public)
    end)
  end

  test "a preprovisioned node pair alone is still a valid fresh boot" do
    with_data_dir(fn dir ->
      :ok = R5e.Signer.Local.ensure_keys!()
      refute File.exists?(Path.join(dir, "log.jsonl"))
      refute File.exists?(Path.join([dir, "keys", "origin.json"]))
      refute File.exists?(Path.join(dir, "cas"))

      start_kernel!()

      assert R5e.Log.events() != []
      assert File.read!(R5e.Log.history_marker_path()) == "r5e-event-log/v1\n"
    end)
  end

  test "a fresh external signer provider is not mistaken for lost local history" do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)

    with_data_dir([signer: {ExternalSigner, %{public: public, private: private}}], fn dir ->
      start_kernel!()

      assert R5e.Log.events() != []
      refute File.exists?(Path.join([dir, "keys", "node_ed25519.key"]))
      refute File.exists?(Path.join([dir, "keys", "node_ed25519.pub"]))
    end)
  end

  test "the first durable log append is followed by a durable history marker before boot returns" do
    with_data_dir(fn _dir ->
      owner = self()
      log = R5e.Log.log_path()
      marker = R5e.Log.history_marker_path()

      Application.put_env(:r5e, :persistence_hook, fn
        :append_durable, ^log -> send(owner, :log_durable)
        :atomic_replace_durable, ^marker -> send(owner, :marker_durable)
        _phase, _path -> :ok
      end)

      start_kernel!()

      assert_receive :log_durable
      assert_receive :marker_durable
      assert File.read!(marker) == "r5e-event-log/v1\n"
    end)
  end

  defp with_started_kernel(fun),
    do:
      with_data_dir(fn dir ->
        start_kernel!()
        fun.(dir)
      end)

  defp endorsement_spec(role, public) do
    now = R5e.Clock.now()

    %{
      "subject" => RecurseVerify.DSSE.key_id!("ed25519", public),
      "subjectKey" => %{"algorithm" => "ed25519", "bytes" => Base.encode64(public)},
      "role" => role,
      "kinds" => ["*"],
      "mayIssue" => false,
      "notBefore" => RecurseVerify.Instant.to_string(now),
      "notAfter" => RecurseVerify.Instant.to_string(DateTime.add(now, 3_600, :second))
    }
  end

  defp with_data_dir(opts \\ [], fun) do
    previous_data_dir = Application.fetch_env!(:r5e, :data_dir)
    previous_signer = Application.get_env(:r5e, :signer)
    dir = Path.join(System.tmp_dir!(), "r5e-history-#{System.unique_integer([:positive])}")

    stop_kernel()
    Application.put_env(:r5e, :data_dir, dir)
    R5e.Persistence.ensure_dir!(dir)

    if signer = opts[:signer], do: Application.put_env(:r5e, :signer, signer)

    try do
      fun.(dir)
    after
      stop_kernel()
      Application.delete_env(:r5e, :persistence_hook)
      Application.put_env(:r5e, :data_dir, previous_data_dir)

      if previous_signer,
        do: Application.put_env(:r5e, :signer, previous_signer),
        else: Application.delete_env(:r5e, :signer)

      {:ok, _} = Application.ensure_all_started(:r5e)
      File.rm_rf!(dir)
    end
  end

  defp start_kernel! do
    {:ok, _} = Application.ensure_all_started(:r5e)
  end

  defp assert_start_refused(message) do
    assert {:error, reason} = Application.ensure_all_started(:r5e)
    assert inspect(reason) =~ message
  end

  defp stop_kernel do
    case Application.stop(:r5e) do
      :ok -> :ok
      {:error, {:not_started, :r5e}} -> :ok
    end
  end
end
