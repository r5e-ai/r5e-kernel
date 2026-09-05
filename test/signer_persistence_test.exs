defmodule R5e.SignerPersistenceTest do
  use ExUnit.Case, async: false

  test "a new node key persists its restricted private half before its public half" do
    with_stopped_kernel(fn dir ->
      owner = self()
      key_dir = Path.join(dir, "keys")
      private_path = Path.join(key_dir, "node_ed25519.key")
      public_path = Path.join(key_dir, "node_ed25519.pub")

      Application.put_env(:r5e, :persistence_hook, fn phase, path ->
        if phase == :atomic_replace_durable and path in [private_path, public_path],
          do: send(owner, {:durable, path})
      end)

      public = R5e.Signer.Local.public_key([])

      assert_receive {:durable, ^private_path}
      assert_receive {:durable, ^public_path}
      assert File.read!(public_path) == public
      assert byte_size(File.read!(private_path)) == 32
      assert Bitwise.band(File.stat!(private_path).mode, 0o777) == 0o600
    end)
  end

  test "a failed public-key sync leaves a partial pair that later use refuses" do
    with_stopped_kernel(fn dir ->
      private_path = Path.join([dir, "keys", "node_ed25519.key"])
      public_path = Path.join([dir, "keys", "node_ed25519.pub"])

      Application.put_env(:r5e, :persistence_hook, fn phase, path ->
        if phase == :before_file_sync and String.starts_with?(path, public_path <> ".tmp."),
          do: raise("injected public-key sync failure")
      end)

      assert_raise RuntimeError, "injected public-key sync failure", fn ->
        R5e.Signer.Local.public_key([])
      end

      private = File.read!(private_path)
      refute File.exists?(public_path)
      Application.delete_env(:r5e, :persistence_hook)

      assert_raise RuntimeError, ~r/incomplete node signing keypair/, fn ->
        R5e.Signer.Local.public_key([])
      end

      assert File.read!(private_path) == private
      refute File.exists?(public_path)
    end)
  end

  test "an existing mismatched keypair is refused without changing either half" do
    with_stopped_kernel(fn dir ->
      key_dir = Path.join(dir, "keys")
      private_path = Path.join(key_dir, "node_ed25519.key")
      public_path = Path.join(key_dir, "node_ed25519.pub")
      File.mkdir_p!(key_dir)

      {_first_public, private} = :crypto.generate_key(:eddsa, :ed25519)
      {other_public, _other_private} = :crypto.generate_key(:eddsa, :ed25519)
      File.write!(private_path, private)
      File.write!(public_path, other_public)

      assert_raise RuntimeError, ~r/public key does not match private key/, fn ->
        R5e.Signer.Local.public_key([])
      end

      assert File.read!(private_path) == private
      assert File.read!(public_path) == other_public
    end)
  end

  test "a missing node key is not regenerated over a nonempty event log" do
    with_stopped_kernel(fn dir ->
      log_path = Path.join(dir, "log.jsonl")
      File.write!(log_path, "acknowledged history\n")

      assert_raise RuntimeError, ~r/refusing to generate.*nonempty event log/, fn ->
        R5e.Signer.Local.public_key([])
      end

      refute File.exists?(Path.join([dir, "keys", "node_ed25519.key"]))
      refute File.exists?(Path.join([dir, "keys", "node_ed25519.pub"]))
      assert File.read!(log_path) == "acknowledged history\n"
    end)
  end

  test "a valid legacy pair is checked, restricted, and reused" do
    with_stopped_kernel(fn dir ->
      key_dir = Path.join(dir, "keys")
      private_path = Path.join(key_dir, "node_ed25519.key")
      public_path = Path.join(key_dir, "node_ed25519.pub")
      File.mkdir_p!(key_dir)
      {public, private} = :crypto.generate_key(:eddsa, :ed25519)
      File.write!(private_path, private)
      File.chmod!(private_path, 0o644)
      File.write!(public_path, public)

      assert R5e.Signer.Local.public_key([]) == public
      assert File.read!(private_path) == private
      assert Bitwise.band(File.stat!(private_path).mode, 0o777) == 0o600
    end)
  end

  defp with_stopped_kernel(fun) do
    previous_data_dir = Application.fetch_env!(:r5e, :data_dir)
    dir = Path.join(System.tmp_dir!(), "r5e-signer-#{System.unique_integer([:positive])}")

    :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :data_dir, dir)
    R5e.Persistence.ensure_dir!(dir)

    try do
      fun.(dir)
    after
      Application.delete_env(:r5e, :persistence_hook)
      Application.put_env(:r5e, :data_dir, previous_data_dir)
      {:ok, _} = Application.ensure_all_started(:r5e)
      File.rm_rf!(dir)
    end
  end
end
