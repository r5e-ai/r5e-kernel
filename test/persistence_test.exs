defmodule R5e.PersistenceTest do
  @moduledoc """
  The event record is acknowledged only after its payload and log line cross
  their persistence barriers. These tests exercise the ordering seam, both
  possible sides of an ambiguous failed append, and startup's refusal to
  repair corrupt history by truncating or overwriting it.
  """

  use ExUnit.Case, async: false

  setup do
    on_exit(fn -> Application.delete_env(:r5e, :persistence_hook) end)
    :ok
  end

  test "a grant syncs its payload, then its log line, then its substrate bytes" do
    R5e.Vectors.with_fresh_kernel(fn ->
      owner = self()

      Application.put_env(:r5e, :persistence_hook, fn phase, path ->
        if phase in [:atomic_replace_durable, :append_durable],
          do: send(owner, {:durable, phase, path})
      end)

      payload = %{"nonce" => System.unique_integer([:positive])}
      substrate = "substrate-#{System.unique_integer([:positive])}"
      payload_address = R5e.Canonical.hash(payload)
      substrate_address = R5e.Canonical.hash_bytes(substrate)

      assert {:ok, event, ^substrate_address} =
               R5e.Log.commit("durability.test", payload, %{}, fn _event ->
                 R5e.CAS.put(substrate)
               end)

      assert event["payload"] == payload_address

      assert collect_durable(3) == [
               {:atomic_replace_durable, cas_path(payload_address)},
               {:append_durable, R5e.Log.log_path()},
               {:atomic_replace_durable, cas_path(substrate_address)}
             ]
    end)
  end

  test "a failure before the payload sync is not acknowledged and appends no event" do
    R5e.Vectors.with_fresh_kernel(fn ->
      before = R5e.Log.events()
      fail_once = :atomics.new(1, [])

      Application.put_env(:r5e, :persistence_hook, fn phase, path ->
        if phase == :before_file_sync and String.contains?(path, "/cas/") and
             String.contains?(path, ".tmp.") and
             :atomics.compare_exchange(fail_once, 1, 0, 1) == :ok do
          raise "injected payload sync failure"
        end
      end)

      assert_raise RuntimeError, "injected payload sync failure", fn ->
        R5e.Log.append("durability.test", %{"case" => "payload-sync"})
      end

      await_log()
      assert R5e.Log.events() == before
      assert :atomics.get(fail_once, 1) == 1
    end)
  end

  test "a complete line left by a failed log sync is recovered but was not acknowledged" do
    R5e.Vectors.with_fresh_kernel(fn ->
      before = length(R5e.Log.events())
      fail_once = :atomics.new(1, [])
      log_path = R5e.Log.log_path()

      Application.put_env(:r5e, :persistence_hook, fn phase, path ->
        if phase == :before_file_sync and path == log_path and
             :atomics.compare_exchange(fail_once, 1, 0, 1) == :ok do
          raise "injected log sync failure"
        end
      end)

      assert_raise RuntimeError, "injected log sync failure", fn ->
        R5e.Log.append("durability.test", %{"case" => "log-sync"})
      end

      await_log()
      assert length(R5e.Log.events()) == before + 1
      assert List.last(R5e.Log.events())["kind"] == "durability.test"
      assert :atomics.get(fail_once, 1) == 1
    end)
  end

  test "startup refuses a torn final line without changing the acknowledged prefix" do
    with_failed_start(
      fn dir ->
        payload = R5e.CAS.put(R5e.Canonical.encode(%{"case" => "acknowledged-prefix"}))
        event = R5e.Chain.build_event(1, R5e.Chain.genesis(), "durability.test", payload)

        File.write!(
          Path.join(dir, "log.jsonl"),
          Jason.encode!(event) <> "\n" <> "{\"seq\":2"
        )
      end,
      fn result ->
        assert inspect(result) =~ "invalid_event_log"
        assert inspect(result) =~ "not newline-terminated"
      end
    )
  end

  test "startup refuses a corrupt chain without changing it" do
    with_failed_start(
      fn dir ->
        payload = R5e.CAS.put(R5e.Canonical.encode(%{"case" => "corrupt-chain"}))

        event =
          R5e.Chain.build_event(1, R5e.Chain.genesis(), "durability.test", payload)
          |> Map.put("hash", String.duplicate("0", 64))

        File.write!(Path.join(dir, "log.jsonl"), Jason.encode!(event) <> "\n")
      end,
      fn result ->
        assert inspect(result) =~ "invalid_event_log"
        assert inspect(result) =~ "recorded hash"
      end
    )
  end

  test "startup refuses blank records that the total verifier parser ignores" do
    with_failed_start(
      fn dir -> File.write!(Path.join(dir, "log.jsonl"), "\n") end,
      fn result ->
        assert inspect(result) =~ "invalid_event_log"
        assert inspect(result) =~ "empty record at line 1"
      end
    )
  end

  test "writable startup refuses an event whose payload cannot be replayed" do
    with_failed_start(
      fn dir ->
        payload = "sha256:" <> String.duplicate("0", 64)
        event = R5e.Chain.build_event(1, R5e.Chain.genesis(), "durability.test", payload)
        File.write!(Path.join(dir, "log.jsonl"), Jason.encode!(event) <> "\n")
      end,
      fn result ->
        assert inspect(result) =~ "invalid_event_log"
        assert inspect(result) =~ "refusing writable startup"
        assert inspect(result) =~ "replay cannot reconstruct admission state"
      end
    )
  end

  defp collect_durable(count) do
    Enum.map(1..count, fn _ ->
      assert_receive {:durable, phase, path}, 1_000
      {phase, path}
    end)
  end

  defp cas_path(address), do: Path.join(R5e.CAS.root(), R5e.CAS.relative_path(address))

  defp await_log(attempts \\ 100)

  defp await_log(0), do: flunk("R5e.Log did not restart")

  defp await_log(attempts) do
    case Process.whereis(R5e.Log) do
      pid when is_pid(pid) ->
        try do
          _ = R5e.Log.events()
          :ok
        catch
          :exit, _ -> retry_log(attempts)
        end

      _ ->
        retry_log(attempts)
    end
  end

  defp retry_log(attempts) do
    Process.sleep(10)
    await_log(attempts - 1)
  end

  defp with_failed_start(prepare, assertions) do
    previous = Application.fetch_env!(:r5e, :data_dir)
    dir = Path.join(System.tmp_dir!(), "r5e-persistence-#{System.unique_integer([:positive])}")

    :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :data_dir, dir)
    R5e.Persistence.ensure_dir!(dir)
    R5e.Signer.Local.ensure_keys!()
    prepare.(dir)

    path = Path.join(dir, "log.jsonl")
    original = File.read!(path)
    result = Application.ensure_all_started(:r5e)

    try do
      refute match?({:ok, _}, result)
      assertions.(result)
      assert File.read!(path) == original
    after
      _ = Application.stop(:r5e)
      Application.put_env(:r5e, :data_dir, previous)
      {:ok, _} = Application.ensure_all_started(:r5e)
      File.rm_rf!(dir)
    end
  end
end
