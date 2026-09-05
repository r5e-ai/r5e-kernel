defmodule R5e.ConsistencyTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  setup do
    base = Path.join(System.tmp_dir!(), "r5e-cons-#{System.unique_integer([:positive])}")
    {early, late} = {base <> "-early", base <> "-late"}
    data_dir = base <> "-kernel"
    previous_data_dir = Application.fetch_env!(:r5e, :data_dir)

    :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :data_dir, data_dir)
    {:ok, _} = Application.ensure_all_started(:r5e)

    # Both directories, not `base` — which is never created. `Export.run`
    # writes into a directory it finds, so a bundle left behind by an
    # earlier run and landed on again by a repeated `unique_integer`
    # would have this run's log beside that run's objects, and the
    # verifier would report the leftovers as objects nothing on the chain
    # put there. It would be right, and the test would be wrong.
    on_exit(fn ->
      _ = Application.stop(:r5e)
      Application.put_env(:r5e, :data_dir, previous_data_dir)
      {:ok, _} = Application.ensure_all_started(:r5e)
      Enum.each([early, late, data_dir], &File.rm_rf/1)
    end)

    {:ok, early: early, late: late}
  end

  test "verifier proves a later export consistent with an earlier one",
       %{early: early, late: late} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "ConsA"}))
    {:ok, ^early, _} = R5e.Export.run(early)

    # The log grows...
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "ConsB"}))
    {:ok, _} = admit("test.r5e.io", "v1alpha1", "ConsB", "b1", %{"title" => "later"})
    {:ok, ^late, _} = R5e.Export.run(late)

    {:ok, report} = RecurseVerify.run(late, prior: early)

    assert report.findings == []
    assert Enum.any?(report.checked, &(&1 =~ "consistency: prior STH"))
    assert Enum.any?(report.checked, &(&1 =~ "nothing before seq"))
    refute Enum.any?(report.not_checked, &(&1 =~ "no prior export presented"))
  end

  test "a prior STH from a rewritten history is reported as inconsistent",
       %{early: early, late: late} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "ConsTamper"}))
    {:ok, ^early, _} = R5e.Export.run(early)

    {:ok, _} = admit("test.r5e.io", "v1alpha1", "ConsTamper", "t1", %{"title" => "x"})
    {:ok, ^late, _} = R5e.Export.run(late)

    # Forge the prior manifest: same signature machinery, different root —
    # as if the earlier checkpoint attested a different history. Re-sign
    # the tampered claim with the node key so the STH itself verifies and
    # only the consistency check can catch the divergence.
    manifest_path = Path.join(early, "manifest.json")
    manifest = manifest_path |> File.read!() |> Jason.decode!()

    forged_claim =
      Map.put(manifest["checkpoint"]["checkpoint"], "merkleRoot", String.duplicate("ab", 32))

    forged_envelope =
      R5e.DSSE.envelope(R5e.Log.checkpoint_payload_type(), R5e.Canonical.encode(forged_claim))

    manifest
    |> put_in(["checkpoint", "checkpoint"], forged_claim)
    |> put_in(["checkpoint", "envelope"], forged_envelope)
    |> then(&File.write!(manifest_path, Jason.encode!(&1)))

    {:ok, report} = RecurseVerify.run(late, prior: early)
    assert Enum.any?(report.findings, &(&1 =~ "NOT consistent with this log"))
  end

  test "without a prior export, consistency is honestly listed as not checked",
       %{late: late} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "ConsSolo"}))
    {:ok, ^late, _} = R5e.Export.run(late)

    {:ok, report} = RecurseVerify.run(late)
    assert Enum.any?(report.not_checked, &(&1 =~ "no prior export presented"))
  end
end
