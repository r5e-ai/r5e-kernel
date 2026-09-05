defmodule R5e.CommitConcurrencyTest do
  @moduledoc """
  The live half of spec/05 §7: a hundred admissions racing on one
  resource, with nothing staged and no hook installed.

  `R5e.StoryTwoTest` provokes the interleaving deterministically, which
  proves the mechanism fires. This proves the property survives when the
  scheduler chooses the interleaving: fifty supersessions of one
  `literal`-named resource and fifty admissions that cite it, all at
  once, against a real kernel on a scratch directory.

  What is asserted afterwards is what a reader of the exported chain
  would be able to check: the chain is contiguous, every generation any
  granted receipt cites is below its own seq and is the generation that
  stood at that position, and the verifier finds nothing. Contention is
  expected and is not a failure — an admission that could not commit what
  it read is denied at `record` with reason `contended`, and that denial
  is on the record with the stale generation it read, which is the
  evidence for the refusal.
  """

  use ExUnit.Case, async: false

  @moduletag timeout: 180_000

  @bundle_ref "race.r5e.io/v1alpha1/Bundle/active"
  @actors for n <- 1..8,
              do: %{"id" => "person:#{n}", "keyFingerprint" => "sha256:test-#{n}"}

  defmodule Policy do
    @moduledoc false
    @behaviour R5e.Policy

    @impl true
    def authorize(_request) do
      generations =
        case R5e.ResourceStore.get("race.r5e.io", "v1alpha1", "Bundle", "active") do
          {:ok, entry, _lineage} ->
            %{"race.r5e.io/v1alpha1/Bundle/active" => entry["admissionSeq"]}

          {:error, :not_found} ->
            %{}
        end

      {:ok,
       %{
         "engine" => "race",
         "decision" => "allow",
         "bundle" => nil,
         "bundleRef" => "race.r5e.io/v1alpha1/Bundle/active",
         "matched" => [],
         "generations" => generations
       }}
    end
  end

  test "fifty supersessions and fifty citers at once: contiguous chain, no stale citation, findings none" do
    dest = Path.join(System.tmp_dir!(), "r5e-race-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)

    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(bundle_kind())
      {:ok, _} = R5e.Vectors.admit_definition(citer_kind())
      {:ok, _} = admit(actor(0), "Bundle", "active", %{"rule" => "generation 0"})

      previous_policy = Application.get_env(:r5e, :policy)
      previous_retries = Application.get_env(:r5e, :commit_retries)
      Application.put_env(:r5e, :policy, Policy)
      Application.put_env(:r5e, :commit_retries, 25)

      on_exit(fn ->
        Application.put_env(:r5e, :policy, previous_policy || R5e.Policy.AllowAll)
        Application.put_env(:r5e, :commit_retries, previous_retries || 3)
      end)

      jobs =
        Enum.map(1..50, &{:supersede, &1}) ++ Enum.map(1..50, &{:cite, &1})

      results =
        jobs
        |> Enum.shuffle()
        |> Task.async_stream(&run_job/1, max_concurrency: 100, timeout: 120_000, ordered: false)
        |> Enum.map(fn {:ok, result} -> result end)

      # Nothing crashed: every job came back with a receipt, granted or
      # refused. A raise here would be the halt path, and nothing in this
      # run injects a substrate failure.
      assert length(results) == 100
      assert Enum.all?(results, &match?({outcome, _} when outcome in [:ok, :denied], &1))
      refute R5e.Log.halted()

      {granted, denied} = Enum.split_with(results, &match?({:ok, _}, &1))
      contended = Enum.count(denied, fn {:denied, r} -> r["reason"] =~ "record: contended: " end)

      # Every denial in this run is a contention denial: nothing else in
      # it can refuse anything.
      assert contended == length(denied), Enum.map_join(denied, "\n", &elem(&1, 1)["reason"])
      assert granted != []

      # The chain: contiguous, every hash recomputed, every prev link
      # verified — the same check the verifier runs offline.
      assert {:ok, tree_size} = R5e.Log.verify()
      assert tree_size == length(R5e.Log.events())

      # The property, over the whole chain.
      assert R5e.CommitInvariants.assert_no_stale_citation() > 0

      # The store's live entry is the last supersession on the chain, and
      # nothing else: the retries did not leave a fork behind.
      {:ok, entry, _} = R5e.ResourceStore.get("race.r5e.io", "v1alpha1", "Bundle", "active")
      assert entry["admissionSeq"] == last_bundle_seq()

      displaced = R5e.ResourceStore.superseded("race.r5e.io", "v1alpha1", "Bundle", "active")
      assert length(displaced) == bundle_admissions() - 1

      # And it all survives the round trip: exported, then re-checked by
      # the standalone verifier, which shares no code with the writer
      # beyond the chain and CAS math.
      {:ok, ^dest, export} = R5e.Export.run(dest)
      assert export["missingObjects"] == []

      {:ok, report} = RecurseVerify.run(dest)
      assert report.findings == [], Enum.join(report.findings, "\n")

      IO.puts(
        "\n  [§7 live run] #{length(R5e.Log.events())} events, " <>
          "#{length(granted)} granted, #{contended} contended, " <>
          "#{bundle_admissions()} admissions of #{@bundle_ref}"
      )
    end)
  end

  # -- the two job shapes ------------------------------------------------

  defp run_job({:supersede, n}) do
    admit(actor(n), "Bundle", "active", %{"rule" => "generation #{n}"})
  end

  # A reader *and* a citer: the policy reads the bundle (so the receipt
  # captures its generation) and the spec cites it (so the manifest
  # captures it a second time, independently). Both must be true at the
  # seq the event lands at.
  defp run_job({:cite, n}) do
    admit(actor(n), "Citer", "c#{n}", %{
      "bundle" => %{"$ref" => @bundle_ref},
      "label" => "citer #{n}"
    })
  end

  defp actor(n), do: Enum.at(@actors, rem(n, length(@actors)))

  defp admit(actor, kind, name, spec) do
    R5e.TestHelpers.admit_request(%{
      actor: actor,
      group: "race.r5e.io",
      version: "v1alpha1",
      kind: kind,
      name: name,
      spec: spec
    })
  end

  defp bundle_events do
    for event <- R5e.Log.events(),
        event["kind"] == "admission.granted",
        {:ok, bytes} <- [R5e.CAS.get(event["payload"] || "")],
        {:ok, payload} <- [Jason.decode(bytes)],
        get_in(payload, ["target", "kind"]) == "Bundle",
        do: event["seq"]
  end

  defp bundle_admissions, do: length(bundle_events())
  defp last_bundle_seq, do: List.last(bundle_events())

  defp bundle_kind do
    %{
      "group" => "race.r5e.io",
      "kind" => "Bundle",
      "version" => "v1alpha1",
      "substrate" => "resource",
      "naming" => %{"mode" => "literal", "value" => "active"},
      "schema" => %{
        "required" => ["rule"],
        "properties" => %{"rule" => %{"type" => "string"}},
        "additionalProperties" => false
      },
      "predicates" => []
    }
  end

  defp citer_kind do
    %{
      "group" => "race.r5e.io",
      "kind" => "Citer",
      "version" => "v1alpha1",
      "substrate" => "resource",
      "naming" => %{"mode" => "caller"},
      "schema" => %{
        "required" => ["bundle"],
        "properties" => %{
          "bundle" => %{"type" => "ref", "ref" => %{"kind" => "race.r5e.io/v1alpha1/Bundle"}},
          "label" => %{"type" => "string"}
        },
        "additionalProperties" => false
      },
      "predicates" => []
    }
  end
end
