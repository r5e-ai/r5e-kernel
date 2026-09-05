defmodule R5e.CommitTest do
  @moduledoc """
  The parts of spec/05 §7 a conformance vector cannot say, because they
  are about what is on the chain and in the store *after* an admission
  rather than about the admission's outcome: the legible gap a halt
  leaves, the fact that a halted node keeps recording denials, and the
  retry budget's two ends.
  """

  use ExUnit.Case, async: false

  @actor %{"id" => "test:alice", "keyFingerprint" => "sha256:test-alice"}

  defmodule ReadingPolicy do
    @moduledoc false
    @behaviour R5e.Policy

    @impl true
    def authorize(_request) do
      generations =
        case R5e.ResourceStore.get("commit.r5e.io", "v1alpha1", "Bundle", "active") do
          {:ok, entry, _} -> %{"commit.r5e.io/v1alpha1/Bundle/active" => entry["admissionSeq"]}
          _ -> %{}
        end

      {:ok,
       %{
         "engine" => "commit-test",
         "decision" => "allow",
         "bundle" => nil,
         "bundleRef" => nil,
         "matched" => [],
         "generations" => generations
       }}
    end
  end

  setup do
    on_exit(fn ->
      Application.put_env(:r5e, :before_record, nil)
      Application.put_env(:r5e, :substrate_hook, nil)
      Application.put_env(:r5e, :policy, R5e.Policy.AllowAll)
      Application.delete_env(:r5e, :commit_retries)
    end)

    :ok
  end

  test "a post-record substrate failure leaves the gap the record can name, and halts the node" do
    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(thing_kind())

      Application.put_env(:r5e, :substrate_hook, fn request ->
        if request[:name] == "boom",
          do: raise(File.Error, reason: :eio, action: "write to", path: "/dev/null")
      end)

      # The caller is owed the failure: the act is on the chain, so a
      # denial receipt here would contradict the record.
      assert_raise File.Error, fn -> admit("boom", %{"label" => "the one that fails"}) end

      # The gap, and it is legible from the record alone: the chain says
      # this admission was granted; the store has no entry for it.
      last = List.last(R5e.Log.events())
      payload = decode(last)
      assert payload["outcome"] == "admitted"
      assert payload["target"]["name"] == "boom"

      assert R5e.ResourceStore.get("commit.r5e.io", "v1alpha1", "Thing", "boom") ==
               {:error, :not_found}

      assert R5e.Log.halted() =~ "halted: the substrate write for the granted admission at seq"

      # Every later granted admission is refused at `record`, and the
      # refusal is recorded: refusing to admit is not refusing to answer.
      before = length(R5e.Log.events())
      {:denied, receipt} = admit("after", %{"label" => "submitted while halted"})
      assert String.starts_with?(receipt["reason"], "record: halted: ")
      assert length(R5e.Log.events()) == before + 1
      assert decode(List.last(R5e.Log.events()))["outcome"] == "denied"

      # A denial that would have been denied anyway still denies at its
      # own stage: the halt is checked at `record`, not before it.
      {:denied, structural} = admit("bad", %{"nope" => true})
      assert String.starts_with?(structural["reason"], "validateStructure: ")

      # Replay is what makes the views agree with the chain again — and
      # the entry the failed write never made is there afterwards,
      # because the log had it all along.
      R5e.Bootstrap.replay()
      refute R5e.Log.halted()
      assert {:ok, entry, _} = R5e.ResourceStore.get("commit.r5e.io", "v1alpha1", "Thing", "boom")
      assert entry["spec"] == %{"label" => "the one that fails"}

      Application.put_env(:r5e, :substrate_hook, nil)
      assert {:ok, _} = admit("later", %{"label" => "after replay"})
    end)
  end

  test "commit_retries: 0 denies on the first mismatch, and the denial is itself appended" do
    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(bundle_kind())
      {:ok, _} = R5e.Vectors.admit_definition(thing_kind())
      {:ok, _} = admit_bundle("first")

      Application.put_env(:r5e, :policy, ReadingPolicy)
      Application.put_env(:r5e, :commit_retries, 0)
      attempts = interleave(fn -> admit_bundle("second") end, 99)

      before = length(R5e.Log.events())
      {:denied, receipt} = admit("t", %{"label" => "x"})

      assert receipt["reason"] =~
               "record: contended: the policy engine read " <>
                 "commit.r5e.io/v1alpha1/Bundle/active at generation"

      assert Agent.get(attempts, & &1) == 1, "with a budget of 0 there is exactly one attempt"

      # The denial appended — it carries no captured generations, so
      # nothing can contend it — and it is on the chain after the
      # supersession the hook performed.
      assert length(R5e.Log.events()) == before + 2
      assert decode(List.last(R5e.Log.events()))["reason"] == receipt["reason"]
    end)
  end

  test "the retry re-asks the policy, so the decision that lands is the one the current state produced" do
    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(bundle_kind())
      {:ok, _} = R5e.Vectors.admit_definition(thing_kind())
      {:ok, _} = admit_bundle("first")

      Application.put_env(:r5e, :policy, ReadingPolicy)
      attempts = interleave(fn -> admit_bundle("second") end, 1)

      {:ok, receipt} = admit("t", %{"label" => "x"})
      assert Agent.get(attempts, & &1) == 2

      {:ok, bundle, _} = R5e.ResourceStore.get("commit.r5e.io", "v1alpha1", "Bundle", "active")

      assert receipt["policy"]["generations"] == %{
               "commit.r5e.io/v1alpha1/Bundle/active" => bundle["admissionSeq"]
             }
    end)
  end

  test "an engine that reports no generations is never contended" do
    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(bundle_kind())
      {:ok, _} = R5e.Vectors.admit_definition(thing_kind())
      {:ok, _} = admit_bundle("first")

      # AllowAll reports `%{}` — a constant is not a read — so the same
      # interleaving that contends the reading policy above cannot touch
      # this admission.
      Application.put_env(:r5e, :commit_retries, 0)
      attempts = interleave(fn -> admit_bundle("second") end, 99)

      assert {:ok, receipt} = admit("t", %{"label" => "x"})
      assert receipt["policy"]["generations"] == %{}
      assert Agent.get(attempts, & &1) == 1
    end)
  end

  test "capture/2 keeps only what a later admission could actually move" do
    manifest = [
      %{"path" => "/a", "class" => "kind", "value" => "g/v/K/n", "generation" => 7},
      %{"path" => "/b", "class" => "bytes", "value" => "bytes:sha256:00"},
      %{"path" => "/c", "class" => "event", "value" => "event:sha256:00", "seq" => 3}
    ]

    capture =
      R5e.Commit.capture(
        %{resolved: manifest, spec: %{}},
        %{"generations" => %{"g/v/K/n" => 7, "g/v/K/m" => "not a seq"}}
      )

    # A `bytes:` address is immutable and an event is a position: neither
    # can move, so neither is captured. Only the kind ref and the policy's
    # integer generation are.
    assert capture["kinds"] == [%{"ref" => "g/v/K/n", "generation" => 7}]
    assert capture["policy"] == %{"g/v/K/n" => 7}
    assert capture["anchors"] == []
    refute R5e.Commit.empty?(capture)
    assert R5e.Commit.empty?(R5e.Commit.capture(%{resolved: [], spec: %{}}, %{}))
  end

  # -- helpers -----------------------------------------------------------

  defp interleave(fun, repeat) do
    {:ok, attempts} = Agent.start_link(fn -> 0 end)

    Application.put_env(:r5e, :before_record, fn _request ->
      n = Agent.get_and_update(attempts, &{&1 + 1, &1 + 1})
      if n <= repeat, do: fun.()
    end)

    attempts
  end

  defp admit(name, spec), do: submit("Thing", name, spec)
  defp admit_bundle(rule), do: submit("Bundle", "active", %{"rule" => rule})

  defp submit(kind, name, spec) do
    R5e.TestHelpers.admit_request(%{
      actor: @actor,
      group: "commit.r5e.io",
      version: "v1alpha1",
      kind: kind,
      name: name,
      spec: spec
    })
  end

  defp decode(event) do
    {:ok, bytes} = R5e.CAS.get(event["payload"])
    Jason.decode!(bytes)
  end

  defp thing_kind do
    %{
      "group" => "commit.r5e.io",
      "kind" => "Thing",
      "version" => "v1alpha1",
      "substrate" => "resource",
      "naming" => %{"mode" => "caller"},
      "schema" => %{
        "required" => [],
        "properties" => %{"label" => %{"type" => "string"}},
        "additionalProperties" => false
      },
      "predicates" => []
    }
  end

  defp bundle_kind do
    %{
      "group" => "commit.r5e.io",
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
end
