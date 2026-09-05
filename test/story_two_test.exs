defmodule R5e.StoryTwoTest do
  @moduledoc """
  Story 2 — *policy changes are on the record, and cannot race* — end to
  end, on a fresh kernel.

  A `PolicyBundle`-shaped resource (naming `literal`, one admissible name,
  superseded in place) governs the admission of something else. The
  engine reads it during `authorize` and reports the generation it read
  (spec/05 §7). Another actor supersedes the bundle in the window between
  that read and the append.

  The claim under test is not "the retry happened" — that is a
  mechanism — but what the mechanism buys: **no granted receipt on this
  chain cites a generation that had already been displaced at the seq the
  receipt was written at.** Without §7 that sentence is false and the
  record is the thing that says so: the receipt would cite bundle
  generation 9 at seq 12 while the chain also carries the supersession at
  seq 11, and a reader would have no way to tell whether the decision was
  made under the old rules or merely recorded as if it were.

  The bundle's own supersessions are held to the same rule, because the
  engine reads `active` when deciding whether `active` may be replaced —
  so this chain exercises the protocol on both the reader and the thing
  being read.
  """

  use ExUnit.Case, async: false

  @actor %{"id" => "person:thomas", "keyFingerprint" => "sha256:test-thomas"}
  @other %{"id" => "person:sam", "keyFingerprint" => "sha256:test-sam"}
  @bundle_ref "story.r5e.io/v1alpha1/PolicyBundleLike/active"

  defmodule Policy do
    @moduledoc false
    # The half of a real engine §7 needs and no more: it decides from an
    # admitted resource, and it reports which one it read and at what
    # generation. Everything else about a decision is §8's business.
    @behaviour R5e.Policy

    @impl true
    def authorize(_request) do
      ref = "story.r5e.io/v1alpha1/PolicyBundleLike/active"

      {generations, bundle} =
        case R5e.ResourceStore.get("story.r5e.io", "v1alpha1", "PolicyBundleLike", "active") do
          {:ok, entry, _lineage} -> {%{ref => entry["admissionSeq"]}, entry["specAddress"]}
          {:error, :not_found} -> {%{}, nil}
        end

      {:ok,
       %{
         "engine" => "story-two",
         "decision" => "allow",
         "bundle" => bundle,
         "bundleRef" => ref,
         "matched" => [],
         "generations" => generations
       }}
    end
  end

  test "a bundle superseded between authorize and record retries the decision, and no receipt cites a displaced generation" do
    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(bundle_kind())
      {:ok, _} = R5e.Vectors.admit_definition(governed_kind())

      {:ok, first} = admit(@actor, "PolicyBundleLike", "active", %{"rule" => "permit all"})

      previous = Application.get_env(:r5e, :policy)
      Application.put_env(:r5e, :policy, Policy)

      on_exit(fn ->
        Application.put_env(:r5e, :policy, previous || R5e.Policy.AllowAll)
        Application.put_env(:r5e, :before_record, nil)
      end)

      # Someone else replaces the bundle in the window between this
      # admission's authorize and its record. One supersession, so the
      # retry finds a settled world and commits.
      interleave_once(fn ->
        {:ok, receipt} =
          admit(@other, "PolicyBundleLike", "active", %{"rule" => "permit some"})

        receipt
      end)

      {:ok, governed} = admit(@actor, "Governed", "g1", %{"label" => "under the new rules"})

      [second] = Process.get(:story_two_interleaved)

      # The decision that landed is the decision the *current* bundle
      # produced: the first pass read `first`, was refused the append, and
      # the pass that committed read `second`.
      assert governed["policy"]["generations"] == %{@bundle_ref => second["seq"]}
      assert governed["policy"]["bundle"] == second["specAddress"]
      refute governed["policy"]["generations"] == %{@bundle_ref => first["seq"]}
      assert second["seq"] < governed["seq"]

      # And the record agrees with the receipt, which is the only reason
      # the receipt is worth anything.
      assert R5e.TestHelpers.payload_of(governed)["policy"] == governed["policy"]

      # The supersession itself is on the record as a supersession (§2,
      # A4): the displaced entry is kept and stamped, the new one names
      # what it displaced.
      displaced =
        R5e.ResourceStore.superseded("story.r5e.io", "v1alpha1", "PolicyBundleLike", "active")

      assert Enum.any?(displaced, &(&1["supersededBy"] == second["eventRef"]))

      # The claim, over the whole chain rather than this one admission.
      assert R5e.CommitInvariants.assert_no_stale_citation() > 0
    end)
  end

  test "the same holds when the bundle is superseded many times in a row" do
    R5e.Vectors.with_fresh_kernel(fn ->
      {:ok, _} = R5e.Vectors.admit_definition(bundle_kind())
      {:ok, _} = R5e.Vectors.admit_definition(governed_kind())
      {:ok, _} = admit(@actor, "PolicyBundleLike", "active", %{"rule" => "0"})

      previous = Application.get_env(:r5e, :policy)
      Application.put_env(:r5e, :policy, Policy)
      on_exit(fn -> Application.put_env(:r5e, :policy, previous || R5e.Policy.AllowAll) end)

      for n <- 1..5 do
        {:ok, _} = admit(@other, "PolicyBundleLike", "active", %{"rule" => "#{n}"})
        {:ok, _} = admit(@actor, "Governed", "g#{n}", %{"label" => "after #{n}"})
      end

      assert R5e.CommitInvariants.assert_no_stale_citation() > 0
    end)
  end

  # -- helpers -----------------------------------------------------------

  # `before_record` is the §7 seam (see `R5e.Admission`): it runs another
  # admission between authorize and record, which is the interleaving the
  # protocol is about, made deterministic rather than hoped for. The live
  # version of the same race is `R5e.CommitConcurrencyTest`.
  defp interleave_once(fun) do
    Process.put(:story_two_interleaved, [])

    Application.put_env(:r5e, :before_record, fn _request ->
      case Process.get(:story_two_interleaved) do
        [] -> Process.put(:story_two_interleaved, [fun.()])
        _already -> :ok
      end
    end)
  end

  defp admit(actor, kind, name, spec) do
    R5e.TestHelpers.admit_request(%{
      actor: actor,
      group: "story.r5e.io",
      version: "v1alpha1",
      kind: kind,
      name: name,
      spec: spec
    })
  end

  defp bundle_kind do
    %{
      "group" => "story.r5e.io",
      "kind" => "PolicyBundleLike",
      "version" => "v1alpha1",
      "substrate" => "resource",
      "naming" => %{"mode" => "literal", "value" => "active"},
      "description" => "One admissible name; admitting it is activation.",
      "schema" => %{
        "required" => ["rule"],
        "properties" => %{"rule" => %{"type" => "string"}},
        "additionalProperties" => false
      },
      "predicates" => []
    }
  end

  defp governed_kind do
    %{
      "group" => "story.r5e.io",
      "kind" => "Governed",
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
end
