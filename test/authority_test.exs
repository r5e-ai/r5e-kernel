defmodule R5e.AuthorityTest do
  @moduledoc """
  The two pure pieces of §0 and §5, asked directly: the `kinds` lattice and
  the succession relation. Everything about how they are *used* is in the
  conformance vectors; what is here is the algebra those vectors rest on,
  where a mistake would be invisible behind a passing admission.
  """

  use ExUnit.Case, async: false

  alias R5e.Authority
  alias R5e.Succession

  describe "the kinds lattice (§5)" do
    test "the normal form is deduplicated, sorted, and collapses to star" do
      assert Authority.normal_form(["b/v1/B", "a/v1/A", "b/v1/B"]) == ["a/v1/A", "b/v1/B"]
      assert Authority.normal_form(["*", "a/v1/A"]) == ["*"]
      assert Authority.normal_form(["*"]) == ["*"]
      assert Authority.normal_form([]) == []
      assert Authority.normal_form(nil) == []
    end

    test "star is top, and nothing but star is inside it" do
      assert Authority.covered?(["a/v1/A"], ["*"])
      assert Authority.covered?(["*"], ["*"])
      assert Authority.covered?(["a/v1/A", "b/v1/B"], ["*", "z/v1/Z"])
      refute Authority.covered?(["*"], ["a/v1/A"])
      refute Authority.covered?(["a/v1/A"], ["b/v1/B"])
    end

    test "an empty grant covers nothing, and an empty ask is inside anything" do
      refute Authority.covered?(["a/v1/A"], [])
      assert Authority.covered?([], ["a/v1/A"])
    end
  end

  describe "the succession relation (§0)" do
    setup do
      R5e.Vectors.with_fresh_kernel(fn ->
        :ok
      end)

      previous = Application.fetch_env!(:r5e, :data_dir)
      dir = Path.join(System.tmp_dir!(), "r5e-succession-#{System.unique_integer([:positive])}")

      :ok = Application.stop(:r5e)
      Application.put_env(:r5e, :data_dir, dir)
      {:ok, _} = Application.ensure_all_started(:r5e)

      on_exit(fn ->
        Application.stop(:r5e)
        Application.put_env(:r5e, :data_dir, previous)
        {:ok, _} = Application.ensure_all_started(:r5e)
        File.rm_rf(dir)
      end)

      keys = for n <- 1..4, into: %{}, do: {n, R5e.Vectors.key(n)}
      {:ok, keys: keys, ids: Map.new(keys, fn {n, k} -> {n, R5e.Request.key_id(k)} end)}
    end

    test "matches is reflexive, follows the path, and never runs backward", ctx do
      succeed(ctx, 1, 2)
      succeed(ctx, 2, 3)
      s = Succession.next_seq()

      # Reflexive.
      assert Succession.matches(ctx.ids[1], ctx.ids[1], s)

      # Forward, one hop and two.
      assert Succession.matches(ctx.ids[1], ctx.ids[2], s)
      assert Succession.matches(ctx.ids[1], ctx.ids[3], s)

      # Never backward: the successor's authority is not the predecessor's.
      refute Succession.matches(ctx.ids[3], ctx.ids[1], s)
      refute Succession.matches(ctx.ids[2], ctx.ids[1], s)

      # And never sideways.
      refute Succession.matches(ctx.ids[4], ctx.ids[3], s)
    end

    test "head is the terminal successor, and the whole path is ancestry", ctx do
      succeed(ctx, 1, 2)
      succeed(ctx, 2, 3)
      s = Succession.next_seq()

      assert Succession.head(ctx.ids[1], s) == ctx.ids[3]
      assert Succession.head(ctx.ids[3], s) == ctx.ids[3]
      assert Succession.head(ctx.ids[4], s) == ctx.ids[4]
      assert Succession.ancestors(ctx.ids[3], s) == [ctx.ids[2], ctx.ids[1]]
      assert Succession.ancestors(ctx.ids[1], s) == []
    end

    test "the relation is answered *as of* a sequence", ctx do
      before = Succession.next_seq()
      succeed(ctx, 1, 2)
      after_edge = Succession.next_seq()

      # The edge did not exist at the seq before it was admitted, which is
      # what lets the verifier ask the same question at any position.
      refute Succession.matches(ctx.ids[1], ctx.ids[2], before)
      assert Succession.matches(ctx.ids[1], ctx.ids[2], after_edge)
    end

    test "revoking an edge reopens both slots, for every seq after the revocation", ctx do
      {:ok, edge} = succeed(ctx, 1, 2)
      version = Succession.version()

      # The successor may withdraw the edge that made it the successor.
      # Authorization therefore reads the relation immediately before the
      # Revocation and only removes the edge after recording that act.
      revoke(ctx, 2, edge["eventRef"])
      s = Succession.next_seq()

      # §0 (r4.3): the edge is still live **at** the Revocation's own seq,
      # and that is load-bearing rather than an off-by-one. §0 asks
      # `matches(target.actor, revoker, R.seq)` of a Revocation, so a
      # successor withdrawing the very edge that made it the successor is
      # valid exactly because the edge still stands at the position the
      # Revocation occupies. Kill it one seq earlier and only the
      # predecessor could ever undo a succession.
      assert Succession.matches(ctx.ids[1], ctx.ids[2], s - 1)

      refute Succession.matches(ctx.ids[1], ctx.ids[2], s)
      assert Succession.head(ctx.ids[1], s) == ctx.ids[1]

      # Both slots: the predecessor may name another successor, and the
      # successor may be named by another predecessor.
      assert Succession.check_edge(ctx.ids[1], ctx.ids[3], s) == :ok
      assert Succession.check_edge(ctx.ids[3], ctx.ids[2], s) == :ok

      # §6: the version moved twice — once for the Succession, once for
      # the Revocation of it.
      assert Succession.version() > version
    end

    test "the node key is the terminal successor of the key that signed event 1", ctx do
      assert R5e.DSSE.node_key_id() == R5e.DSSE.local_key_id()

      # Succeed the node key itself, and §0's node key moves with it while
      # the key this process holds does not.
      node = R5e.DSSE.local_key_id()
      {:ok, _} = succeed_keys(node, ctx.keys[2])

      assert R5e.DSSE.node_key_id() == ctx.ids[2]
      assert R5e.DSSE.local_key_id() == node
    end
  end

  # Debt #45, pinned as a **unit** test of the shared walk rather than as a
  # bundle vector, because the scenario needs an event **between** two the
  # kernel wrote: a bundle's log is hash-chained and its head is signed, so
  # splicing one in mid-chain needs the node's own key. That is a
  # compromised node, not the hostile assembler the runner's `inject` models
  # (append-only, which a forger with the bundle really can do). The index
  # is a plain value, so the scenario can be built exactly.
  #
  describe "a forged Revocation of a Succession (debt #45)" do
    test "an unauthorized revocation leaves the preceding relation intact" do
      a = "key:ed25519:sha256:" <> String.duplicate("a", 64)
      b = "key:ed25519:sha256:" <> String.duplicate("b", 64)
      stranger = "key:ed25519:sha256:" <> String.duplicate("c", 64)
      subject = "key:ed25519:sha256:" <> String.duplicate("d", 64)

      index =
        RecurseVerify.Authority.build([
          # 5 — A endorses somebody.
          endorsement(5, a, subject),
          # 6 — A succeeds to B.
          succession(6, a, b),
          # 7 — a Revocation of that Succession by a stranger. No kernel
          #     would admit it: `resolve: sameActor` refuses it.
          revocation(7, stranger, ref(6)),
          # 8 — B, A's successor, withdraws the endorsement A made. This
          #     one is honest and a kernel did admit it.
          revocation(8, b, ref(5))
        ])

      walk = RecurseVerify.Authority.effective(index, ref(5), 9, "2026-09-02T00:00:00Z")

      # The forgery withdraws nothing. The A→B edge still stands at seq 8,
      # so B matches A and its genuine withdrawal takes effect.
      refute walk.ok
      assert walk.reason == "revoked at 8"

      assert RecurseVerify.Authority.matches(index, a, b, 8)
      assert RecurseVerify.Authority.matches(index, a, b, 7)
    end

    defp ref(seq), do: "event:sha256:" <> String.duplicate(Integer.to_string(seq), 64)

    defp event(seq),
      do: %{
        "seq" => seq,
        "hash" => "sha256:" <> String.duplicate(Integer.to_string(seq), 64),
        "ts" => "2026-09-02T00:00:00Z"
      }

    defp payload(kind, actor, spec) do
      %{
        "outcome" => "admitted",
        "actor" => %{"id" => actor},
        "target" => %{"group" => "core.r5e.io", "version" => "v1", "kind" => kind},
        "spec" => spec
      }
    end

    defp endorsement(seq, actor, subject) do
      {event(seq),
       payload("Endorsement", actor, %{
         "subject" => subject,
         "kinds" => ["*"],
         "mayIssue" => false,
         "notBefore" => "2020-01-01T00:00:00Z",
         "notAfter" => "2099-01-01T00:00:00Z"
       })}
    end

    defp succession(seq, predecessor, successor),
      do:
        {event(seq),
         payload("Succession", predecessor, %{
           "predecessor" => predecessor,
           "successor" => successor
         })}

    defp revocation(seq, actor, target),
      do: {event(seq), payload("Revocation", actor, %{"revokes" => %{"$ref" => target}})}
  end

  # §11/KS-7, the kernel half: what `authorize` is handed about the actor.
  # The vectors pin `resolvedAuthority` on the *record*; this asks the
  # request itself, because `authorityRefs` and `authorityRoots` exist for
  # the engine and are not written to the payload under those names — a
  # regression in either would be invisible to every vector.
  describe "the policy view of authority (§11)" do
    setup do
      previous = Application.get_env(:r5e, :policy)
      Application.put_env(:r5e, :policy, R5e.AuthorityTest.CapturingPolicy)
      on_exit(fn -> Application.put_env(:r5e, :policy, previous) end)
      :ok
    end

    test "an actor citing nothing is handed an empty list, not a missing key" do
      R5e.Vectors.with_fresh_kernel(fn ->
        {:ok, _receipt} = admit_note(1, [])
        request = Process.get(:captured_request)

        assert Map.fetch(request, :authority_refs) == {:ok, []}
        assert Map.fetch(request, :authority_roots) == {:ok, []}
        assert request[:resolved_authority] == []
      end)
    end

    test "the refs are the cited ones sorted, and the roots are their root actors" do
      R5e.Vectors.with_fresh_kernel(fn ->
        one = endorse(1, 2)
        two = endorse(1, 2)
        cited = Enum.sort([one, two])

        {:ok, _receipt} = admit_note(2, cited)
        request = Process.get(:captured_request)

        assert request[:authority_refs] == cited
        assert request[:authority_roots] == [R5e.Request.key_id(R5e.Vectors.key(1))]

        # And the whole derivation is beside them, in the order the
        # request named its authority rather than sorted.
        assert Enum.map(request[:resolved_authority], & &1["value"]) == cited
      end)
    end
  end

  defp admit_note(signer, authority) do
    {:ok, _} =
      R5e.TestHelpers.admit_request(%{
        keys: [R5e.Vectors.key(1)],
        group: "core.r5e.io",
        version: "v1",
        kind: "KindDefinition",
        name: nil,
        spec: note_kind()
      })

    R5e.TestHelpers.admit_request(%{
      keys: [R5e.Vectors.key(signer)],
      group: "vectors.r5e.io",
      version: "v1alpha1",
      kind: "Note",
      name: "n#{System.unique_integer([:positive])}",
      spec: %{"body" => "under authority"},
      authority: authority
    })
  end

  defp note_kind do
    %{
      "group" => "vectors.r5e.io",
      "kind" => "Note",
      "version" => "v1alpha1",
      "substrate" => "resource",
      "naming" => %{"mode" => "caller"},
      "description" => "A one-field resource, so an authority test has something to admit.",
      "schema" => %{
        "required" => ["body"],
        "properties" => %{"body" => %{"type" => "string"}},
        "additionalProperties" => false
      },
      "predicates" => []
    }
  end

  defp endorse(issuer, subject) do
    {:ok, receipt} =
      R5e.TestHelpers.admit_request(%{
        keys: [R5e.Vectors.key(issuer)],
        group: "core.r5e.io",
        version: "v1",
        kind: "Endorsement",
        name: nil,
        spec: %{
          "subject" => R5e.Request.key_id(R5e.Vectors.key(subject)),
          "subjectKey" => %{
            "algorithm" => "ed25519",
            "bytes" => Base.encode64(R5e.Request.public_key(R5e.Vectors.key(subject)))
          },
          "kinds" => ["*"],
          "mayIssue" => true,
          "notBefore" => "2020-01-01T00:00:00Z",
          "notAfter" => "2030-01-01T00:00:00Z"
        }
      })

    receipt["eventRef"]
  end

  defp succeed(ctx, from, to), do: succeed_keys(ctx.ids[from], ctx.keys[to], ctx.keys[from])

  defp succeed_keys(predecessor_id, successor, predecessor \\ :node) do
    R5e.TestHelpers.admit_request(%{
      keys: [predecessor, successor],
      group: "core.r5e.io",
      version: "v1",
      kind: "Succession",
      name: nil,
      spec: %{
        "predecessor" => predecessor_id,
        "successor" => R5e.Request.key_id(successor),
        "successorKey" => %{
          "algorithm" => "ed25519",
          "bytes" => Base.encode64(R5e.Request.public_key(successor))
        }
      }
    })
  end

  defp revoke(ctx, signer, target) do
    {:ok, _} =
      R5e.TestHelpers.admit_request(%{
        keys: [ctx.keys[signer]],
        group: "core.r5e.io",
        version: "v1",
        kind: "Revocation",
        name: nil,
        spec: %{"revokes" => %{"$ref" => target}}
      })
  end
end

defmodule R5e.AuthorityTest.CapturingPolicy do
  @moduledoc false
  # Allows everything and keeps the request it was handed, so a test can
  # ask what the gate actually settled before `authorize` ran. It runs in
  # the admitting process, so the process dictionary is the whole of it.
  @behaviour R5e.Policy

  @impl true
  def authorize(request) do
    Process.put(:captured_request, request)

    {:ok,
     %{
       "engine" => "capturing",
       "decision" => "allow",
       "bundle" => nil,
       "bundleRef" => nil,
       "matched" => []
     }}
  end
end
