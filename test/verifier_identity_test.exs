defmodule R5e.VerifierIdentityTest do
  @moduledoc """
  Spec 011 §9, checked the only way it can honestly be checked: against
  bundles this kernel actually exported.

  Every test builds a chain, exports it, and asks the verifier what it
  says — and where a finding is under test, it edits the *bundle* rather
  than the kernel, because a finding exists precisely for the case where
  the producer and the record disagree and no kernel would have written
  it.
  """

  use ExUnit.Case, async: false

  import R5e.TestHelpers

  @far "2099-01-01T00:00:00Z"
  @past "2020-01-01T00:00:00Z"

  setup do
    dest =
      Path.join(System.tmp_dir!(), "r5e-identity-bundle-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, dest: dest}
  end

  describe "the three lines (§9)" do
    test "a signed chain counts its signatures and its legacy payloads", %{dest: dest} do
      fresh(fn ->
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "SigProbe"}))
        {:ok, _} = admit("test.r5e.io", "v1alpha1", "SigProbe", "p1", %{"title" => "t"})

        {:ok, report} = verify(dest)
        line = checked(report, "signatures:")

        # Every admission on a chain this kernel wrote is signed, so S = T
        # and U is zero — which is what makes the legacy not-checked lines
        # false here, and they are absent.
        assert line =~ ~r/signatures: (\d+) of \1 admissions signed and verified/
        assert line =~ "0 legacy unsigned"
        refute Enum.any?(report.not_checked, &(&1 =~ "admissions are not signed"))
        refute Enum.any?(report.not_checked, &(&1 =~ "actor fingerprints are asserted"))
        assert report.findings == []

        # ...and the two lines the contract adds on every run.
        assert Enum.any?(report.not_checked, &(&1 =~ "wall-clock validity is not"))
        assert Enum.any?(report.not_checked, &(&1 =~ "self-declared"))
      end)
    end

    test "the endorsements line counts chains, citing admissions and cuts", %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "AuthProbe"}))
        {:ok, root} = endorse(:node, alice, kinds: ["*"])

        {:ok, _} =
          admit("test.r5e.io", "v1alpha1", "AuthProbe", "p1", %{"title" => "t"}, %{
            keys: [alice],
            authority: [root["eventRef"]]
          })

        {:ok, report} = verify(dest)
        assert checked(report, "endorsements:") =~ "1 chains cited across 1 admissions"
        assert checked(report, "endorsements:") =~ "0 resolved to a pinned root"
        assert checked(report, "endorsements:") =~ "0 cut"
        assert report.findings == []
      end)
    end

    test "a pinned root is counted as resolved, and pins never follow succession", %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        node = R5e.DSSE.local_key_id()
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "PinProbe"}))
        {:ok, root} = endorse(:node, alice, kinds: ["*"])

        {:ok, _} =
          admit("test.r5e.io", "v1alpha1", "PinProbe", "p1", %{"title" => "t"}, %{
            keys: [alice],
            authority: [root["eventRef"]]
          })

        {:ok, pinned} = verify(dest, trust: [%{"key" => node, "label" => "the node"}])
        assert checked(pinned, "endorsements:") =~ "1 resolved to a pinned root"

        # A pin for somebody else admits nothing, and the checkpoint line
        # goes back to saying the key is self-declared.
        {:ok, other} = verify(dest, trust: [%{"key" => R5e.Request.key_id(key_for("nobody"))}])
        assert checked(other, "endorsements:") =~ "0 resolved to a pinned root"
        assert Enum.any?(other.not_checked, &(&1 =~ "self-declared"))

        # Pinning the node key changes what the checkpoint line can say.
        assert Enum.any?(pinned.not_checked, &(&1 =~ "pinned by this reader"))
      end)
    end

    test "a pin whose kinds exclude the act does not admit the chain", %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        node = R5e.DSSE.local_key_id()
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "KindPinProbe"}))
        {:ok, root} = endorse(:node, alice, kinds: ["*"])

        {:ok, _} =
          admit("test.r5e.io", "v1alpha1", "KindPinProbe", "p1", %{"title" => "t"}, %{
            keys: [alice],
            authority: [root["eventRef"]]
          })

        pin = %{"key" => node, "kinds" => ["some.other/v1/Kind"]}
        {:ok, report} = verify(dest, trust: [pin])
        assert checked(report, "endorsements:") =~ "0 resolved to a pinned root"
      end)
    end

    test "the identities line counts profiles, badge users and badge-only keys", %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "IdProbe"}))

        # Alice publishes a profile and acts as herself.
        {:ok, _} =
          admit(
            "core.r5e.io",
            "v1",
            "Principal",
            R5e.Request.key_id(alice),
            %{
              "key" => R5e.Request.key_id(alice),
              "kind" => "person",
              "custody" => "self"
            },
            %{keys: [alice]}
          )

        {:ok, report} = verify(dest, posture: "house")
        line = checked(report, "identities:")
        assert line =~ "1 keys with self profiles"
        assert line =~ "0 keys acting under badges"
        assert line =~ "person 0, agent 0, org 0, instrument 0, service 0, mixed 0"
        assert line =~ "deployment declaration: none"
        assert line =~ "reader posture: house"
      end)
    end
  end

  describe "posture (§9)" do
    test "an admitted Badge makes --posture required, and the Kind alone does not",
         %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        bob = key_for("bob")

        # The Badge Kind is seeded on every chain; with no instance, no
        # posture is required.
        {:ok, no_badge} = verify(dest)
        assert checked(no_badge, "identities:") =~ "reader posture: not stated"

        {:ok, _} = badge(alice, bob, kinds: ["*"])
        dest2 = dest <> "-with-badge"
        on_exit(fn -> File.rm_rf(dest2) end)
        {:ok, ^dest2, _} = R5e.Export.run(dest2)

        assert {:error, message} = RecurseVerify.run(dest2)
        assert message =~ "--posture house|commons is required"
        assert {:ok, _} = RecurseVerify.run(dest2, posture: "house")
        assert {:error, _} = RecurseVerify.run(dest2, posture: "sideways")
      end)
    end

    test "badge-only-person fires under commons and only counts under house", %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        bob = key_for("bob")
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "BadgeProbe"}))
        {:ok, badge} = badge(alice, bob, kinds: ["*"])

        # Bob's only signed act as an actor cites the badge, and he has no
        # profile: badge-only.
        {:ok, _} =
          admit("test.r5e.io", "v1alpha1", "BadgeProbe", "p1", %{"title" => "t"}, %{
            keys: [bob],
            authority: [badge["eventRef"]]
          })

        {:ok, house} = verify(dest, posture: "house")
        assert checked(house, "identities:") =~ "1 keys acting only under badges"
        refute Enum.any?(house.findings, &String.starts_with?(&1, "badge-only-person:"))

        dest2 = dest <> "-commons"
        on_exit(fn -> File.rm_rf(dest2) end)
        {:ok, ^dest2, _} = R5e.Export.run(dest2)
        {:ok, commons} = RecurseVerify.run(dest2, posture: "commons")

        assert Enum.any?(commons.findings, &String.starts_with?(&1, "badge-only-person:"))
        assert checked(commons, "identities:") =~ "agent 1"
      end)
    end
  end

  describe "findings (§9)" do
    test "a tampered submittedTarget is a projection finding", %{dest: dest} do
      fresh(fn ->
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "ProjProbe"}))
        {:ok, receipt} = admit("test.r5e.io", "v1alpha1", "ProjProbe", "p1", %{"title" => "t"})
        {:ok, ^dest, _} = R5e.Export.run(dest)

        edit_payload(dest, receipt, fn payload ->
          put_in(payload, ["submittedTarget", "name"], "somebody-elses-name")
        end)

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 String.starts_with?(f, "projection:") and f =~ "the signed target names"
               end)
      end)
    end

    test "a tampered signature is a signature finding", %{dest: dest} do
      fresh(fn ->
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "SigTamper"}))
        {:ok, receipt} = admit("test.r5e.io", "v1alpha1", "SigTamper", "p1", %{"title" => "t"})
        {:ok, ^dest, _} = R5e.Export.run(dest)

        edit_payload(dest, receipt, fn payload ->
          update_in(payload, ["signed", "signatures"], fn [first | rest] ->
            {:ok, sig} = Base.decode64(first["sig"])
            <<head::binary-size(63), last>> = sig
            [%{first | "sig" => Base.encode64(head <> <<Bitwise.bxor(last, 1)>>)} | rest]
          end)
        end)

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 String.starts_with?(f, "signature:") and f =~ "does not verify"
               end)

        assert checked(report, "signatures:") =~ ~r/signatures: (\d+) of (\d+)/
      end)
    end

    test "a Revocation by a stranger is a revocation-actor finding, and the chain stands",
         %{dest: dest} do
      fresh(fn ->
        alice = key_for("alice")
        mallory = key_for("mallory")
        {:ok, _} = admit_kind(kind_spec(%{"kind" => "RevProbe"}))
        {:ok, root} = endorse(:node, alice, kinds: ["*"])

        {:ok, act} =
          admit("test.r5e.io", "v1alpha1", "RevProbe", "p1", %{"title" => "t"}, %{
            keys: [alice],
            authority: [root["eventRef"]]
          })

        # The kernel refuses this at `resolve: sameActor`, so the only way
        # a bundle carries one is if somebody put it there.
        {:denied, _} =
          admit_request(%{
            keys: [mallory],
            group: "core.r5e.io",
            version: "v1",
            kind: "Revocation",
            name: nil,
            spec: %{"revokes" => %{"$ref" => root["eventRef"]}}
          })

        {:ok, ^dest, _} = R5e.Export.run(dest)
        inject_revocation(dest, root["eventRef"], R5e.Request.key_id(mallory))

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 String.starts_with?(f, "revocation-actor:") and f =~ "withdraws nothing"
               end)

        # ...and the chain the forged Revocation aimed at is still not cut.
        assert checked(report, "endorsements:") =~ "0 cut"
        assert act["outcome"] == "admitted"
      end)
    end

    test "an admitted PolicyShape citing actor.keyFingerprint is a stale-shape finding",
         %{dest: dest} do
      fresh(fn ->
        {:ok, _} =
          admit_kind(
            kind_spec(%{
              "group" => "gateway.r5e.io",
              "version" => "v1alpha1",
              "kind" => "PolicyShape",
              "schema" => %{
                "required" => ["resourceId"],
                "properties" => %{
                  "action" => %{"type" => "string"},
                  "resourceType" => %{"type" => "string"},
                  "resourceId" => %{"type" => "string"},
                  "description" => %{"type" => "string"}
                },
                "additionalProperties" => false
              }
            })
          )

        {:ok, _} =
          admit("gateway.r5e.io", "v1alpha1", "PolicyShape", "s1", %{
            "action" => "admit",
            "resourceType" => "@kind",
            "resourceId" => "@actor.keyFingerprint"
          })

        {:ok, report} = verify(dest)

        assert Enum.any?(report.findings, fn f ->
                 String.starts_with?(f, "stale-shape:") and f =~ "KS-7"
               end)
      end)
    end
  end

  describe "trust files (§9)" do
    test "a duplicate pin is unusable input, and the schema is closed" do
      assert {:error, message} =
               RecurseVerify.Trust.load(["k", "k=label"], nil)

      assert message =~ "pinned twice"

      path = Path.join(System.tmp_dir!(), "trust-#{System.unique_integer([:positive])}.json")
      on_exit(fn -> File.rm(path) end)

      File.write!(path, Jason.encode!([%{"key" => "k", "colour" => "blue"}]))
      assert {:error, reason} = RecurseVerify.Trust.load([], path)
      assert reason =~ "undeclared key"

      File.write!(path, Jason.encode!([%{"key" => "k", "label" => "ok", "kinds" => ["g/v/K"]}]))
      assert {:ok, [%{"key" => "k"}]} = RecurseVerify.Trust.load([], path)
    end
  end

  # -- harness -----------------------------------------------------------

  defp fresh(fun), do: R5e.Vectors.with_fresh_kernel(fun)

  # Export once per destination: a bundle is a snapshot, and asking the
  # same snapshot two questions is the point of the `opts`.
  defp verify(dest, opts \\ []) do
    unless File.dir?(dest), do: {:ok, ^dest, _} = R5e.Export.run(dest)
    RecurseVerify.run(dest, opts)
  end

  defp checked(report, prefix),
    do: Enum.find(report.checked, "", &String.starts_with?(&1, prefix))

  defp endorse(issuer, subject, opts) do
    R5e.Bootstrap.endorse_role(R5e.Request.public_key(subject), opts[:role] || "probe",
      kinds: opts[:kinds],
      may_issue: Keyword.get(opts, :may_issue, false)
    )
    |> tap(fn _ -> issuer end)
  end

  defp badge(issuer, subject, opts) do
    admit_request(%{
      keys: [issuer, subject],
      group: "core.r5e.io",
      version: "v1",
      kind: "Badge",
      name: nil,
      spec: %{
        "subject" => R5e.Request.key_id(subject),
        "subjectKey" => %{
          "algorithm" => "ed25519",
          "bytes" => Base.encode64(R5e.Request.public_key(subject))
        },
        "kinds" => opts[:kinds],
        "mayIssue" => false,
        "subjectKind" => opts[:subject_kind] || "agent",
        "notBefore" => @past,
        "notAfter" => @far
      }
    })
  end

  # Rewrite one payload inside an exported bundle. The event hash still
  # names the old bytes, so this is exactly the "the producer and the
  # record disagree" case the findings exist for — the payload is
  # rewritten, re-addressed, the chain relinked and the checkpoint
  # re-signed, which is what a forging *node* can do. Writing the new
  # bytes over the old file would only make the payload unreadable
  # (spec/07 §1.6) and every finding below unreachable.
  defp edit_payload(dest, receipt, fun) do
    event = Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))
    path = Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])
    payload = path |> File.read!() |> Jason.decode!()
    R5e.Vectors.rebuild(dest, event, fun.(payload))
  end

  # Append an unauthenticated Revocation to a copy of the bundle's log:
  # what a hostile assembler can do, and what the verifier is for.
  defp inject_revocation(dest, target, actor) do
    log = Path.join(dest, "log.jsonl")
    events = R5e.Chain.read_log(log) |> elem(1)
    last = List.last(events)

    payload = %{
      "actor" => %{"id" => actor},
      "target" => %{
        "group" => "core.r5e.io",
        "version" => "v1",
        "kind" => "Revocation",
        "name" => "injected"
      },
      "outcome" => "admitted",
      "identity" => "signed",
      "spec" => %{"revokes" => %{"$ref" => target}},
      "resolvedRefs" => [],
      "scopeDefaulted" => false
    }

    bytes = R5e.Canonical.encode(payload)
    address = R5e.Canonical.hash_bytes(bytes)
    object = Path.join([dest, "cas", R5e.CAS.relative_path(address)])
    File.mkdir_p!(Path.dirname(object))
    File.write!(object, bytes)

    event =
      R5e.Chain.build_event(last["seq"] + 1, last["hash"], "admission.granted", address)

    File.write!(log, File.read!(log) <> Jason.encode!(event) <> "\n")
  end
end
