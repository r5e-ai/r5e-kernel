defmodule R5e.VerifierTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  # Each test exports a chain of its own. The verifier reads a whole
  # bundle, so a bundle built from the suite's shared kernel would carry
  # whatever any other test happened to admit — including a receipt citing
  # a policy object that does not exist, which is a finding, correctly, and
  # has nothing to do with what is under test here.
  setup do
    dest =
      Path.join(
        System.tmp_dir!(),
        "r5e-bundle-#{System.unique_integer([:positive])}"
      )

    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, dest: dest}
  end

  defp fresh(fun), do: R5e.Vectors.with_fresh_kernel(fun)

  test "an intact bundle: chain checked, scopes printed, gaps none, never a bare 'valid'",
       %{dest: dest} do
    fresh(fn ->
      {:ok, _} = admit_kind(kind_spec(%{"kind" => "BundleProbe"}))
      {:ok, _} = admit("test.r5e.io", "v1alpha1", "BundleProbe", "p1", %{"title" => "t"})

      {:ok, ^dest, _manifest} = R5e.Export.run(dest)
      {:ok, report} = RecurseVerify.run(dest)

      assert report.findings == []
      assert Enum.any?(report.checked, &(&1 =~ "chain: intact"))
      assert Enum.any?(report.checked, &(&1 =~ "checkpoint signature: verified"))
      assert Enum.any?(report.checked, &(&1 =~ "NOT the key holder's identity"))
      assert Enum.any?(report.checked, &(&1 =~ "merkle: root rebuilt"))
      assert Enum.any?(report.checked, &(&1 =~ "inclusion proofs generated and verified"))

      output = RecurseVerify.format(report)
      assert output =~ "not checked"
      assert output =~ "does NOT claim"
      # Doctrine: no unqualified verdict.
      refute output =~ ~r/^\s*valid\s*$/im
    end)
  end

  test "a missing payload in the bundle is reported as a gap finding", %{dest: dest} do
    fresh(fn ->
      {:ok, receipt} = admit_kind(kind_spec(%{"kind" => "GapProbe"}))
      {:ok, ^dest, _} = R5e.Export.run(dest)

      # Remove the CAS object for the GapProbe admission's payload.
      event = Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))
      victim = Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])
      File.rm!(victim)

      {:ok, report} = RecurseVerify.run(dest)

      assert Enum.any?(report.findings, fn f ->
               f =~ "gap:" and f =~ event["payload"] and f =~ "seq #{event["seq"]}"
             end)

      # The chain itself is still intact — the verifier says both things.
      assert Enum.any?(report.checked, &(&1 =~ "chain: intact"))
    end)
  end

  test "a tampered log line in the bundle is reported as tamper", %{dest: dest} do
    fresh(fn ->
      {:ok, _} = admit_kind(kind_spec(%{"kind" => "TamperProbe"}))
      {:ok, ^dest, _} = R5e.Export.run(dest)

      log_path = Path.join(dest, "log.jsonl")
      lines = log_path |> File.read!() |> String.split("\n", trim: true)
      middle = div(length(lines), 2)

      tampered_line =
        lines
        |> Enum.at(middle)
        |> Jason.decode!()
        |> Map.put("kind", "admission.granted.rewritten")
        |> Jason.encode!()

      File.write!(log_path, lines |> List.replace_at(middle, tampered_line) |> Enum.join("\n"))

      {:ok, report} = RecurseVerify.run(dest)
      assert Enum.any?(report.findings, &(&1 =~ "tamper:"))
    end)
  end

  describe "refs (spec/05 §4, §10)" do
    test "an intact bundle re-derives every manifest entry", %{dest: dest} do
      with_probe(dest, fn %{citing: citing} ->
        {:ok, report} = RecurseVerify.run(dest)

        assert report.findings == []

        line = Enum.find(report.checked, &String.starts_with?(&1, "refs:"))
        assert line =~ "2 typed refs recorded across 1/"
        assert line =~ "(bytes 1, kind 1)"
        assert line =~ "every one re-derived from this bundle"

        # The manifest the verifier re-derived is the one the caller was handed.
        assert length(citing["resolvedRefs"]) == 2
      end)
    end

    test "a ref target's payload, rewritten, no longer matches the recorded specAddress",
         %{dest: dest} do
      with_probe(dest, fn %{base: base} ->
        # A forging node, in two steps, because one is not enough: the
        # payload is re-addressed and the chain relinked (writing over
        # the old file would leave a payload that does not hash to its
        # address, which is not read at all — spec/07 §1.6), and *then*
        # the citing manifest is pointed at the event's new hash. Without
        # the second step the citation simply names no event on this
        # chain, and this finding — a spec that is read and disagrees
        # with the address recorded for it — stays out of reach.
        event = Enum.find(R5e.Log.events(), &(&1["hash"] == base["event"]))

        payload =
          dest |> event_payload_path(base) |> File.read!() |> Jason.decode!()

        R5e.Vectors.rebuild(
          dest,
          event,
          put_in(payload, ["spec", "label"], "not what was admitted")
        )

        repoint(dest, event["seq"], base["eventRef"])

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 f =~ "refs:" and f =~ "records specAddress" and
                   f =~ "but that admission's spec hashes to"
               end)
      end)
    end

    test "a deleted bytes object is a ref finding, not only a missing file", %{dest: dest} do
      with_probe(dest, fn %{blob: blob} ->
        File.rm!(Path.join([dest, "cas", R5e.CAS.relative_path(blob)]))

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 f =~ "refs:" and f =~ blob and f =~ "missing from this bundle"
               end)
      end)
    end

    test "a recorded generation that is not the target's seq is a finding", %{dest: dest} do
      with_probe(dest, fn _ ->
        # A kernel cannot mint a forward reference — an unappended event has
        # no hash to cite — so §4's "at a lower seq" is only ever falsifiable
        # offline, against a manifest that claims a position the chain
        # contradicts. That is what this rewrites.
        rewrite_manifest(dest, fn entry -> %{entry | "generation" => 99} end)

        {:ok, report} = RecurseVerify.run(dest)
        assert Enum.any?(report.findings, &(&1 =~ "records generation 99"))
      end)
    end

    test "a $ref with no manifest entry is a finding even though the record looks whole",
         %{dest: dest} do
      with_probe(dest, fn _ ->
        rewrite_payload(dest, fn payload -> Map.put(payload, "resolvedRefs", []) end)

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(
                 report.findings,
                 &(&1 =~ "unresolved ref recorded without a manifest entry")
               )
      end)
    end

    test "a manifest entry naming the wrong CasObject admission is a finding", %{dest: dest} do
      with_probe(dest, fn _ ->
        # The kernel fills `casObjectEvent` from its own index; offline,
        # the backing admission is found on the chain and the recorded
        # value is checked against it, so a manifest that names a
        # plausible-looking event nobody admitted these bytes with fails.
        rewrite_payload(dest, fn payload ->
          Map.update!(payload, "resolvedRefs", fn entries ->
            Enum.map(entries, fn
              %{"class" => "bytes"} = entry ->
                %{entry | "casObjectEvent" => "event:sha256:" <> String.duplicate("ab", 32)}

              entry ->
                entry
            end)
          end)
        end)

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 f =~ "refs:" and f =~ "records casObjectEvent" and
                   f =~ "but the CasObject admission for that address on this chain is"
               end)
      end)
    end
  end

  describe "raw objects (spec/05 §5, §10)" do
    test "the cas: line counts what the chain put in the bundle", %{dest: dest} do
      with_probe(dest, fn _ ->
        {:ok, report} = RecurseVerify.run(dest)

        line = Enum.find(report.checked, &String.starts_with?(&1, "cas:"))
        assert line =~ "1 object(s) admitted, 0 expired, 0 kernel-derived"
        assert line =~ "every object in this bundle's CAS is accounted for"
        assert report.findings == []
      end)
    end

    test "an object nothing on the chain put there is a finding", %{dest: dest} do
      with_probe(dest, fn _ ->
        # Bytes dropped into the bundle's CAS by hand: present, hashing to
        # their address, and admitted by nobody. §5's whole point is that
        # this is not the same as an object somebody put on the record.
        orphan = "smuggled into the bundle"
        address = R5e.Canonical.hash_bytes(orphan)
        target = Path.join([dest, "cas", R5e.CAS.relative_path(address)])
        File.mkdir_p!(Path.dirname(target))
        File.write!(target, orphan)

        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 f =~ "cas:" and f =~ address and f =~ "nothing on the chain put it there"
               end)

        line = Enum.find(report.checked, &String.starts_with?(&1, "cas:"))
        assert line =~ "1 object(s) in this bundle's CAS are accounted for by nothing"
      end)
    end

    test "a CasExpired for a public-record object is a finding" do
      dest = Path.join(System.tmp_dir!(), "r5e-pubrec-#{System.unique_integer([:positive])}")
      on_exit(fn -> File.rm_rf(dest) end)

      fresh(fn ->
        {:ok, _} =
          admit_kind(
            kind_spec(%{
              "kind" => "Archive",
              "schema" => %{
                "required" => [],
                "properties" => %{
                  "archived" => %{
                    "type" => "ref",
                    "ref" => %{"bytes" => true, "retention" => "public-record"}
                  }
                },
                "additionalProperties" => false
              }
            })
          )

        bytes = "the public record"
        address = R5e.TestHelpers.put_object(bytes)

        # The kernel refuses to expire a cited object, so the only chain
        # that carries this sequence is one where the expiry came first
        # and the object was re-admitted afterwards. §10's rule is about
        # the chain as a whole, and the finding says which order it saw.
        {:ok, _} =
          admit("core.r5e.io", "v1", "CasExpired", nil, %{"address" => address}, %{
            actor: R5e.Retention.actor(),
            authority: R5e.Retention.authority()
          })

        refute R5e.CAS.exists?(address)
        ^address = R5e.TestHelpers.put_object(bytes)

        {:ok, _} =
          admit("test.r5e.io", "v1alpha1", "Archive", "a", %{"archived" => %{"$ref" => address}})

        {:ok, ^dest, _} = R5e.Export.run(dest)
        {:ok, report} = RecurseVerify.run(dest)

        assert Enum.any?(report.findings, fn f ->
                 f =~ "cas:" and f =~ "a public-record object is never expired" and
                   f =~ "the object was re-admitted after being expired"
               end)

        line = Enum.find(report.checked, &String.starts_with?(&1, "cas:"))
        assert line =~ "1 object(s) admitted, 1 expired, 0 kernel-derived"
      end)
    end
  end

  # One Kind citing both a resource and an object, one instance citing
  # another, exported — then whatever the test wants to break.
  defp with_probe(dest, fun) do
    fresh(fn ->
      {:ok, _} =
        admit_kind(
          kind_spec(%{
            "kind" => "RefProbe",
            "schema" => %{
              "required" => [],
              "properties" => %{
                "blob" => %{"type" => "ref", "ref" => %{"bytes" => true}},
                "inner" => %{
                  "type" => "ref",
                  "ref" => %{"kind" => "test.r5e.io/v1alpha1/RefProbe"}
                },
                "label" => %{"type" => "string"}
              },
              "additionalProperties" => false
            }
          })
        )

      blob = R5e.TestHelpers.put_object("the referenced object")

      {:ok, base} = admit("test.r5e.io", "v1alpha1", "RefProbe", "base", %{"label" => "base"})

      {:ok, citing} =
        admit("test.r5e.io", "v1alpha1", "RefProbe", "citing", %{
          "blob" => %{"$ref" => blob},
          "inner" => %{"$ref" => "test.r5e.io/v1alpha1/RefProbe/base"}
        })

      {:ok, ^dest, _} = R5e.Export.run(dest)
      fun.(%{base: base, citing: citing, blob: blob})
    end)
  end

  # Point every manifest entry that cited `was` at whatever the event at
  # `seq` hashes to now, rebuilding the citing payload in turn.
  defp repoint(dest, seq, was) do
    {:ok, events} = R5e.Chain.read_log(Path.join(dest, "log.jsonl"))
    now = "event:" <> Enum.find(events, &(&1["seq"] == seq))["hash"]

    Enum.each(events, fn event ->
      path = Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])

      with {:ok, %{"resolvedRefs" => [_ | _] = entries} = payload} <-
             path |> File.read!() |> Jason.decode(),
           true <- Enum.any?(entries, &(&1["admissionEvent"] == was)) do
        updated =
          Enum.map(entries, fn
            %{"admissionEvent" => ^was} = entry -> %{entry | "admissionEvent" => now}
            entry -> entry
          end)

        R5e.Vectors.rebuild(dest, event, %{payload | "resolvedRefs" => updated})
      end
    end)
  end

  defp event_payload_path(dest, receipt) do
    event = Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))
    Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])
  end

  # Rewrite the first payload in the bundle that carries a non-empty
  # manifest, **as a forging node would**: re-addressed, the chain
  # relinked, the checkpoint re-signed. Writing the new bytes over the
  # old file would stop them hashing to their address, and a payload that
  # does not hash to its address is not read at all (spec/07 §1.6) — the
  # refs findings below would then be unreachable.
  defp rewrite_payload(dest, fun) do
    {:ok, events} = R5e.Chain.read_log(Path.join(dest, "log.jsonl"))

    Enum.find_value(events, fn event ->
      path = Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])

      case path |> File.read!() |> Jason.decode() do
        {:ok, %{"resolvedRefs" => [_ | _]} = payload} ->
          R5e.Vectors.rebuild(dest, event, fun.(payload))
          path

        _ ->
          nil
      end
    end)
  end

  defp rewrite_manifest(dest, fun) do
    rewrite_payload(dest, fn payload ->
      Map.update!(payload, "resolvedRefs", fn entries ->
        Enum.map(entries, fn
          %{"class" => "kind"} = entry -> fun.(entry)
          entry -> entry
        end)
      end)
    end)
  end
end
