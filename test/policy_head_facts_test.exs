# SPDX-License-Identifier: AGPL-3.0-only
defmodule R5e.PolicyHeadFactsTest do
  use ExUnit.Case, async: false
  alias R5e.Policy.Facts
  @kind "head.test/v1/Entry"
  @anchor %{"id" => "one"}

  defmodule Policy do
    @behaviour R5e.Policy
    def authorize(request), do: Process.get(:head_policy).(request)
  end

  setup do
    previous = Application.get_env(:r5e, :policy)

    on_exit(fn ->
      Application.put_env(:r5e, :policy, previous)
      Application.delete_env(:r5e, :before_record)
    end)

    :ok
  end

  test "absence is captured and present heads return immutable payloads; unused receipts stay unchanged" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn _ ->
        assert {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
        :ok
      end)

      assert {:ok, meta} = R5e.Policy.decide(%{})
      assert meta["eventHeads"] == [head(nil)]
      refute R5e.Commit.empty?(R5e.Commit.capture(%{}, meta))
      assert R5e.Commit.stale(R5e.Commit.capture(%{}, meta)) == nil
      policy(fn _ -> :ok end)
      assert {:ok, clean} = R5e.Policy.decide(%{})
      refute Map.has_key?(clean, "eventHeads")
      {:ok, receipt} = admit(@anchor, nil, "first")

      policy(fn _ ->
        assert {:ok, fact} = Facts.head(@kind, "anchor", @anchor)
        assert fact.event["seq"] == receipt["seq"]
        assert fact.payload == R5e.TestHelpers.payload_of(receipt)
        :ok
      end)

      assert {:ok, meta} = R5e.Policy.decide(%{})
      assert meta["eventHeads"] == [head(receipt["eventRef"])]
      assert {:error, _} = Facts.head(@kind, "anchor", @anchor)
    end)
  end

  test "ignored invalid queries and caught log failures poison the decision" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      for {kind, field, anchor} <- [
            {@kind, "anchor", nil},
            {@kind, "", @anchor},
            {"head.test/v1/Entry/name", "anchor", @anchor},
            {@kind, "anchor", 1.5},
            {@kind, "anchor", %{atom: "bad"}},
            {@kind, "anchor", self()},
            {@kind, "anchor", [1 | :bad]},
            {<<255>>, "anchor", @anchor}
          ] do
        policy(fn _ ->
          try do
            Facts.head(kind, field, anchor)
          rescue
            _ -> :ignored
          catch
            _, _ -> :ignored
          end

          :ok
        end)

        assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
      end

      policy(fn _ ->
        log = Process.whereis(R5e.Log)
        Process.unregister(R5e.Log)

        try do
          try do
            Facts.head(@kind, "anchor", @anchor)
          catch
            :exit, _ -> :ignored
          end
        after
          Process.register(log, R5e.Log)
        end

        :ok
      end)

      assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
      policy(fn _ -> :ok end)
      assert {:ok, meta} = R5e.Policy.decide(%{})
      refute Map.has_key?(meta, "eventHeads")
    end)
  end

  test "untracked or contradictory adapter reports cannot manufacture a grant" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      for report <- [[head(nil)], nil, %{}, [head("event:sha256:" <> String.duplicate("0", 64))]] do
        policy(fn _ -> {:ok, %{"eventHeads" => report, "evidence" => "retained"}} end)
        assert {:deny, _, meta} = R5e.Policy.decide(%{})
        assert meta["upstreamPolicy"]["evidence"] == "retained"
      end

      policy(fn _ ->
        {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
        {:ok, %{"eventHeads" => [head("event:sha256:" <> String.duplicate("0", 64))]}}
      end)

      assert {:deny, _, meta} = R5e.Policy.decide(%{})
      assert meta["eventHeads"] == [head(nil)]
    end)
  end

  test "a negative repeated read conflict and nested ignored conflict poison enclosing decisions" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn
        %{kind: "Entry"} ->
          :ok

        %{inner: true} ->
          {:ok, _} = Facts.head(@kind, "anchor", @anchor)
          {:ok, %{"eventHeads" => [head("event:sha256:" <> String.duplicate("0", 64))]}}

        _ ->
          assert {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
          {:ok, _} = admit(@anchor, nil, "moves-absence")
          assert {:error, _} = Facts.head(@kind, "anchor", @anchor)
          :ok
      end)

      assert {:deny, _, meta} = R5e.Policy.decide(%{})
      assert meta["eventHeads"] == [head(nil)]

      Process.put(:head_policy, fn
        %{inner: true} ->
          {:ok, _} = Facts.head(@kind, "anchor", @anchor)
          {:ok, %{"eventHeads" => [head(nil)]}}

        _ ->
          assert {:deny, _, _} = R5e.Policy.decide(%{inner: true})
          :ok
      end)

      assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
    end)
  end

  test "inner-only reads merge into outer metadata and retain schema sameAnchor captures" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn
        %{inner: true} ->
          {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
          :ok

        _ ->
          {:ok, _} = R5e.Policy.decide(%{inner: true})
          :ok
      end)

      assert {:ok, meta} = R5e.Policy.decide(%{})

      manifest = [
        %{
          "class" => "event",
          "anchorField" => "other",
          "targetKind" => "other/v1/K",
          "head" => "event:existing"
        }
      ]

      capture = R5e.Commit.capture(%{resolved: manifest, spec: %{"other" => "value"}}, meta)
      assert length(capture["anchors"]) == 2
      assert head(nil) in capture["anchors"]

      assert %{
               "kind" => "other/v1/K",
               "field" => "other",
               "anchor" => R5e.Canonical.encode("value"),
               "head" => "event:existing"
             } in capture["anchors"]
    end)
  end

  for predecessor <- [:absent, :present] do
    test "two concurrent #{predecessor} predecessor admissions grant only one successor" do
      R5e.Vectors.with_fresh_kernel(fn ->
        seed()

        previous =
          case unquote(predecessor) do
            :absent ->
              nil

            :present ->
              {:ok, receipt} = admit(@anchor, nil, "initial")
              receipt["eventRef"]
          end

        parent = self()
        Application.put_env(:r5e, :policy, Policy)

        check = fn request ->
          {:ok, fact} = Facts.head(@kind, "anchor", request.spec["anchor"])
          observed = if fact, do: "event:" <> fact.event["hash"]

          if Process.get(:head_barrier_passed) != true do
            Process.put(:head_barrier_passed, true)
            send(parent, {:read, self(), observed})

            receive do
              :commit -> :ok
            after
              5_000 -> raise "barrier timed out"
            end
          end

          if request.spec["previous"] == observed, do: :ok, else: {:deny, "stale predecessor"}
        end

        tasks =
          for label <- ["left", "right"] do
            Task.async(fn ->
              Process.put(:head_policy, check)
              admit(@anchor, previous, label, %{"id" => label})
            end)
          end

        assert_receive {:read, first, ^previous}, 2_000
        assert_receive {:read, second, ^previous}, 2_000
        send(first, :commit)
        send(second, :commit)
        results = Enum.map(tasks, &Task.await(&1, 5_000))
        assert Enum.count(results, &match?({:ok, _}, &1)) == 1
        assert [{:denied, denied}] = Enum.filter(results, &match?({:denied, _}, &1))
        assert denied["reason"] =~ "stale predecessor"

        granted =
          Enum.find_value(results, fn case_result ->
            case case_result do
              {:ok, r} -> r
              _ -> nil
            end
          end)

        assert granted["policy"]["eventHeads"] == [head(previous)]
        assert {:ok, _} = R5e.Log.verify()
        # Existing export and standalone verifier accept the additive metadata.
        path = Path.join(System.tmp_dir!(), "head-export-#{System.unique_integer([:positive])}")

        try do
          {:ok, ^path, _} = R5e.Export.run(path)
          assert {:ok, report} = RecurseVerify.run(path)

          assert report.findings == [
                   "gap: receipt at seq #{denied["seq"]} records a denial under engine \"unknown\" with no policy object in force -- nothing in this bundle shows the rule that denied"
                 ]
        after
          File.rm_rf!(path)
        end
      end)
    end
  end

  test "unrelated anchors and denied matching events never move a captured granted head" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn _ ->
        {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
        :ok
      end)

      {:ok, meta} = R5e.Policy.decide(%{})
      capture = R5e.Commit.capture(%{}, meta)
      policy(fn _ -> :ok end)
      {:ok, _} = admit(%{"id" => "other"}, nil, "unrelated")
      assert R5e.Commit.stale(capture) == nil
      policy(fn _ -> {:deny, "deliberate"} end)
      {:denied, _} = admit(@anchor, nil, "denied")
      assert R5e.Commit.stale(capture) == nil
      policy(fn _ -> :ok end)
      {:ok, _} = admit(@anchor, nil, "matching")
      assert R5e.Commit.stale(capture) =~ "was absent"
    end)
  end

  test "an unrelated anchor admitted between policy read and append does not retry" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn request ->
        if request.spec["label"] == "interleaved" do
          :ok
        else
          Process.put(:head_read_count, Process.get(:head_read_count, 0) + 1)
          assert {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
          :ok
        end
      end)

      Application.put_env(:r5e, :before_record, fn _ ->
        Application.delete_env(:r5e, :before_record)
        {:ok, _} = admit(%{"id" => "other"}, nil, "interleaved")
      end)

      assert {:ok, receipt} = admit(@anchor, nil, "main")
      assert receipt["policy"]["eventHeads"] == [head(nil)]
      assert Process.get(:head_read_count) == 1
    end)
  end

  test "Kind and literal top-level field are exact query dimensions" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      {:ok, _} = admit(@anchor, nil, "first")

      policy(fn _ ->
        assert {:ok, nil} = Facts.head("other.test/v1/Entry", "anchor", @anchor)
        assert {:ok, nil} = Facts.head("head.test/v2/Entry", "anchor", @anchor)
        assert {:ok, nil} = Facts.head("head.test/v1/Other", "anchor", @anchor)
        assert {:ok, nil} = Facts.head(@kind, "anchor.id", "one")
        assert {:ok, _} = Facts.head(@kind, "anchor", @anchor)
        :ok
      end)

      assert {:ok, meta} = R5e.Policy.decide(%{})
      assert length(meta["eventHeads"]) == 5
    end)
  end

  test "a changed head read only by a nested decision cannot overwrite the outer absence" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn
        %{kind: "Entry"} ->
          :ok

        %{inner: true} ->
          {:ok, _} = Facts.head(@kind, "anchor", @anchor)
          :ok

        _ ->
          assert {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
          {:ok, _} = admit(@anchor, nil, "nested-change")
          assert {:ok, _} = R5e.Policy.decide(%{inner: true})
          :ok
      end)

      assert {:deny, _, meta} = R5e.Policy.decide(%{})
      assert meta["eventHeads"] == [head(nil)]
      assert meta["reason"] == "factsInvalid"
    end)
  end

  test "an unreadable granted payload cannot masquerade as an absent head at read or commit" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn _ ->
        {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
        :ok
      end)

      {:ok, meta} = R5e.Policy.decide(%{})
      capture = R5e.Commit.capture(%{}, meta)
      policy(fn _ -> :ok end)
      {:ok, receipt} = admit(@anchor, nil, "corrupt")
      event = Enum.find(R5e.Log.events(), &("event:" <> &1["hash"] == receipt["eventRef"]))
      path = Path.join(R5e.CAS.root(), R5e.CAS.relative_path(event["payload"]))
      bytes = File.read!(path)

      try do
        tampered =
          bytes
          |> Jason.decode!()
          |> put_in(["spec", "anchor"], %{"id" => "elsewhere"})
          |> Jason.encode!()

        for damage <- [:missing, tampered] do
          if damage == :missing, do: File.rm!(path), else: File.write!(path, damage)

          policy(fn _ ->
            assert {:error, _} = Facts.head(@kind, "anchor", @anchor)
            :ok
          end)

          assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
          assert R5e.Commit.stale(capture) =~ "cannot recheck event heads"
        end
      after
        File.write!(path, bytes)
      end
    end)
  end

  test "missing, empty, malformed, and invalid histories cannot establish absence" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()

      policy(fn _ ->
        assert {:ok, nil} = Facts.head(@kind, "anchor", @anchor)
        :ok
      end)

      {:ok, meta} = R5e.Policy.decide(%{})
      capture = R5e.Commit.capture(%{}, meta)
      path = R5e.Log.log_path()
      original = File.read!(path)
      [first | rest] = String.split(original, "\n", trim: true)

      broken_hash =
        Jason.encode!(Map.put(Jason.decode!(first), "hash", String.duplicate("0", 64))) <>
          "\n" <> Enum.join(rest, "\n") <> "\n"

      try do
        for corrupt <- [
              :missing,
              "",
              "{broken JSON}\n",
              "{}\n",
              original <> "{broken JSON}\n",
              broken_hash
            ] do
          if corrupt == :missing, do: File.rm!(path), else: File.write!(path, corrupt)

          policy(fn _ ->
            assert {:error, _} = Facts.head(@kind, "anchor", @anchor)
            :ok
          end)

          assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
          assert R5e.Commit.stale(capture) =~ "cannot read policy event history"
          File.write!(path, original)
        end
      after
        File.write!(path, original)
      end
    end)
  end

  test "older event hydration and resolve citations reject valid JSON payload tampering" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      policy(fn _ -> :ok end)
      {:ok, older} = admit(@anchor, nil, "older")
      {:ok, _newer} = admit(@anchor, older["eventRef"], "newer")
      event = Enum.find(R5e.Log.events(), &("event:" <> &1["hash"] == older["eventRef"]))
      path = Path.join(R5e.CAS.root(), R5e.CAS.relative_path(event["payload"]))
      bytes = File.read!(path)

      request = %{
        actor: %{"id" => "actor"},
        resolved_authority: [],
        resolved: [%{"class" => "event", "value" => older["eventRef"]}]
      }

      policy(fn _ ->
        assert {:ok, _} = Facts.event(older["eventRef"])
        assert {:ok, _} = Facts.resolve(request)
        :ok
      end)

      assert {:ok, _} = R5e.Policy.decide(%{})

      try do
        File.write!(
          path,
          bytes |> Jason.decode!() |> put_in(["spec", "label"], "tampered") |> Jason.encode!()
        )

        for read <- [fn -> Facts.event(older["eventRef"]) end, fn -> Facts.resolve(request) end] do
          policy(fn _ ->
            assert {:error, _} = read.()
            :ok
          end)

          assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
        end
      after
        File.write!(path, bytes)
      end
    end)
  end

  defp policy(fun) do
    Application.put_env(:r5e, :policy, Policy)
    Process.put(:head_policy, fun)
  end

  defp head(ref),
    do: %{
      "kind" => @kind,
      "field" => "anchor",
      "anchor" => R5e.Canonical.encode(@anchor),
      "head" => ref
    }

  defp admit(anchor, previous, label, actor \\ %{"id" => "test:head"}) do
    spec = %{"anchor" => anchor, "label" => label}
    spec = if previous, do: Map.put(spec, "previous", previous), else: spec
    R5e.TestHelpers.admit("head.test", "v1", "Entry", nil, spec, %{actor: actor})
  end

  defp seed do
    spec =
      R5e.TestHelpers.kind_spec(%{
        "group" => "head.test",
        "version" => "v1",
        "kind" => "Entry",
        "substrate" => "event",
        "naming" => %{"mode" => "content"},
        "schema" => %{
          "required" => ["anchor", "label"],
          "additionalProperties" => false,
          "properties" => %{
            "anchor" => %{
              "type" => "object",
              "properties" => %{"id" => %{"type" => "string"}},
              "required" => ["id"],
              "additionalProperties" => false
            },
            "label" => %{"type" => "string"},
            "previous" => %{"type" => "string"}
          }
        }
      })

    {:ok, _} = R5e.Vectors.admit_definition(spec)
  end
end

