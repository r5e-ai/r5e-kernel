defmodule R5e.PolicyFactsTest do
  use ExUnit.Case, async: false
  alias R5e.Policy.Facts
  @ref "facts.test/v1/Rule/active"
  @gate "facts.test/v1/Gate/active"

  defmodule Policy do
    @behaviour R5e.Policy
    def authorize(request), do: Process.get(:facts_policy).(request)
  end

  setup do
    previous = Application.get_env(:r5e, :policy)

    on_exit(fn ->
      Application.put_env(:r5e, :policy, previous)
      Application.delete_env(:r5e, :before_record)
    end)

    :ok
  end

  test "omitted generations cannot allow an admission after its multi-hop policy fact moved" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      {:ok, first} = admit_rule("allow")

      {:ok, gate} =
        R5e.TestHelpers.admit("facts.test", "v1", "Gate", "active", %{"title" => @ref})

      Application.put_env(:r5e, :policy, Policy)

      Process.put(:facts_policy, fn request ->
        if request.kind == "Rule" do
          :ok
        else
          {:ok, facts} = Facts.resolve(request)
          assert facts.actor == request.actor
          assert facts.resolved_authority == request.resolved_authority
          {:ok, gate_entry} = Facts.fetch(@gate)
          {:ok, entry} = Facts.fetch(gate_entry["spec"]["title"])
          if entry["spec"]["title"] == "allow", do: :ok, else: {:deny, "changed rule"}
        end
      end)

      Application.put_env(:r5e, :before_record, fn _ ->
        Application.delete_env(:r5e, :before_record)
        {:ok, replacement} = admit_rule("deny")
        Process.put(:replacement, replacement)
      end)

      assert {:denied, receipt} =
               R5e.TestHelpers.admit("facts.test", "v1", "Thing", "t", %{"title" => "t"})

      assert receipt["reason"] =~ "changed rule"

      assert receipt["policy"]["generations"] == %{
               @ref => Process.get(:replacement)["seq"],
               @gate => gate["seq"]
             }

      refute receipt["policy"]["generations"] == %{@ref => first["seq"]}
      assert {:error, _} = Facts.fetch(@ref)
      Process.put(:facts_policy, fn _ -> :ok end)
      assert {:ok, clean_meta} = R5e.Policy.decide(%{})
      assert clean_meta["generations"] == %{}
    end)
  end

  test "resolve presents admitted citations and immutable event actor and spec" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      {:ok, receipt} = admit_rule("allow")

      request = %{
        actor: %{"id" => "actor"},
        resolved_authority: [],
        resolved: [
          %{"class" => "kind", "value" => @ref},
          %{"class" => "event", "value" => receipt["eventRef"]}
        ]
      }

      Application.put_env(:r5e, :policy, Policy)

      Process.put(:facts_policy, fn req ->
        assert {:ok, facts} = Facts.resolve(req)
        assert facts.resources[@ref]["spec"] == %{"title" => "allow"}
        assert facts.resources[@ref]["admissionSeq"] == receipt["seq"]
        assert facts.events[receipt["eventRef"]].payload == R5e.TestHelpers.payload_of(receipt)
        :ok
      end)

      assert {:ok, meta} = R5e.Policy.decide(request)
      assert meta["generations"] == %{@ref => receipt["seq"]}
    end)
  end

  test "ignored missing and malformed reads fail closed; tracking clears after errors and raises" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      Application.put_env(:r5e, :policy, Policy)

      for read <- [
            fn -> Facts.fetch(@ref) end,
            fn -> Facts.fetch(nil) end,
            fn -> Facts.resolve(%{}) end,
            fn -> Facts.event("event:bad") end
          ] do
        Process.put(:facts_policy, fn _ ->
          read.()
          :ok
        end)

        assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
      end

      Process.put(:facts_policy, fn _ ->
        Facts.fetch(@ref)
        raise "policy bug"
      end)

      assert_raise RuntimeError, "policy bug", fn -> R5e.Policy.decide(%{}) end
      assert {:error, _} = Facts.fetch(@ref)
      Process.put(:facts_policy, fn _ -> :ok end)
      assert {:ok, clean_meta} = R5e.Policy.decide(%{})
      assert clean_meta["generations"] == %{}
    end)
  end

  test "adapter generation conflicts and repeated reads of a changed entry fail closed" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      {:ok, _} = admit_rule("allow")
      Application.put_env(:r5e, :policy, Policy)

      Process.put(:facts_policy, fn _ ->
        {:ok, _} = Facts.fetch(@ref)
        {:ok, %{"generations" => %{@ref => -1}}}
      end)

      assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})

      Process.put(:facts_policy, fn _ ->
        {:ok, entry} = Facts.fetch(@ref)

        R5e.ResourceStore.put(
          "facts.test",
          "v1",
          "Rule",
          "active",
          Map.update!(entry, "admissionSeq", &(&1 + 1))
        )

        assert {:error, _} = Facts.fetch(@ref)
        :ok
      end)

      assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
    end)
  end

  test "a malformed stored generation cannot be ignored by an allowing adapter" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      {:ok, _} = admit_rule("allow")
      {:ok, entry, _} = R5e.ResourceStore.get("facts.test", "v1", "Rule", "active")

      R5e.ResourceStore.put(
        "facts.test",
        "v1",
        "Rule",
        "active",
        Map.put(entry, "admissionSeq", "1")
      )

      Application.put_env(:r5e, :policy, Policy)

      Process.put(:facts_policy, fn _ ->
        assert {:error, _} = Facts.fetch(@ref)
        :ok
      end)

      assert {:deny, _, %{"decision" => "error"}} = R5e.Policy.decide(%{})
    end)
  end

  test "nested decisions restore the enclosing capture without leaking into the next request" do
    R5e.Vectors.with_fresh_kernel(fn ->
      seed()
      {:ok, receipt} = admit_rule("allow")
      Application.put_env(:r5e, :policy, Policy)

      Process.put(:facts_policy, fn
        %{inner: true} ->
          :ok

        _ ->
          {:ok, _} = Facts.fetch(@ref)
          assert {:ok, clean_meta} = R5e.Policy.decide(%{inner: true})
          assert clean_meta["generations"] == %{}
          :ok
      end)

      assert {:ok, meta} = R5e.Policy.decide(%{})
      assert meta["generations"] == %{@ref => receipt["seq"]}
      assert {:ok, clean_meta} = R5e.Policy.decide(%{inner: true})
      assert clean_meta["generations"] == %{}
    end)
  end

  defp seed do
    for {kind, naming} <- [
          {"Gate", %{"mode" => "literal", "value" => "active"}},
          {"Rule", %{"mode" => "literal", "value" => "active"}},
          {"Thing", %{"mode" => "caller"}}
        ] do
      spec =
        R5e.TestHelpers.kind_spec(%{
          "group" => "facts.test",
          "version" => "v1",
          "kind" => kind,
          "naming" => naming
        })

      {:ok, _} = R5e.Vectors.admit_definition(spec)
    end
  end

  defp admit_rule(title),
    do: R5e.TestHelpers.admit("facts.test", "v1", "Rule", "active", %{"title" => title})
end
