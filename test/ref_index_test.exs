defmodule R5e.RefIndexTest do
  @moduledoc """
  The reference index (spec/05 §5): the four citation sources, the
  partition it answers in one lookup, and the kernel-derived class it
  defines a slice before anything populates it.
  """

  use ExUnit.Case, async: false

  @actor %{"id" => "test:alice", "keyFingerprint" => "sha256:test-alice"}

  @cites %{
    "group" => "index.r5e.io",
    "kind" => "Cites",
    "version" => "v1alpha1",
    "substrate" => "resource",
    "naming" => %{"mode" => "caller"},
    "schema" => %{
      "required" => [],
      "properties" => %{
        "blob" => %{"type" => "ref", "ref" => %{"bytes" => true}},
        "archived" => %{
          "type" => "ref",
          "ref" => %{"bytes" => true, "retention" => "public-record"}
        }
      },
      "additionalProperties" => false
    },
    "predicates" => []
  }

  defp fresh(fun), do: R5e.Vectors.with_fresh_kernel(fun)

  defp put(bytes) do
    {:ok, receipt, address, _size} = R5e.TestHelpers.cas_admit(@actor, bytes)
    {receipt, address}
  end

  defp cite(spec) do
    {:ok, _} = R5e.Vectors.admit_definition(@cites)

    {:ok, receipt} =
      R5e.TestHelpers.admit_request(%{
        actor: @actor,
        group: "index.r5e.io",
        version: "v1alpha1",
        kind: "Cites",
        name: "c",
        spec: spec
      })

    receipt
  end

  test "a CasObject admission is what makes an address citable" do
    fresh(fn ->
      {receipt, address} = put("on the record")

      assert {:ok, info} = R5e.RefIndex.cas_object(address)
      assert info["eventRef"] == receipt["eventRef"]
      assert info["seq"] == receipt["seq"]
      assert info["size"] == byte_size("on the record")
      assert info["admissions"] == 1

      # The object's own admission does not cite it: a CasObject's spec is
      # the record of the object, not a reference to it, and counting it
      # would make every object permanently unexpirable.
      assert R5e.RefIndex.citations(address) == []
      assert R5e.RefIndex.unreferenced?(address)
    end)
  end

  test "the four citation sources, each recorded with the seq that produced it" do
    fresh(fn ->
      {_, address} = put("cited")
      receipt = cite(%{"blob" => %{"$ref" => address}})

      kinds = R5e.RefIndex.citations(address) |> Enum.map(& &1["kind"]) |> Enum.sort()
      assert kinds == ["manifest", "spec"]

      for citation <- R5e.RefIndex.citations(address) do
        assert citation["seq"] == receipt["seq"]
        assert citation["eventRef"] == receipt["eventRef"]
      end

      refute R5e.RefIndex.unreferenced?(address)

      # The other two sources are what §4's partition is made of.
      payload_address = payload_address(receipt)
      assert R5e.RefIndex.partition(payload_address) == {:error, :payload}
      assert R5e.RefIndex.partition(receipt["specAddress"]) == {:error, :spec}
      assert R5e.RefIndex.partition(address) == :ok
    end)
  end

  test "retention rides from the declaration onto the citation" do
    fresh(fn ->
      {_, plain} = put("ordinary")
      {_, archived} = put("permanent")
      cite(%{"blob" => %{"$ref" => plain}, "archived" => %{"$ref" => archived}})

      assert R5e.RefIndex.public_record_citations(plain) == []
      assert [%{"path" => "/archived"}] = R5e.RefIndex.public_record_citations(archived)
    end)
  end

  test "the index is a view of the chain, rebuilt by replay" do
    fresh(fn ->
      {receipt, address} = put("survives a rebuild")
      cite(%{"blob" => %{"$ref" => address}})

      before_citations = R5e.RefIndex.citations(address)

      R5e.RefIndex.reset()
      assert R5e.RefIndex.citations(address) == []
      assert R5e.RefIndex.cas_object(address) == :error

      R5e.Bootstrap.replay()

      assert R5e.RefIndex.citations(address) == before_citations
      assert {:ok, %{"eventRef" => ref}} = R5e.RefIndex.cas_object(address)
      assert ref == receipt["eventRef"]
    end)
  end

  # §5's kernel-derived class, defined now and empty until §8's policy
  # evaluation record. Registering one synthetically is the only way to
  # exercise it in this slice, and the class has to exist before the first
  # member does — otherwise the first member arrives with nowhere to go
  # and a null `casObjectEvent` that reads as a gap.
  test "a kernel-derived object resolves without a CasObject admission" do
    fresh(fn ->
      address = "bytes:" <> R5e.CAS.put(~s({"format":"r5e.policy-evaluation/1"}))

      # Before registration it is bytes in a directory, and §5 refuses it.
      assert R5e.RefIndex.cas_object(address) == :error
      refute R5e.RefIndex.derived?(address)

      {:ok, _} = R5e.Vectors.admit_definition(@cites)

      {:denied, denial} =
        R5e.TestHelpers.admit_request(%{
          actor: @actor,
          group: "index.r5e.io",
          version: "v1alpha1",
          kind: "Cites",
          name: "before",
          spec: %{"blob" => %{"$ref" => address}}
        })

      assert denial["reason"] =~ "bytes present is not bytes admitted"

      R5e.RefIndex.register_derived(address)

      assert R5e.RefIndex.derived?(address)
      assert R5e.RefIndex.derived_objects() == [address]

      # It resolves, and says which class it resolved as: a null
      # `casObjectEvent` beside `derived: true` is a stated class, not an
      # unanswered question.
      receipt = cite(%{"blob" => %{"$ref" => address}})

      assert [%{"casObjectEvent" => nil, "derived" => true, "value" => ^address}] =
               receipt["resolvedRefs"]

      # And it is never unreferenced: the admission that wrote it is what
      # cites it, and that admission is on the chain.
      R5e.RefIndex.reset()
      R5e.Bootstrap.replay()
      R5e.RefIndex.register_derived(address)
      assert R5e.RefIndex.unreferenced?(address) == false
    end)
  end

  test "the export lists the derived objects and carries their bytes" do
    dest = Path.join(System.tmp_dir!(), "r5e-derived-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)

    fresh(fn ->
      address = "bytes:" <> R5e.CAS.put(~s({"format":"r5e.policy-evaluation/1","n":1}))
      R5e.RefIndex.register_derived(address)

      {:ok, ^dest, manifest} = R5e.Export.run(dest)

      assert manifest["derivedObjects"] == [address]
      assert manifest["missingObjects"] == []
      assert RecurseVerify.CAS.intact?(Path.join(dest, "cas"), address)
    end)
  end

  defp payload_address(receipt) do
    Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))["payload"]
  end
end
