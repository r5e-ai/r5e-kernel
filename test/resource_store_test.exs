defmodule R5e.ResourceStoreTest do
  @moduledoc """
  Deep hydration (spec/05 §6). The vectors under `test/vectors/hydration/`
  pin the shapes; what is here is the behaviour a vector cannot express —
  lineage, the refs-first stored form beside the computed view, and what a
  cycle does.
  """

  use ExUnit.Case, async: false

  import R5e.TestHelpers

  @doc_kind %{
    "required" => [],
    "properties" => %{
      "body" => %{"type" => "ref", "ref" => %{"bytes" => true}},
      "meta" => %{"type" => "ref", "ref" => %{"bytes" => true, "json" => %{"type" => "object"}}},
      "inner" => %{"type" => "ref", "ref" => %{"kind" => "test.r5e.io/v1alpha1/Doc"}},
      "label" => %{"type" => "string"}
    },
    "additionalProperties" => false
  }

  setup do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "Doc", "schema" => @doc_kind}))
    :ok
  end

  test "deep resolution hydrates each class per its declaration; the stored form stays refs" do
    body = "referenced content"
    body_ref = R5e.TestHelpers.put_object(body)
    meta_ref = R5e.TestHelpers.put_object(Jason.encode!(%{"author" => "alice"}))

    {:ok, _} =
      admit("test.r5e.io", "v1alpha1", "Doc", "base", %{
        "body" => %{"$ref" => body_ref},
        "meta" => %{"$ref" => meta_ref}
      })

    {:ok, _} =
      admit("test.r5e.io", "v1alpha1", "Doc", "wrapper", %{
        "inner" => %{"$ref" => "test.r5e.io/v1alpha1/Doc/base"},
        "label" => "wraps base"
      })

    # refs (default): the stored form holds refs, nothing materialized
    {:ok, stored, []} = R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "Doc", "wrapper")
    assert stored["spec"]["inner"] == %{"$ref" => "test.r5e.io/v1alpha1/Doc/base"}

    # deep: a computed view, carrying the refs it was derived from
    {:ok, deep, lineage} =
      R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "Doc", "wrapper", :deep)

    inner = deep["spec"]["inner"]["spec"]

    # `bytes` with no `json`: the object itself, with its size. No
    # mediaType is invented — nothing records one until CasObject (§5).
    assert inner["body"] == %{"size" => byte_size(body), "base64" => Base.encode64(body)}
    refute Map.has_key?(inner["body"], "mediaType")

    # `bytes` with `json`: the declaration is what makes it a value.
    assert inner["meta"] == %{"author" => "alice"}

    # Lineage is transitive: the nested refs are in it too.
    assert "test.r5e.io/v1alpha1/Doc/base" in lineage
    assert body_ref in lineage
    assert meta_ref in lineage
  end

  test "hydration is declaration-aware: the same object reads two ways under two declarations" do
    object = Jason.encode!(%{"n" => 1})
    ref = R5e.TestHelpers.put_object(object)

    {:ok, _} =
      admit("test.r5e.io", "v1alpha1", "Doc", "both", %{
        "body" => %{"$ref" => ref},
        "meta" => %{"$ref" => ref}
      })

    {:ok, deep, _} = R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "Doc", "both", :deep)

    assert deep["spec"]["meta"] == %{"n" => 1}

    assert deep["spec"]["body"] == %{
             "size" => byte_size(object),
             "base64" => Base.encode64(object)
           }
  end

  test "an object that declares json but does not hold it is flagged, not guessed at" do
    ref = R5e.TestHelpers.put_object("not json at all")
    {:ok, _} = admit("test.r5e.io", "v1alpha1", "Doc", "bad", %{"meta" => %{"$ref" => ref}})

    {:ok, deep, _} = R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "Doc", "bad", :deep)

    assert deep["spec"]["meta"] == %{
             "$ref" => ref,
             "$unresolved" => "declared json, but the object is not valid JSON"
           }
  end

  test "an event ref hydrates to the envelope and the decoded payload" do
    {:ok, _} =
      admit_kind(
        kind_spec(%{
          "kind" => "Note",
          "substrate" => "event",
          "naming" => %{"mode" => "content"},
          "schema" => %{
            "required" => ["title"],
            "properties" => %{"title" => %{"type" => "string"}},
            "additionalProperties" => false
          }
        })
      )

    {:ok, note} = admit("test.r5e.io", "v1alpha1", "Note", nil, %{"title" => "hello"})

    {:ok, _} =
      admit_kind(
        kind_spec(%{
          "kind" => "Citation",
          "schema" => %{
            "required" => ["note"],
            "properties" => %{
              "note" => %{
                "type" => "ref",
                "ref" => %{"event" => "test.r5e.io/v1alpha1/Note", "outcome" => "admitted"}
              }
            },
            "additionalProperties" => false
          }
        })
      )

    {:ok, _} =
      admit("test.r5e.io", "v1alpha1", "Citation", "c1", %{
        "note" => %{"$ref" => note["eventRef"]}
      })

    {:ok, deep, lineage} =
      R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "Citation", "c1", :deep)

    assert deep["spec"]["note"]["event"]["hash"] == note["event"]
    assert deep["spec"]["note"]["payload"]["spec"] == %{"title" => "hello"}
    assert note["eventRef"] in lineage
  end

  test "a self-citing entry is flagged as a cycle rather than looped over" do
    # `caller` naming lets an entry name itself before it exists: the ref
    # resolves against the entry admitted a moment earlier under the same
    # name, and the hydrated view then points back at itself.
    {:ok, _} = admit("test.r5e.io", "v1alpha1", "Doc", "loop", %{"label" => "first"})

    {:ok, _} =
      admit("test.r5e.io", "v1alpha1", "Doc", "loop", %{
        "inner" => %{"$ref" => "test.r5e.io/v1alpha1/Doc/loop"}
      })

    {:ok, deep, _} = R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "Doc", "loop", :deep)

    assert deep["spec"]["inner"]["spec"]["inner"] == %{
             "$ref" => "test.r5e.io/v1alpha1/Doc/loop",
             "$cycle" => true
           }
  end
end
