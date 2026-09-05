defmodule R5e.KindTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  test "omitted epistemic scope receives the modest default and is flagged" do
    {:ok, kind} = R5e.Kind.from_map(kind_spec())

    assert kind.scope_defaulted
    assert kind.epistemic_scope["claims"] == ["signed by author", "matches schema"]
    assert kind.epistemic_scope["doesNotClaim"] == ["anything else"]
  end

  test "a declared scope is preserved and not flagged" do
    {:ok, kind} =
      R5e.Kind.from_map(
        kind_spec(%{
          "epistemicScope" => %{
            "claims" => ["the widget existed"],
            "doesNotClaim" => ["the widget worked"]
          }
        })
      )

    refute kind.scope_defaulted
    assert kind.epistemic_scope["claims"] == ["the widget existed"]
  end

  test "the defaulted flag rides the receipt through admission" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "DefaultScoped"}))

    {:ok, receipt} =
      admit("test.r5e.io", "v1alpha1", "DefaultScoped", "w1", %{"title" => "hello"})

    assert receipt["scopeDefaulted"] == true
    assert receipt["epistemicScope"]["doesNotClaim"] == ["anything else"]
  end

  test "a malformed substrate is denied at validate, before record of an admit" do
    {:denied, receipt} = admit_kind(kind_spec(%{"substrate" => "vibes"}))
    assert receipt["reason"] =~ "substrate"
  end

  test "a spec over the 1 MiB limit is denied, and one under it is not" do
    {:ok, _} =
      admit_kind(
        kind_spec(%{
          "kind" => "Bulky",
          "schema" => %{
            "required" => [],
            "properties" => %{"blob" => %{"type" => "string"}},
            "additionalProperties" => false
          }
        })
      )

    {:ok, _} =
      admit("test.r5e.io", "v1alpha1", "Bulky", "small", %{
        "blob" => String.duplicate("x", 1_000_000)
      })

    {:denied, receipt} =
      admit("test.r5e.io", "v1alpha1", "Bulky", "big", %{
        "blob" => String.duplicate("x", 1_100_000)
      })

    assert receipt["reason"] =~ "spec limit exceeded"
    assert String.starts_with?(receipt["reason"], "validateStructure:")
  end

  test "the two predicates of §0 are separate: exists is not nonEmpty" do
    assert R5e.Kind.exists?(%{"a" => ""}, "a")
    assert R5e.Kind.exists?(%{"a" => []}, "a")
    assert R5e.Kind.exists?(%{"a" => %{}}, "a")
    refute R5e.Kind.exists?(%{"a" => nil}, "a")
    refute R5e.Kind.exists?(%{}, "a")

    refute R5e.Kind.non_empty?("")
    refute R5e.Kind.non_empty?([])
    refute R5e.Kind.non_empty?(%{})
    refute R5e.Kind.non_empty?(nil)
    assert R5e.Kind.non_empty?(0)
    assert R5e.Kind.non_empty?(false)
  end

  test "patterns are whole-string matched, with :re under [:unicode, :ucp]" do
    assert {:ok, re} = R5e.Kind.compile_pattern("(cat|dog)")
    assert :re.run("dog", re, [{:capture, :none}]) == :match
    assert :re.run("dogged", re, [{:capture, :none}]) == :nomatch
    assert :re.run("dog\n", re, [{:capture, :none}]) == :nomatch

    assert {:ok, unicode} = R5e.Kind.compile_pattern("\\w+")
    assert :re.run("naïve", unicode, [{:capture, :none}]) == :match

    assert {:error, reason} = R5e.Kind.compile_pattern("([a-z")
    assert reason =~ "does not compile"
  end

  test "a name is legal iff it matches the §2 charset, at most 255 bytes" do
    assert R5e.Kind.valid_name?("first-note")
    assert R5e.Kind.valid_name?("sha256:" <> String.duplicate("a", 64))
    assert R5e.Kind.valid_name?("gateway.r5e.io/v1alpha1/ToolCall")
    assert R5e.Kind.valid_name?("cedar.*")
    refute R5e.Kind.valid_name?("has a space")
    refute R5e.Kind.valid_name?("trailing/")
    refute R5e.Kind.valid_name?("")
    refute R5e.Kind.valid_name?(String.duplicate("a", 256))
  end

  test "a receipt carries eventRef, the empty resolve manifest, and derivedFrom" do
    # §5/C8: an envelope derivedFrom is a bytes citation, so it is backed
    # by a CasObject admission like any other or the admission is denied
    # at `resolve`. `put_object/1` is `PUT /cas` without the HTTP.
    address = put_object("the natural-language document this Kind was derived from")

    {:ok, receipt} =
      admit_kind(kind_spec(%{"kind" => "FromADocument"}), %{derived_from: address})

    assert receipt["eventRef"] == "event:" <> receipt["event"]
    assert receipt["resolvedRefs"] == []
    assert receipt["derivedFrom"] == address

    payload = R5e.TestHelpers.payload_of(receipt)
    assert payload["derivedFrom"] == address
    assert payload["resolvedRefs"] == []
    # The envelope is beside the spec, never inside it: the address is the
    # hash of the authored file, unchanged by the envelope.
    refute Map.has_key?(payload["spec"], "derivedFrom")
    assert receipt["specAddress"] == R5e.Canonical.hash(payload["spec"])

    {:ok, entry, _} =
      R5e.ResourceStore.get(
        "core.r5e.io",
        "v1",
        "KindDefinition",
        "test.r5e.io/v1alpha1/FromADocument"
      )

    assert entry["derivedFrom"] == address
    assert entry["actor"] == R5e.TestHelpers.key_id_for("test:alice")
    assert entry["admissionEvent"] == receipt["eventRef"]

    {:ok, kind} = R5e.KindRegistry.get("test.r5e.io", "v1alpha1", "FromADocument")
    assert R5e.Kind.to_map(kind)["derivedFrom"] == address
  end
end
