defmodule R5e.AdmissionTest.DenyingPolicy do
  @moduledoc false
  @behaviour R5e.Policy

  @meta %{
    "engine" => "test",
    "decision" => "deny",
    "bundle" => "sha256:abc",
    "bundleRef" => "x/y/Z/w",
    "matched" => ["p1"],
    "generations" => %{}
  }

  def meta, do: @meta

  @impl true
  def authorize(_request), do: {:deny, "nope", @meta}
end

defmodule R5e.AdmissionTest.LegacyPolicy do
  @moduledoc false
  @behaviour R5e.Policy

  @impl true
  def authorize(_request), do: :ok
end

defmodule R5e.AdmissionTest.MalformedPolicy do
  @moduledoc false

  # Deliberately outside the R5e.Policy contract, so no @behaviour here.
  def authorize(_request), do: :maybe
end

defmodule R5e.AdmissionTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  alias R5e.AdmissionTest.{DenyingPolicy, LegacyPolicy, MalformedPolicy}

  @allow_all %{
    "engine" => "allow-all",
    "decision" => "allow",
    "bundle" => nil,
    "bundleRef" => nil,
    "matched" => [],
    # §7: what the engine read and could be contended on. A constant
    # reads nothing.
    "generations" => %{},
    # §5: and what it wrote inside the decision. A constant writes nothing.
    "derivedObjects" => []
  }

  defp with_policy(module) do
    previous = Application.get_env(:r5e, :policy)
    Application.put_env(:r5e, :policy, module)
    ExUnit.Callbacks.on_exit(fn -> Application.put_env(:r5e, :policy, previous) end)
  end

  test "a denial is itself recorded on the log — requests are acts" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "DenialProbe"}))

    # Schema violation: required "title" missing.
    {:denied, receipt} =
      admit("test.r5e.io", "v1alpha1", "DenialProbe", "bad-one", %{"nope" => true})

    assert receipt["outcome"] == "denied"
    assert receipt["reason"] =~ "validate"

    denial_event = Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))
    assert denial_event["kind"] == "admission.denied"

    {:ok, payload_bytes} = R5e.CAS.get(denial_event["payload"])
    payload = Jason.decode!(payload_bytes)
    assert payload["outcome"] == "denied"
    assert payload["target"]["name"] == "bad-one"

    # And the denied instance never reached the substrate.
    assert {:error, :not_found} =
             R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "DenialProbe", "bad-one")
  end

  test "an unattributable request is refused, not recorded — it is not an act (§12)" do
    before = length(R5e.Log.events())

    {:denied, receipt} =
      R5e.Admission.admit(%{
        envelope: nil,
        group: "core.r5e.io",
        version: "v1",
        kind: "KindDefinition",
        name: nil,
        spec: kind_spec()
      })

    assert receipt["reason"] =~ "authenticate: malformed envelope"
    assert receipt["recorded"] == false
    refute Map.has_key?(receipt, "event")
    assert length(R5e.Log.events()) == before
  end

  test "an attributable authenticate denial is recorded — the signer is known" do
    {:denied, receipt} = R5e.Admission.admit(wrong_origin_request())

    assert receipt["reason"] =~ "authenticate: wrong origin"
    assert receipt["recorded"] == true
    assert Enum.any?(R5e.Log.events(), &(&1["hash"] == receipt["event"]))

    payload = payload_of(receipt)
    assert payload["identity"] == "signed"
    assert payload["actor"]["id"] == R5e.TestHelpers.key_id_for("test:alice")
    assert payload["origin"] == "sha256:" <> String.duplicate("a", 64)
  end

  test "a granted receipt names what it admitted and where its spec landed" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "AddressedThing"}))
    spec = %{"title" => "addressed"}

    {:ok, receipt} = admit("test.r5e.io", "v1alpha1", "AddressedThing", "a1", spec)

    assert receipt["name"] == "a1"
    assert receipt["specAddress"] == R5e.Canonical.hash(spec)

    {:ok, entry, _} = R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "AddressedThing", "a1")
    assert entry["specAddress"] == receipt["specAddress"]

    # The address is honest: the canonical bytes are in the CAS at it.
    assert {:ok, bytes} = R5e.CAS.get(receipt["specAddress"])
    assert Jason.decode!(bytes) == spec

    # The log is not the place for the address; the receipt is.
    payload = payload_of(receipt)
    assert payload["target"]["name"] == "a1"
    refute Map.has_key?(payload, "specAddress")
  end

  test "an unnamed instance gets its canonical-hash name back on the receipt" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "UnnamedThing"}))
    spec = %{"title" => "no name of its own"}

    {:ok, receipt} = admit("test.r5e.io", "v1alpha1", "UnnamedThing", nil, spec)

    assert receipt["name"] == R5e.Canonical.hash(spec)
    assert receipt["specAddress"] == receipt["name"]

    assert {:ok, _, _} =
             R5e.ResourceStore.get("test.r5e.io", "v1alpha1", "UnnamedThing", receipt["name"])
  end

  test "a denial carries the requested name and no specAddress — nothing was stored" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "UnstoredThing"}))

    {:denied, receipt} =
      admit("test.r5e.io", "v1alpha1", "UnstoredThing", "never-was", %{"nope" => true})

    assert receipt["name"] == "never-was"
    refute Map.has_key?(receipt, "specAddress")

    {:denied, anonymous} =
      admit("test.r5e.io", "v1alpha1", "UnstoredThing", nil, %{"nope" => true})

    assert Map.fetch!(anonymous, "name") == nil
    refute Map.has_key?(anonymous, "specAddress")
  end

  test "receipts carry assurance label and epistemic scope" do
    {:ok, receipt} = admit_kind(kind_spec(%{"kind" => "ScopedThing"}))
    assert receipt["assurance"] == "observed"
    assert %{"claims" => _, "doesNotClaim" => _} = receipt["epistemicScope"]
  end

  test "a granted receipt and its recorded payload name the policy that allowed it" do
    {:ok, receipt} = admit_kind(kind_spec(%{"kind" => "PolicyMetaThing"}))

    assert receipt["policy"] == @allow_all
    assert payload_of(receipt)["policy"] == @allow_all
  end

  test "a policy denial records the engine's own account of the decision" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "PolicyDeniedThing"}))
    with_policy(DenyingPolicy)

    {:denied, receipt} =
      admit("test.r5e.io", "v1alpha1", "PolicyDeniedThing", "whatever", %{"title" => "x"})

    assert receipt["outcome"] == "denied"
    assert String.starts_with?(receipt["reason"], "authorize:")
    assert receipt["reason"] =~ "nope"
    assert receipt["policy"] == DenyingPolicy.meta()
    assert payload_of(receipt)["policy"] == DenyingPolicy.meta()
  end

  test "a policy that predates the metadata contract is recorded as engine unknown" do
    with_policy(LegacyPolicy)

    {:ok, receipt} = admit_kind(kind_spec(%{"kind" => "LegacyPolicyThing"}))

    assert receipt["policy"] == %{
             "engine" => "unknown",
             "decision" => "allow",
             "bundle" => nil,
             "bundleRef" => nil,
             "matched" => [],
             "generations" => %{},
             "derivedObjects" => []
           }

    assert payload_of(receipt)["policy"] == receipt["policy"]
  end

  test "an authenticate-stage denial carries no policy key — no policy ran" do
    {:denied, receipt} = R5e.Admission.admit(wrong_origin_request())

    assert receipt["reason"] =~ "authenticate"
    refute Map.has_key?(receipt, "policy")
    refute Map.has_key?(payload_of(receipt), "policy")
  end

  test "a constraints-stage denial still says which policy allowed it" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "LateDenialThing"}))

    {:denied, receipt} =
      admit("test.r5e.io", "v1alpha1", "LateDenialThing", "x", %{})

    assert String.starts_with?(receipt["reason"], "validateConstraints:")
    assert receipt["policy"] == @allow_all
    assert payload_of(receipt)["policy"] == @allow_all
  end

  test "a structure-stage denial carries no policy — structure is judged before policy runs" do
    {:denied, receipt} =
      admit("test.r5e.io", "v1alpha1", "NeverDefined", "x", %{"title" => "x"})

    assert String.starts_with?(receipt["reason"], "validateStructure:")
    assert receipt["reason"] =~ "unknown Kind"
    refute Map.has_key?(receipt, "policy")
    refute Map.has_key?(payload_of(receipt), "policy")
  end

  test "a policy answer outside the contract fails closed, with a receipt" do
    with_policy(MalformedPolicy)

    {:denied, receipt} = admit_kind(kind_spec(%{"kind" => "MalformedPolicyThing"}))

    assert String.starts_with?(
             receipt["reason"],
             "authorize: policy returned a malformed answer"
           )

    assert receipt["reason"] =~ ":maybe"
    assert receipt["policy"]["decision"] == "error"
    assert receipt["policy"]["engine"] == "unknown"
    assert payload_of(receipt)["policy"] == receipt["policy"]
  end

  # Spec 011 §2: an `authenticate` denial that *is* recorded. The signer
  # is known, so the asking is an act; the request is simply addressed to
  # another chain.
  defp wrong_origin_request do
    R5e.TestHelpers.sign_request(%{
      group: "core.r5e.io",
      version: "v1",
      kind: "KindDefinition",
      name: nil,
      spec: kind_spec(),
      sign_opts: [origin: "sha256:" <> String.duplicate("a", 64)]
    })
  end
end
