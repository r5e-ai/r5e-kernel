defmodule R5e.KernelPolicyGovernanceTest do
  @moduledoc """
  The four properties an admitted kernel policy bundle has to have for
  "admitted" to mean what it says, each of them a defect the 2026-09-05
  adversarial review demonstrated on the frozen candidate:

  * a candidate that would deny the node key's own governance acts is
    **refused at admission**, with a receipt that names the acts (B1/K2);
  * an operator's admitted bundle **survives a restart**, and the shipped
    default is re-imposed only by an explicit, recorded recovery act
    (B2/K1);
  * a revoked role Endorsement **stays revoked** across a restart (K4);
  * a boot-time act this node cannot sign or cannot get admitted refuses
    with an operator-legible message, never a `MatchError` (K6, B1).

  Every test here boots a real kernel over a throwaway data directory with
  `R5e.Policy.KernelCedar` in force, and "restart" means stopping and
  starting the application, which is the only thing that reproduces any of
  them.
  """

  use ExUnit.Case, async: false

  import R5e.TestHelpers

  alias R5e.Policy.{EngineBuild, KernelCedar}

  @bundle_ref "core.r5e.io/v1/PolicyBundle/active"

  # Permits every admission the node key signs directly — a plausible
  # operator policy, narrower than the shipped default (which also admits
  # acts merely *rooted* at the node key) and still permitting all four
  # governance acts.
  @operator """
  @id("operator-node-only")
  permit (
    principal,
    action == R5e::Action::"admit",
    resource
  )
  when {
    context.direct_node_signature
  };
  """

  # Permits an action that does not exist, so nothing at all is admitted.
  # This is the review's `@lockout` fixture: syntactically valid Cedar that
  # bricks the node.
  @lockout """
  @id("nothing")
  permit (
    principal,
    action == R5e::Action::"never",
    resource
  )
  when {
    context.direct_node_signature
  };
  """

  # Permits exactly its own replacement and nothing else — the subtler
  # lockout, and the reason the invariant is over four acts rather than
  # one: the node could still swap its policy, and could no longer admit
  # an Endorsement, transition its meta-Kind, or admit the next engine
  # descriptor, so the next kernel upgrade would not boot.
  @half_lockout """
  @id("only-its-own-replacement")
  permit (
    principal,
    action == R5e::Action::"admit",
    resource == R5e::Resource::"core.r5e.io/v1/PolicyBundle/active"
  )
  when {
    context.direct_node_signature
  };
  """

  setup do
    previous = %{
      data_dir: Application.fetch_env!(:r5e, :data_dir),
      policy: Application.fetch_env!(:r5e, :policy),
      seed: Application.fetch_env!(:r5e, :seed_kernel_policy),
      recover: Application.get_env(:r5e, :kernel_policy_recover, false),
      lock: Application.get_env(:r5e, :cedar_cargo_lock_path)
    }

    dir =
      Path.join(System.tmp_dir!(), "r5e-kernel-governance-#{System.unique_integer([:positive])}")

    :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :data_dir, dir)
    Application.put_env(:r5e, :policy, KernelCedar)
    Application.put_env(:r5e, :seed_kernel_policy, true)
    {:ok, _apps} = Application.ensure_all_started(:r5e)

    on_exit(fn ->
      Application.stop(:r5e)
      Application.put_env(:r5e, :data_dir, previous.data_dir)
      Application.put_env(:r5e, :policy, previous.policy)
      Application.put_env(:r5e, :seed_kernel_policy, previous.seed)
      Application.put_env(:r5e, :kernel_policy_recover, previous.recover)

      if previous.lock,
        do: Application.put_env(:r5e, :cedar_cargo_lock_path, previous.lock),
        else: Application.delete_env(:r5e, :cedar_cargo_lock_path)

      {:ok, _apps} = Application.ensure_all_started(:r5e)
      File.rm_rf!(dir)
    end)

    {:ok, dir: dir}
  end

  # -- B1: the governance-acts invariant ----------------------------------

  test "a bundle that would deny every admission is refused, naming all four acts" do
    before = active_bundle()

    assert {:denied, receipt} = admit_bundle(@lockout)

    assert String.starts_with?(
             receipt["reason"],
             "authorize: candidate would deny the node key's governance acts: "
           )

    assert receipt["reason"] =~ "supersede of #{@bundle_ref}"
    assert receipt["reason"] =~ "admission of core.r5e.io/v1/Endorsement"
    assert receipt["reason"] =~ "transition of core.r5e.io/v1/KindDefinition"
    assert receipt["reason"] =~ "admission of the measured engine descriptor"

    # The bundle in force is untouched, and the refusal is on the chain.
    assert active_bundle() == before
    assert List.last(R5e.Log.events())["kind"] == "admission.denied"
  end

  test "a bundle that permits only its own replacement is refused for the other three" do
    assert {:denied, receipt} = admit_bundle(@half_lockout)

    reason = receipt["reason"]
    assert reason =~ "candidate would deny the node key's governance acts"
    refute reason =~ "supersede of #{@bundle_ref}"
    assert reason =~ "admission of core.r5e.io/v1/Endorsement"
    assert reason =~ "transition of core.r5e.io/v1/KindDefinition"
    assert reason =~ "admission of the measured engine descriptor"
  end

  test "the refusal is recorded as a kernel decision, not as a Cedar evaluation error" do
    assert {:denied, receipt} = admit_bundle(@lockout)

    policy = receipt["policy"]
    assert policy["decision"] == "deny"
    assert policy["engine"] == "cedar"
    assert policy["bundleRef"] == @bundle_ref
    assert policy["evaluation"] == nil
    assert policy["note"] =~ "the kernel refused the candidate PolicyBundle (governanceActs)"
    assert policy["note"] =~ "the request itself was not evaluated"
  end

  # -- K7: a malformed candidate is a denial, not an evaluation error -----

  test "a candidate whose source is not Cedar is denied with cause candidate" do
    address = put_object("this is not Cedar", "text/cedar", R5e.DSSE.node_key_id())

    assert {:denied, receipt} = admit_bundle_at(address)

    assert receipt["reason"] =~ "candidate PolicyBundle is not a valid Cedar core policy"
    refute receipt["reason"] =~ "evaluation error"

    policy = receipt["policy"]
    assert policy["decision"] == "deny"
    assert policy["evaluation"] == nil
    assert policy["note"] =~ "the kernel refused the candidate PolicyBundle (candidate)"
  end

  # -- B2: seeding is keyed on presence -----------------------------------

  test "an operator's admitted kernel bundle survives a restart" do
    default_source = bundle_source()
    address = put_object(@operator, "text/cedar", R5e.DSSE.node_key_id())

    assert {:ok, _receipt} = admit_bundle_at(address)
    assert bundle_source() == address

    restart!()

    assert bundle_source() == address,
           "boot re-imposed the shipped default over an admitted bundle"

    refute bundle_source() == default_source
  end

  test "R5E_KERNEL_POLICY_RECOVER re-admits the shipped default as a recorded act" do
    default_source = bundle_source()
    address = put_object(@operator, "text/cedar", R5e.DSSE.node_key_id())
    assert {:ok, _receipt} = admit_bundle_at(address)

    Application.put_env(:r5e, :kernel_policy_recover, true)
    restart!()

    assert bundle_source() == default_source

    # An ordinary admission by the node key, decided by the bundle it
    # replaced — not a substitution behind the chain's back.
    event = List.last(R5e.Log.events())
    assert event["kind"] == "admission.granted"
    assert {:ok, payload} = R5e.Log.payload(event)
    assert get_in(payload, ["target", "kind"]) == "PolicyBundle"
    assert payload["actor"]["id"] == R5e.DSSE.node_key_id()
    assert payload["policy"]["decision"] == "allow"
    assert payload["policy"]["bundle"] == previous_bundle_address(address)
  end

  test "a restart without the flag re-admits nothing at all" do
    address = put_object(@operator, "text/cedar", R5e.DSSE.node_key_id())
    assert {:ok, _receipt} = admit_bundle_at(address)
    events = length(R5e.Log.events())

    restart!()

    assert length(R5e.Log.events()) == events
  end

  # -- K4: a revoked role Endorsement stays revoked -----------------------

  test "revoking the retention Endorsement is not undone by the next boot" do
    subject = R5e.Request.key_id(R5e.Bootstrap.retention_key())
    ref = R5e.Bootstrap.role_endorsement("retention", subject)
    assert is_binary(ref)

    assert %{"status" => "effective", "endorsement" => ^ref} =
             R5e.Bootstrap.role_status("retention")

    assert {:ok, _receipt} =
             admit(
               "core.r5e.io",
               "v1",
               "Revocation",
               nil,
               %{"revokes" => %{"$ref" => ref}, "reason" => "compromised"},
               %{actor: R5e.DSSE.node_key_id()}
             )

    assert R5e.Bootstrap.role_endorsement("retention", subject) == nil
    endorsements = count_endorsements(subject)

    restart!()

    assert R5e.Bootstrap.role_endorsement("retention", subject) == nil,
           "boot re-minted the revoked role Endorsement"

    assert count_endorsements(subject) == endorsements

    status = R5e.Bootstrap.role_status("retention")
    assert status["status"] == "withheld"
    assert status["endorsement"] == nil
    assert status["reason"] =~ "explicit re-endorsement required"
    assert status["reason"] =~ ref
    assert status["reason"] =~ "is revoked at"
    assert status["reason"] =~ "a revocation a restart reverses is a suspension"
  end

  test "re-endorsing the role is an explicit act, and then boot leaves it alone" do
    subject = R5e.Request.key_id(R5e.Bootstrap.retention_key())
    ref = R5e.Bootstrap.role_endorsement("retention", subject)

    assert {:ok, _receipt} =
             admit(
               "core.r5e.io",
               "v1",
               "Revocation",
               nil,
               %{"revokes" => %{"$ref" => ref}, "reason" => "compromised"},
               %{actor: R5e.DSSE.node_key_id()}
             )

    assert {:ok, renewal} =
             R5e.Bootstrap.endorse_role(R5e.Bootstrap.retention_key().public, "retention",
               kinds: ["core.r5e.io/v1/CasExpired"]
             )

    assert %{"status" => "effective", "endorsement" => endorsement} =
             R5e.Bootstrap.role_status("retention")

    assert endorsement == renewal["eventRef"]

    events = length(R5e.Log.events())
    restart!()

    assert length(R5e.Log.events()) == events
    assert R5e.Bootstrap.role_endorsement("retention", subject) == renewal["eventRef"]
  end

  test "role_status names a role that was never endorsed" do
    assert %{"status" => "unendorsed", "endorsement" => nil, "reason" => nil} =
             R5e.Bootstrap.role_status("no-such-role")
  end

  # -- K6: a node key this node does not hold -----------------------------

  test "a node act refuses legibly when the local signer is not the node key" do
    successor_id = succeed_node_key!()

    error =
      assert_raise R5e.Bootstrap.Refused, fn ->
        R5e.Bootstrap.admit_as_node("core.r5e.io", "v1", "Deployment", "deployment", %{
          "commons" => false,
          "declaredBy" => successor_id
        })
      end

    assert error.message =~ "no longer the node key"
    assert error.message =~ successor_id
    assert error.message =~ R5e.DSSE.local_key_id()
    assert error.message =~ "core.r5e.io/v1/Deployment/deployment"
    assert error.message =~ "Recovery:"
  end

  test "an engine rebuild after a succession this node cannot sign for refuses the boot" do
    successor_id = succeed_node_key!()

    # A clean restart still works: nothing needs admitting.
    assert {:ok, _apps} = restart!()

    # Now the deployment upgrades and the measured descriptor changes, so
    # the boot has an act to record. Before this pass that was a MatchError
    # inside `admit_bytes_again/3`.
    lock = Path.join(System.tmp_dir!(), "governance-lock-#{System.unique_integer([:positive])}")
    File.write!(lock, ~s([[package]]\nname = "cedar-policy"\nversion = "9.9.9"\n))
    Application.put_env(:r5e, :cedar_cargo_lock_path, lock)

    outcome = restart!()

    Application.delete_env(:r5e, :cedar_cargo_lock_path)
    File.rm(lock)

    text = inspect(outcome, limit: :infinity, printable_limit: :infinity)
    refute text =~ "MatchError"
    assert text =~ "R5e.Bootstrap.Refused"
    assert text =~ "no longer the node key"
    assert text =~ successor_id
  end

  # -- helpers ------------------------------------------------------------

  defp restart! do
    :ok = Application.stop(:r5e)
    Application.ensure_all_started(:r5e)
  end

  defp active_bundle do
    case R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active") do
      {:ok, entry, _lineage} -> entry
      other -> other
    end
  end

  defp bundle_source, do: get_in(active_bundle(), ["spec", "sourceRef", "$ref"])

  defp previous_bundle_address(source_address) do
    R5e.CAS.spec_address(%{
      "engine" => "cedar",
      "governs" => ["core.r5e.io"],
      "sourceRef" => %{"$ref" => source_address},
      "description" => "operator policy"
    })
  end

  defp admit_bundle(source) do
    source |> put_object("text/cedar", R5e.DSSE.node_key_id()) |> admit_bundle_at()
  end

  defp admit_bundle_at(address) do
    admit(
      "core.r5e.io",
      "v1",
      "PolicyBundle",
      "active",
      %{
        "engine" => "cedar",
        "governs" => ["core.r5e.io"],
        "sourceRef" => %{"$ref" => address},
        "description" => "operator policy"
      },
      %{actor: R5e.DSSE.node_key_id()}
    )
  end

  defp count_endorsements(subject) do
    Enum.count(R5e.Log.events(), fn event ->
      with "admission.granted" <- event["kind"],
           {:ok, payload} <- R5e.Log.payload(event),
           "core.r5e.io/v1/Endorsement" <- R5e.Admission.target_path(payload) do
        payload["spec"]["subject"] == subject
      else
        _ -> false
      end
    end)
  end

  defp succeed_node_key! do
    successor = key_for("test:kernel-successor")
    successor_id = R5e.Request.key_id(successor)

    assert {:ok, _receipt} =
             admit(
               "core.r5e.io",
               "v1",
               "Succession",
               nil,
               %{
                 "predecessor" => R5e.DSSE.node_key_id(),
                 "successor" => successor_id,
                 "successorKey" => %{
                   "algorithm" => "ed25519",
                   "bytes" => Base.encode64(successor.public)
                 },
                 "reason" => "rotation to a key this node does not hold"
               },
               %{keys: [:node, successor]}
             )

    assert R5e.DSSE.node_key_id() == successor_id
    refute R5e.DSSE.local_key_id() == successor_id
    assert EngineBuild.cached_address() != nil

    successor_id
  end
end
