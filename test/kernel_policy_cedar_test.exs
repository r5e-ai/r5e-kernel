defmodule R5e.KernelPolicyCedarTest.TenantDeny do
  @moduledoc false
  def authorize(_request), do: {:deny, "tenant denied"}
end

defmodule R5e.KernelPolicyCedarTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  alias R5e.Policy.{EngineBuild, EvaluationRecord, KernelCedar}

  setup do
    previous = %{
      data_dir: Application.fetch_env!(:r5e, :data_dir),
      policy: Application.fetch_env!(:r5e, :policy),
      seed: Application.fetch_env!(:r5e, :seed_kernel_policy)
    }

    dir = Path.join(System.tmp_dir!(), "r5e-kernel-policy-#{System.unique_integer([:positive])}")
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
      {:ok, _apps} = Application.ensure_all_started(:r5e)
      File.rm_rf!(dir)
    end)

    :ok
  end

  test "bootstrap admits the core policy, source and measured engine" do
    assert KernelCedar.ready?()

    assert {:ok, bundle, []} =
             R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active")

    source = bundle["spec"]["sourceRef"]["$ref"]
    assert bundle["spec"]["governs"] == ["core.r5e.io"]
    assert {:ok, _source_admission} = R5e.RefIndex.cas_object(source)
    assert R5e.RefIndex.public_record_citations(source) != []

    build = R5e.Policy.EngineBuild.cached_address()
    assert is_binary(build)
    assert {:ok, _build_admission} = R5e.RefIndex.cas_object(build)
  end

  test "a restart without seeding restores the exact admitted engine proof" do
    original_build = EngineBuild.cached_address()
    assert :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :seed_kernel_policy, false)
    assert {:ok, _apps} = Application.ensure_all_started(:r5e)

    assert KernelCedar.ready?()
    assert EngineBuild.cached_address() == original_build

    node = R5e.DSSE.node_key_id()

    assert {:ok, %{"decision" => "allow", "engineBuild" => ^original_build}} =
             KernelCedar.authorize(policy_request(node, "core.r5e.io"))
  end

  test "a missing or damaged cached engine proof refuses an actual evaluation" do
    node = R5e.DSSE.node_key_id()
    request = policy_request(node, "core.r5e.io")
    build = EngineBuild.cached_address()

    EngineBuild.clear_cached_address()
    refute KernelCedar.ready?()

    assert {:deny, reason, %{"evaluation" => nil, "engineBuild" => nil}} =
             KernelCedar.authorize(request)

    assert reason =~ "no cached Cedar engine descriptor"

    :ok = EngineBuild.cache_address(build)
    build_path = Path.join(R5e.CAS.root(), R5e.CAS.relative_path(build))
    assert :ok = File.rm(build_path)
    refute KernelCedar.ready?()

    assert {:deny, damaged_reason, %{"evaluation" => nil, "engineBuild" => ^build}} =
             KernelCedar.authorize(request)

    assert damaged_reason =~ "cached Cedar engine descriptor is absent or invalid"

    events_before_restart = length(R5e.Log.events())
    assert :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :seed_kernel_policy, false)
    assert {:ok, _apps} = Application.ensure_all_started(:r5e)

    refute KernelCedar.ready?()
    assert length(R5e.Log.events()) == events_before_restart

    assert {:deny, restart_reason, %{"evaluation" => nil}} = KernelCedar.authorize(request)
    assert restart_reason =~ "no cached Cedar engine descriptor"
  end

  test "seeding restores a missing measured descriptor through only the exact bootstrap path" do
    build = EngineBuild.cached_address()
    {:ok, expected_bytes} = R5e.CAS.get(build)
    build_path = Path.join(R5e.CAS.root(), R5e.CAS.relative_path(build))
    assert :ok = File.rm(build_path)
    events_before_restart = length(R5e.Log.events())

    assert :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :seed_kernel_policy, true)
    assert {:ok, _apps} = Application.ensure_all_started(:r5e)

    assert KernelCedar.ready?()
    assert EngineBuild.cached_address() == build
    assert {:ok, ^expected_bytes} = R5e.CAS.get(build)
    assert length(R5e.Log.events()) == events_before_restart + 1

    last_event = List.last(R5e.Log.events())
    assert {:ok, payload} = R5e.Log.payload(last_event)
    assert get_in(payload, ["target", "kind"]) == "CasObject"
    assert payload["spec"]["address"] == build
    assert payload["policy"]["bootstrap"] == true
    assert payload["policy"]["engineBuild"] == build
  end

  test "bootstrap bypasses an active policy only for this boot's exact engine descriptor" do
    invalid = put_object("this is not Cedar", "text/cedar", R5e.DSSE.node_key_id())
    replace_bundle_source(invalid)
    measurement = EngineBuild.measure()
    node = R5e.DSSE.node_key_id()

    arbitrary_bytes = "not the measured engine descriptor"

    arbitrary_request =
      engine_build_request(
        node,
        arbitrary_bytes,
        R5e.CAS.object_spec(arbitrary_bytes, "text/plain")
      )

    assert {:deny, reason, meta} =
             KernelCedar.with_bootstrap(
               fn -> KernelCedar.authorize(arbitrary_request) end,
               measurement
             )

    assert reason =~ "cedar evaluation error"
    refute meta["bootstrap"]

    exact_request = engine_build_request(node, measurement.bytes, measurement.spec)

    assert {:ok,
            %{
              "bootstrap" => true,
              "engineBuild" => engine_build,
              "evaluation" => nil
            }} =
             KernelCedar.with_bootstrap(
               fn -> KernelCedar.authorize(exact_request) end,
               measurement
             )

    assert engine_build == measurement.address
  end

  test "a node-signed admission records its exact Cedar question" do
    node = R5e.DSSE.node_key_id()

    assert {:ok, receipt} =
             R5e.Bootstrap.admit_as_node(
               "core.r5e.io",
               "v1",
               "Deployment",
               "deployment",
               %{"commons" => false, "declaredBy" => node}
             )

    policy = receipt["policy"]
    assert policy["engine"] == "cedar"
    assert policy["decision"] == "allow"
    assert policy["source"] == bundle_source()
    assert policy["generations"]["core.r5e.io/v1/PolicyBundle/active"] == 14
    assert [policy["evaluation"]] == receipt["derivedObjects"]

    assert {:ok, evaluation} = EvaluationRecord.fetch(policy["evaluation"])
    assert evaluation["bundle"] == policy["bundle"]
    assert evaluation["source"] == policy["source"]
    assert evaluation["engineBuild"] == policy["engineBuild"]
    assert evaluation["decision"] == policy["decision"]
    assert evaluation["matched"] == policy["matched"]
  end

  test "a missing bundle fails closed except for the narrow bootstrap seed" do
    delete_active_bundle()
    refute KernelCedar.ready?()

    node = R5e.DSSE.node_key_id()

    assert {:denied, receipt} =
             R5e.Bootstrap.admit_as_node(
               "core.r5e.io",
               "v1",
               "Deployment",
               "deployment",
               %{"commons" => false, "declaredBy" => node}
             )

    assert receipt["reason"] =~ "no admitted core.r5e.io/v1/PolicyBundle/active"
    assert receipt["policy"]["decision"] == "error"
    refute receipt["policy"]["bootstrap"]

    assert {:ok, %{"bootstrap" => true}} =
             KernelCedar.with_bootstrap(fn ->
               KernelCedar.authorize(policy_request(node, "core.r5e.io"))
             end)

    assert {:deny, _reason, %{"decision" => "error"}} =
             KernelCedar.with_bootstrap(fn ->
               KernelCedar.authorize(policy_request("tenant:policy-admin", "core.r5e.io"))
             end)

    assert {:deny, _reason, %{"decision" => "error"}} =
             KernelCedar.with_bootstrap(fn ->
               KernelCedar.authorize(policy_request(node, "tenant.example"))
             end)
  end

  test "invalid admitted policy bytes fail closed" do
    invalid = put_object("this is not Cedar", "text/cedar", R5e.DSSE.node_key_id())
    replace_bundle_source(invalid)
    node = R5e.DSSE.node_key_id()

    assert {:denied, receipt} =
             R5e.Bootstrap.admit_as_node(
               "core.r5e.io",
               "v1",
               "Deployment",
               "deployment",
               %{"commons" => false, "declaredBy" => node}
             )

    assert receipt["reason"] =~ "cedar evaluation error"
    assert receipt["policy"]["decision"] == "error"
    assert receipt["policy"]["evaluation"] == nil
  end

  test "a non-node signer cannot replace the kernel PolicyBundle" do
    {:ok, bundle, []} =
      R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active")

    assert {:denied, receipt} =
             admit_request(%{
               actor: "tenant:policy-admin",
               group: "core.r5e.io",
               version: "v1",
               kind: "PolicyBundle",
               name: "active",
               spec: bundle["spec"]
             })

    assert String.starts_with?(receipt["reason"], "validateStructure: ")
    assert receipt["reason"] =~ "readmitBy: nodeKey"
  end

  test "the kernel evaluator does not consult a tenant policy module" do
    Application.put_env(:r5e, :policy, R5e.KernelPolicyCedarTest.TenantDeny)
    node = R5e.DSSE.node_key_id()

    request = %{
      actor: %{"id" => node},
      group: "core.r5e.io",
      version: "v1",
      kind: "Deployment",
      name: "deployment",
      spec: %{"commons" => false, "declaredBy" => node},
      identity: "signed",
      authority_roots: [],
      resolved_authority: [],
      resolved: []
    }

    assert {:ok, %{"decision" => "allow", "engine" => "cedar"}} =
             KernelCedar.authorize(request)

    assert {:deny, _reason,
            %{"decision" => "deny", "engine" => "cedar", "evaluation" => evaluation}} =
             KernelCedar.authorize(policy_request("tenant:caller", "tenant.example"))

    assert {:ok, %{"decision" => "deny"}} = EvaluationRecord.fetch(evaluation)
  end

  defp bundle_source do
    {:ok, bundle, []} =
      R5e.ResourceStore.get("core.r5e.io", "v1", "PolicyBundle", "active")

    bundle["spec"]["sourceRef"]["$ref"]
  end

  defp delete_active_bundle do
    Agent.update(R5e.ResourceStore, fn state ->
      update_in(state, [:entries], &Map.delete(&1, "core.r5e.io/v1/PolicyBundle/active"))
    end)
  end

  defp replace_bundle_source(address) do
    Agent.update(R5e.ResourceStore, fn state ->
      update_in(state, [:entries, "core.r5e.io/v1/PolicyBundle/active"], fn entry ->
        spec = put_in(entry["spec"], ["sourceRef", "$ref"], address)
        %{entry | "spec" => spec, "specAddress" => R5e.CAS.spec_address(spec)}
      end)
    end)
  end

  defp policy_request(actor, group) do
    %{
      actor: %{"id" => actor},
      group: group,
      version: "v1",
      kind: "Workload",
      name: "example",
      spec: %{},
      identity: "signed",
      authority_roots: [],
      resolved_authority: [],
      resolved: []
    }
  end

  defp engine_build_request(node, bytes, spec) do
    %{
      actor: %{"id" => node},
      signers: [node],
      group: "core.r5e.io",
      version: "v1",
      kind: "CasObject",
      name: spec["address"],
      spec: spec,
      cas_bytes: bytes,
      identity: "signed",
      authority_roots: [],
      resolved_authority: [],
      resolved: []
    }
  end
end
