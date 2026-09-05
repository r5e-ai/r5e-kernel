defmodule R5e.Policy.KernelCedar do
  @moduledoc """
  Kernel-owned Cedar policy for admissions delegated to the kernel layer.

  The active policy is the admitted
  `core.r5e.io/v1/PolicyBundle/active` resource. Its detached source and
  measured engine descriptor are admitted `CasObject`s. Each evaluation
  records the exact request and entities, the bundle and source addresses,
  and the bundle generation used by the commit check.

  Bootstrap is a narrow fixpoint: while `R5e.Bootstrap` synchronously seeds,
  a node-signed core seed receives an explicit bootstrap decision when no
  bundle exists. An exact admission of the engine descriptor measured for
  that boot may also receive a bootstrap decision while an older bundle is
  active. The flag and measurement are process-local and cleared in an
  `after` block. A missing bundle or engine proof at any other time fails
  closed.

  ## The governance-acts invariant

  A candidate bundle is evaluated against the four acts the node key must
  keep in order to govern this chain — superseding this bundle, admitting
  an `Endorsement`, transitioning the meta-Kind, and admitting the
  measured engine descriptor. A candidate that would deny any of them is
  **inadmissible**: the admission is refused with a recorded denial naming
  the acts it would deny. A correctly signed, syntactically valid bundle
  can still carry that logic error, and without this check admitting one
  locks the node out of its own governance, including out of replacing the
  bundle that did it.

  The check runs on the candidate's own source, at `authorize`, on the
  bootstrap path as well as the ordinary one, so the first bundle a chain
  records is held to the same rule as its successors.

  ## Seeding is keyed on presence

  `seed_bundle/1` admits the shipped default only when no active bundle
  exists. An operator's admitted bundle therefore survives a restart:
  admission means what it says. The shipped default is not re-imposed when
  the two differ, so a kernel upgrade that changes `priv/policy/default.cedar`
  does not silently replace an operator's policy; re-admitting it is an
  explicit act, `R5E_KERNEL_POLICY_RECOVER=1`, which is recorded on the
  chain like any other admission and can be refused by the bundle in force.
  """

  @behaviour R5e.Policy

  alias R5e.Policy.{EngineBuild, EvaluationRecord}

  @group "core.r5e.io"
  @version "v1"
  @kind "PolicyBundle"
  @name "active"
  @bundle_ref "#{@group}/#{@version}/#{@kind}/#{@name}"
  @bootstrap_key {__MODULE__, :bootstrap}

  # The acts the node key must keep to govern this chain. A candidate
  # bundle that denies any of them is inadmissible: `{label, kind, name}`,
  # each evaluated as the node key acting on itself.
  @governance_acts [
    {"supersede of #{@bundle_ref}", @kind, @name},
    {"admission of #{@group}/#{@version}/Endorsement", "Endorsement", nil},
    {"transition of #{@group}/#{@version}/KindDefinition", "KindDefinition",
     "#{@group}/#{@version}/KindDefinition"},
    {"admission of the measured engine descriptor (#{@group}/#{@version}/CasObject)", "CasObject",
     nil}
  ]

  @doc "Whether the admitted kernel policy bundle and cached engine proof are present."
  @spec ready?() :: boolean()
  def ready? do
    match?({:ok, _entry, _lineage}, active_bundle()) and
      match?({:ok, _address}, admitted_engine_build())
  end

  @doc false
  @spec prepare_engine_build() :: EngineBuild.measurement()
  def prepare_engine_build do
    measurement = EngineBuild.measure()
    EngineBuild.clear_cached_address()

    if measured_engine_build_admitted?(measurement) do
      :ok = EngineBuild.cache_address(measurement.address)
    end

    measurement
  end

  @doc false
  @spec seed_engine_build_if_known(EngineBuild.measurement()) :: :ok
  def seed_engine_build_if_known(measurement) do
    case R5e.KindRegistry.get(@group, @version, "CasObject") do
      {:ok, _kind} -> seed_engine_build(measurement)
      {:error, :unknown_kind} -> :ok
    end
  end

  @doc "Admit the PolicyBundle Kind, policy source, engine descriptor and active bundle."
  @spec seed(EngineBuild.measurement()) :: :ok
  def seed(measurement \\ EngineBuild.measure()) do
    seed_kind()
    :ok = seed_engine_build(measurement)
    source_address = admit_bytes(File.read!(priv_path("policy/default.cedar")), "text/cedar")
    seed_bundle(source_address)
    :ok
  end

  @doc false
  def with_bootstrap(fun, engine_build \\ nil) when is_function(fun, 0) do
    previous = Process.get(@bootstrap_key)
    Process.put(@bootstrap_key, %{engine_build: engine_build})

    try do
      fun.()
    after
      if previous == nil,
        do: Process.delete(@bootstrap_key),
        else: Process.put(@bootstrap_key, previous)
    end
  end

  @impl true
  def authorize(request) do
    if bootstrap_engine_build_request?(request) do
      measurement = Process.get(@bootstrap_key).engine_build
      {:ok, bootstrap_meta(measurement.address, "exact engine descriptor measured for this boot")}
    else
      case active_bundle() do
        {:ok, bundle, _lineage} -> authorize_with_bundle(request, bundle)
        {:error, :not_found} -> authorize_without_bundle(request)
      end
    end
  end

  # The first bundle a chain records is held to the same candidate rules as
  # every later one: the bootstrap fixpoint decides *who* may seed, never
  # *what* may be seeded.
  defp authorize_without_bundle(request) do
    if bootstrap_request?(request) do
      case validate_candidate(request) do
        :ok ->
          {:ok,
           bootstrap_meta(nil, "node-signed core seed while the initial PolicyBundle is absent")}

        {:refused, reason, source, cause} ->
          {:deny, reason, refusal_meta(nil, source, cause)}
      end
    else
      {:deny, "no admitted #{@bundle_ref}; kernel admission fails closed",
       error_meta(nil, nil, "bundleMissing")}
    end
  end

  defp authorize_with_bundle(request, bundle) do
    with :ok <- validate_bundle(bundle),
         {:ok, engine_build} <- admitted_engine_build(),
         {:ok, source_address} <- source_address(bundle),
         {:ok, source} <- fetch_source(source_address),
         :ok <- validate_candidate(request),
         {:ok, request_json, entities_json} <- present(request),
         {:ok, result} <- R5e.Cedar.evaluate(source, request_json, entities_json) do
      answer(
        result,
        request,
        bundle,
        source_address,
        engine_build,
        request_json,
        entities_json
      )
    else
      # A refusal of the *candidate* is a decision the kernel made, not a
      # failure to ask Cedar about the request: the receipt says `deny` and
      # names the cause, rather than reporting an evaluation that never ran.
      {:refused, reason, source, cause} ->
        {:deny, reason, refusal_meta(bundle, source, cause)}

      {:error, reason, source, cause} ->
        {:deny, reason, error_meta(bundle, source, cause)}

      {:error, reason} ->
        {:deny, "cedar evaluation error (fail-closed): #{reason}",
         error_meta(bundle, nil, "evaluation")}
    end
  end

  defp answer(
         result,
         request,
         bundle,
         source_address,
         engine_build,
         request_json,
         entities_json
       ) do
    decision = to_string(result.decision)

    evaluation =
      EvaluationRecord.write(%{
        engine: "cedar",
        engine_build: engine_build,
        kind_definition: kind_definition_address(request),
        bundle: bundle["specAddress"],
        source: source_address,
        request_bytes: request_json,
        entities_bytes: entities_json,
        resolution: request[:resolved] || [],
        decision: decision,
        matched: result.matched_policies,
        resolved_authority: request[:resolved_authority] || []
      })

    meta = %{
      "engine" => "cedar",
      "decision" => decision,
      "bundle" => bundle["specAddress"],
      "bundleRef" => @bundle_ref,
      "source" => source_address,
      "shape" => nil,
      "evaluation" => evaluation,
      "engineBuild" => engine_build,
      "matched" => result.matched_policies,
      "generations" => %{@bundle_ref => bundle["admissionSeq"]},
      "derivedObjects" => [evaluation]
    }

    case result.decision do
      :allow -> {:ok, meta}
      :deny -> {:deny, "cedar denied kernel admission (deny by default)", meta}
    end
  end

  defp present(request) do
    actor = get_in(request, [:actor, "id"]) || ""
    node = R5e.DSSE.node_key_id()
    target = target_ref(request)

    cedar_request = %{
      "principal" => uid("R5e::Principal", actor),
      "action" => uid("R5e::Action", "admit"),
      "resource" => uid("R5e::Resource", target),
      "context" => %{
        "node_authorized" => actor == node or node in (request[:authority_roots] || []),
        "direct_node_signature" => actor == node,
        "target_group" => request[:group],
        "target_kind" => request[:kind]
      }
    }

    entities = [
      entity("R5e::Principal", actor, %{
        "authority_roots" => request[:authority_roots] || [],
        "identity" => request[:identity] || "unsigned"
      }),
      entity("R5e::Resource", target, %{})
    ]

    {:ok, R5e.Canonical.encode(cedar_request), R5e.Canonical.encode(entities)}
  rescue
    error -> {:error, Exception.message(error)}
  end

  defp validate_bundle(%{"spec" => %{"engine" => "cedar", "governs" => [@group]}}), do: :ok

  defp validate_bundle(_bundle),
    do:
      {:error, "#{@bundle_ref} does not declare Cedar over #{@group} (fail-closed)", nil,
       "bundleInvalid"}

  defp source_address(bundle) do
    case get_in(bundle, ["spec", "sourceRef", "$ref"]) do
      address when is_binary(address) ->
        {:ok, address}

      _ ->
        {:error, "#{@bundle_ref} has no bytes sourceRef (fail-closed)", nil, "sourceRefMalformed"}
    end
  end

  defp fetch_source(address) do
    case R5e.CAS.get(address) do
      {:ok, bytes} ->
        {:ok, bytes}

      {:error, _} ->
        {:error, "policy source #{address} is absent (fail-closed)", address, "sourceMissing"}
    end
  end

  # The naming contract restricts activation to the effective node key.
  # These additional checks prevent malformed Cedar source, and source that
  # would deny the node key's own governance acts, from becoming active.
  defp validate_candidate(%{group: @group, version: @version, kind: @kind, spec: spec}) do
    with %{"engine" => "cedar", "governs" => [@group], "sourceRef" => %{"$ref" => address}} <-
           spec,
         {:ok, source} <- R5e.CAS.get(address),
         :ok <- R5e.Cedar.validate_policy_syntax(source) do
      governance_acts(source, address)
    else
      _ ->
        {:refused, "candidate PolicyBundle is not a valid Cedar core policy", nil, "candidate"}
    end
  end

  defp validate_candidate(_request), do: :ok

  # Self-replacement is an admission rule: a bundle that would deny the acts
  # required to admit its successor is inadmissible. The same evaluation is
  # run for the three other acts the node key needs in order to keep
  # governing the chain, so a candidate cannot strand a node between two
  # policies either.
  defp governance_acts(source, address) do
    node = R5e.DSSE.node_key_id()

    case Enum.reject(@governance_acts, fn {_label, kind, name} ->
           permits_node?(source, node, kind, name)
         end) do
      [] ->
        :ok

      denied ->
        {:refused,
         "candidate would deny the node key's governance acts: " <>
           Enum.map_join(denied, "; ", fn {label, _kind, _name} -> label end), address,
         "governanceActs"}
    end
  end

  # The candidate decides a request it will itself receive: the node key
  # acting as itself on a core resource, presented exactly as `authorize`
  # presents a live one. An engine error on the candidate is a refusal —
  # a bundle whose answer cannot be obtained is not one this node can
  # demonstrate it survives.
  defp permits_node?(source, node, kind, name) do
    request = %{
      group: @group,
      version: @version,
      kind: kind,
      name: name,
      actor: %{"id" => node},
      identity: "signed",
      authority_roots: []
    }

    match?(
      {:ok, %{decision: :allow}},
      with {:ok, request_json, entities_json} <- present(request) do
        R5e.Cedar.evaluate(source, request_json, entities_json)
      end
    )
  end

  defp bootstrap_request?(request) do
    is_map(Process.get(@bootstrap_key)) and
      request[:group] == @group and
      get_in(request, [:actor, "id"]) == R5e.DSSE.node_key_id()
  end

  defp bootstrap_engine_build_request?(request) do
    with %{engine_build: %{bytes: bytes, spec: spec}} <- Process.get(@bootstrap_key),
         node when is_binary(node) <- R5e.DSSE.node_key_id() do
      request[:group] == @group and
        request[:version] == @version and
        request[:kind] == "CasObject" and
        get_in(request, [:actor, "id"]) == node and
        request[:signers] == [node] and
        request[:authority] in [nil, []] and
        request[:authority_refs] in [nil, []] and
        request[:authority_roots] in [nil, []] and
        request[:cas_bytes] == bytes and
        request[:spec] == spec
    else
      _ -> false
    end
  end

  defp bootstrap_meta(engine_build, note) do
    %{
      "engine" => "cedar",
      "decision" => "allow",
      "bundle" => nil,
      "bundleRef" => @bundle_ref,
      "source" => nil,
      "shape" => nil,
      "evaluation" => nil,
      "engineBuild" => engine_build,
      "matched" => ["kernel-bootstrap-fixpoint"],
      "generations" => %{},
      "derivedObjects" => [],
      "bootstrap" => true,
      "note" => note
    }
  end

  # The engine could not answer: nothing was decided, and the receipt says so.
  defp error_meta(bundle, source, cause),
    do: decision_meta(bundle, source, "error", "nothing was handed to Cedar (#{cause})")

  # The kernel decided, about the candidate rather than about the request.
  # `"source"` stays the source of the bundle in force, which is nothing
  # here: the bytes that were read are the candidate's, and the note names
  # them rather than letting a reader take them for the active policy.
  defp refusal_meta(bundle, candidate, cause) do
    note =
      "the kernel refused the candidate PolicyBundle (#{cause}); " <>
        "the request itself was not evaluated"

    decision_meta(
      bundle,
      nil,
      "deny",
      if(candidate, do: note <> "; candidate source #{candidate}", else: note)
    )
  end

  defp decision_meta(bundle, source, decision, note) do
    %{
      "engine" => "cedar",
      "decision" => decision,
      "bundle" => bundle && bundle["specAddress"],
      "bundleRef" => @bundle_ref,
      "source" => source,
      "shape" => nil,
      "evaluation" => nil,
      "engineBuild" => EngineBuild.cached_address(),
      "matched" => [],
      "generations" => if(bundle, do: %{@bundle_ref => bundle["admissionSeq"]}, else: %{}),
      "derivedObjects" => [],
      "note" => note
    }
  end

  defp active_bundle, do: R5e.ResourceStore.get(@group, @version, @kind, @name)

  defp admitted_engine_build do
    case EngineBuild.cached_address() do
      address when is_binary(address) ->
        with {:ok, facts} <- R5e.RefIndex.cas_object(address),
             true <- facts["mediaType"] == EngineBuild.media_type(),
             {:ok, bytes} <- R5e.CAS.get(address),
             true <- facts["size"] == byte_size(bytes),
             true <- address == "bytes:" <> R5e.Canonical.hash_bytes(bytes) do
          {:ok, address}
        else
          _ ->
            {:error, "cached Cedar engine descriptor is absent or invalid (fail-closed)", nil,
             "engineBuildInvalid"}
        end

      _ ->
        {:error, "no cached Cedar engine descriptor is available (fail-closed)", nil,
         "engineBuildMissing"}
    end
  end

  defp measured_engine_build_admitted?(measurement) do
    with {:ok, facts} <- R5e.RefIndex.cas_object(measurement.address),
         true <- facts["mediaType"] == EngineBuild.media_type(),
         true <- facts["size"] == byte_size(measurement.bytes),
         {:ok, bytes} <- R5e.CAS.get(measurement.address),
         true <- bytes == measurement.bytes do
      true
    else
      _ -> false
    end
  end

  defp seed_engine_build(measurement) do
    if measured_engine_build_admitted?(measurement) do
      EngineBuild.cache_address(measurement.address)
    else
      address = admit_bytes(measurement.bytes, EngineBuild.media_type())

      if address == measurement.address and measured_engine_build_admitted?(measurement) do
        EngineBuild.cache_address(address)
      else
        raise "admitted Cedar engine descriptor does not match this boot's measurement"
      end
    end
  end

  defp seed_kind do
    spec = priv_path("policy/policy-bundle.json") |> File.read!() |> Jason.decode!()
    name = "#{@group}/#{@version}/#{@kind}"

    case R5e.ResourceStore.get(@group, @version, "KindDefinition", name) do
      {:ok, _entry, _lineage} ->
        :ok

      {:error, :not_found} ->
        case R5e.Bootstrap.admit_as_node(@group, @version, "KindDefinition", name, spec) do
          {:ok, _receipt} ->
            :ok

          {:denied, receipt} ->
            raise R5e.Bootstrap.Refused, """
            refusing to start: this node could not seed the #{@kind} Kind.

              #{@group}/#{@version}/KindDefinition/#{name}
              denial: #{receipt["reason"]}

            Without this Kind there is no vocabulary for kernel policy to be
            admitted under, so the node has no policy it can name.
            """
        end
    end
  end

  # Keyed on **presence**, not on equality with the shipped default. An
  # equality test re-admits the default at every boot whenever the two
  # differ, which silently supersedes an operator's admitted bundle and
  # makes kernel policy a build-time constant re-imposed at every start.
  # The recovery act is the one way the shipped default is admitted over an
  # existing one, and it is an ordinary admission: the bundle in force may
  # refuse it, and the refusal is recorded.
  defp seed_bundle(source_address) do
    spec = %{
      "engine" => "cedar",
      "governs" => [@group],
      "sourceRef" => %{"$ref" => source_address},
      "description" => "Kernel admission policy for the core namespace"
    }

    case active_bundle() do
      {:ok, %{"spec" => ^spec}, _lineage} -> :ok
      {:ok, _entry, _lineage} -> if recover_default?(), do: admit_bundle!(spec), else: :ok
      {:error, :not_found} -> admit_bundle!(spec)
    end
  end

  @doc """
  Whether this boot was asked to re-admit the shipped default kernel policy
  over the bundle already in force (`R5E_KERNEL_POLICY_RECOVER=1`).
  """
  @spec recover_default?() :: boolean()
  def recover_default?, do: Application.get_env(:r5e, :kernel_policy_recover, false) == true

  defp admit_bundle!(spec) do
    case R5e.Bootstrap.admit_as_node(@group, @version, @kind, @name, spec) do
      {:ok, _receipt} ->
        :ok

      {:denied, receipt} ->
        raise R5e.Bootstrap.Refused, bundle_refusal(receipt, spec)
    end
  end

  defp bundle_refusal(receipt, spec) do
    active =
      case active_bundle() do
        {:ok, entry, _lineage} ->
          "the bundle in force is #{entry["specAddress"]} " <>
            "(source #{get_in(entry, ["spec", "sourceRef", "$ref"])})"

        _ ->
          "no #{@bundle_ref} is admitted"
      end

    """
    refusing to start: this node could not admit its kernel policy bundle.

      #{@bundle_ref} candidate source: #{get_in(spec, ["sourceRef", "$ref"])}
      #{active}
      denial: #{receipt["reason"]}

    Recovery: R5E_KERNEL_POLICY_RECOVER=1 re-admits the shipped default under
    the node key as an explicit, recorded act. It is an ordinary admission, so
    the bundle in force decides it; a bundle that denies the node key's own
    supersede cannot be replaced this way and the chain has to be read to see
    when it was admitted and by whom.
    """
  end

  defp admit_bytes(bytes, media_type) do
    expected = R5e.CAS.object_spec(bytes, media_type)["address"]

    case R5e.RefIndex.cas_object(expected) do
      {:ok, _facts} ->
        case R5e.CAS.get(expected) do
          {:ok, ^bytes} -> expected
          _ -> admit_bytes_again(bytes, media_type, expected)
        end

      :error ->
        admit_bytes_again(bytes, media_type, expected)
    end
  end

  defp admit_bytes_again(bytes, media_type, expected) do
    R5e.Bootstrap.ensure_node_key_held!("admitting #{media_type} object #{expected}")
    spec = R5e.CAS.object_spec(bytes, media_type)
    target = %{"group" => @group, "version" => @version, "kind" => "CasObject", "name" => nil}
    envelope = R5e.Request.sign(%{target: target, spec: spec}, [:node])

    case R5e.CAS.admit(envelope, bytes, media_type) do
      {:ok, _receipt, ^expected, _size} ->
        expected

      {:denied, receipt} ->
        raise R5e.Bootstrap.Refused, """
        refusing to start: this node could not admit a core object it needs.

          object: #{expected} (#{media_type})
          denial: #{receipt["reason"]}

        The kernel policy bundle in force decided this. A bundle that denies
        the node key's admission of the measured Cedar engine descriptor makes
        the next kernel upgrade unbootable; #{@bundle_ref} is refused at
        admission when it would, so a chain that carries one predates that
        check.
        """
    end
  end

  defp kind_definition_address(request) do
    case R5e.KindRegistry.get(request[:group], request[:version], request[:kind]) do
      {:ok, kind} -> kind.spec_address
      _ -> nil
    end
  end

  defp target_ref(request),
    do:
      Enum.join([request[:group], request[:version], request[:kind], request[:name] || "*"], "/")

  defp uid(type, id), do: type <> "::" <> Jason.encode!(id)

  defp entity(type, id, attrs),
    do: %{"uid" => %{"type" => type, "id" => id}, "attrs" => attrs, "parents" => []}

  defp priv_path(relative), do: :r5e |> :code.priv_dir() |> to_string() |> Path.join(relative)
end
