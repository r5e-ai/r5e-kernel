ExUnit.start()

defmodule R5e.TestHelpers do
  @moduledoc false

  @doc """
  A deterministic ed25519 keypair for a test actor id.

  An ed25519 private key is 32 arbitrary bytes, so `sha256(id)` is one —
  which means `"test:alice"` and `"test:bob"` are two different keys, the
  same two on every run, and a test that used to say "another actor" still
  says it. Nothing here is secret; these keys exist only inside a test's
  own throwaway data directory.
  """
  def key_for(%{"id" => id}), do: key_for(id)

  def key_for(id) when is_binary(id) do
    # A test that names the node's own key id means the node key, which
    # this process does not hold the private half of — `:node` is how
    # `R5e.Request` asks the signer provider for it.
    cond do
      id == R5e.DSSE.node_key_id() ->
        :node

      # §10: the sweeper's key, held under the data directory like the
      # node's. A test naming it means that key, not a synthesized one.
      id == R5e.Request.key_id(R5e.Bootstrap.retention_key()) ->
        R5e.Bootstrap.retention_key()

      true ->
        private = :crypto.hash(:sha256, "r5e-test-key:" <> id)
        {public, ^private} = :crypto.generate_key(:eddsa, :ed25519, private)
        %{public: public, private: private, algorithm: "ed25519"}
    end
  end

  @doc "The §0 key id a test actor id signs under."
  def key_id_for(id), do: R5e.Request.key_id(key_for(id))

  @doc """
  Turn a request written the old way — `actor: %{"id" => …}` beside the
  route and the spec — into the signed request the gate now takes.
  `:keys` overrides the signers (a list, in signature order); `:actor` is
  the shorthand for one.
  """
  def sign_request(request) do
    {actor, request} = Map.pop(request, :actor)
    {keys, request} = Map.pop(request, :keys)
    {opts, request} = Map.pop(request, :sign_opts, [])
    keys = keys || [key_for(actor_id(actor))]

    target = %{
      "group" => request[:group],
      "version" => request[:version],
      "kind" => request[:kind],
      "name" => request[:name]
    }

    fields = %{
      target: target,
      spec: request[:spec],
      derived_from: request[:derived_from],
      authority: request[:authority] || []
    }

    request
    |> Map.drop([:derived_from, :authority])
    |> Map.put(:envelope, R5e.Request.sign(fields, keys, opts))
  end

  defp actor_id(%{"id" => id}) when is_binary(id) and id != "", do: id
  defp actor_id(id) when is_binary(id) and id != "", do: id
  defp actor_id(_), do: "test:alice"

  @doc "Admit a request written the old way, signed by its actor's key."
  def admit_request(request), do: R5e.Admission.admit(sign_request(request))

  @doc "Admit through the pipeline with a throwaway test actor."
  def admit(group, version, kind, name, spec, extra \\ %{}) do
    admit_request(
      Map.merge(
        %{
          group: group,
          version: version,
          kind: kind,
          name: name,
          spec: spec
        },
        extra
      )
    )
  end

  @doc "Admit a fresh Kind definition (map) via the pipeline."
  def admit_kind(spec, extra \\ %{}) do
    admit("core.r5e.io", "v1", "KindDefinition", nil, spec, extra)
  end

  @doc """
  A minimal schema-lite v2 KindDefinition. `naming` and `predicates` are
  required in v2, and a schema's `additionalProperties: false` is too.
  """
  def kind_spec(overrides \\ %{}) do
    Map.merge(
      %{
        "group" => "test.r5e.io",
        "kind" => "Widget#{System.unique_integer([:positive])}",
        "version" => "v1alpha1",
        "substrate" => "resource",
        "naming" => %{"mode" => "caller"},
        "schema" => %{
          "required" => ["title"],
          "properties" => %{"title" => %{"type" => "string"}},
          "additionalProperties" => false
        },
        "predicates" => []
      },
      overrides
    )
  end

  @doc """
  Put raw bytes on the record and return their `bytes:sha256:…` address.

  This is `PUT /cas` without the HTTP: `R5e.CAS.admit/3` is the function
  the router calls, so a test that needs a citable object gets one the
  same way a caller would — through a granted `core.r5e.io/v1/CasObject`
  admission, with the bytes written as its `admit` step (§5). A bare
  `R5e.CAS.put/1` no longer produces something a ref may cite.
  """
  def put_object(bytes, media_type \\ nil, actor \\ "test:alice") do
    {:ok, _receipt, address, _size} = cas_admit(actor, bytes, media_type)
    address
  end

  @doc """
  `PUT /cas` without the HTTP: build the `CasObject` spec the kernel will
  build, sign its address, and hand both to `R5e.CAS.admit/3` — which is
  exactly what the route does with the `x-r5e-request` header.
  """
  def cas_admit(actor, bytes, media_type \\ nil) do
    spec = R5e.CAS.object_spec(bytes, media_type)

    envelope =
      R5e.Request.sign(
        %{
          target: %{
            "group" => "core.r5e.io",
            "version" => "v1",
            "kind" => "CasObject",
            "name" => nil
          },
          spec: spec
        },
        [key_for(actor)]
      )

    R5e.CAS.admit(envelope, bytes, media_type)
  end

  @fixtures Path.expand("fixtures", __DIR__)
  @external_resource Path.join(@fixtures, "kind-definition.v2.json")
  @external_resource Path.join(@fixtures, "cas-expired.v1.json")

  @doc """
  Write the chain a **pre-011** kernel wrote into `dir`, before the
  application starts: the schema-lite v2 meta-Kind and the v1
  `CasExpired`, admitted by `system:bootstrap` with an asserted key
  fingerprint, no signature, no origin and no `identity` field.

  That kernel still held a node signing key for its checkpoints. The fixture
  provisions that pre-existing identity before writing the nonempty log, so
  the transition reuses it instead of pretending a deployment can resume
  acknowledged history under a newly generated key.

  Nothing here is rewritten by the boot that follows; §10's transition is
  a set of *new* acts on top of it, and the absence of `identity` on
  these two is what the verifier renders `unsigned`.
  """
  @spec write_legacy_log(String.t()) :: :ok
  def write_legacy_log(dir) do
    File.mkdir_p!(dir)
    R5e.Signer.Local.ensure_keys!(key_dir: Path.join(dir, "keys"))

    lines =
      [
        {"kind-definition.v2.json", "core.r5e.io/v1/KindDefinition"},
        {"cas-expired.v1.json", "core.r5e.io/v1/CasExpired"}
      ]
      |> Enum.with_index(1)
      |> Enum.reduce({[], R5e.Chain.genesis()}, fn {{file, name}, seq}, {lines, prev} ->
        payload = legacy_payload(file, name)
        address = R5e.CAS.put(R5e.Canonical.encode(payload))
        event = R5e.Chain.build_event(seq, prev, "admission.granted", address)
        {lines ++ [Jason.encode!(event)], event["hash"]}
      end)
      |> elem(0)

    File.write!(Path.join(dir, "log.jsonl"), Enum.join(lines, "\n") <> "\n")
  end

  defp legacy_payload(file, name) do
    %{
      "actor" => %{
        "id" => "system:bootstrap",
        "keyFingerprint" => "sha256:0000-bootstrap-placeholder"
      },
      "target" => %{
        "group" => "core.r5e.io",
        "version" => "v1",
        "kind" => "KindDefinition",
        "name" => name
      },
      "outcome" => "admitted",
      "assurance" => "observed",
      "spec" => @fixtures |> Path.join(file) |> File.read!() |> Jason.decode!(),
      "resolvedRefs" => [],
      "scopeDefaulted" => false
    }
  end

  @doc """
  Put **chosen** node and retention keys under `dir` before the
  application starts, so the two keys a fresh boot would otherwise
  generate are the same two on every run.

  This exists for the golden reports and for nothing else. A report names
  key ids — the actors on the `claims:` line, the checkpoint key, the
  roots on the `endorsements:` line — so a report over freshly generated
  keys is different bytes every run and cannot be frozen. The seeds are
  written down here rather than hidden: an ed25519 private key is 32
  arbitrary bytes, and `sha256(<label>)` is one.
  """
  @spec write_fixed_keys(String.t()) :: :ok
  def write_fixed_keys(dir) do
    keys = Path.join(dir, "keys")
    File.mkdir_p!(keys)

    for role <- ~w(node retention fold) do
      private = :crypto.hash(:sha256, "r5e-golden-key:" <> role)
      {public, ^private} = :crypto.generate_key(:eddsa, :ed25519, private)
      File.write!(Path.join(keys, "#{role}_ed25519.key"), private)
      File.chmod!(Path.join(keys, "#{role}_ed25519.key"), 0o600)
      File.write!(Path.join(keys, "#{role}_ed25519.pub"), public)
    end

    :ok
  end

  @doc "The recorded event a receipt points at."
  def event_of(receipt), do: Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))

  @doc "The decoded event payload a receipt points at."
  def payload_of(receipt) do
    {:ok, bytes} = R5e.CAS.get(event_of(receipt)["payload"])
    Jason.decode!(bytes)
  end
end

defmodule R5e.Vectors.ReadingPolicy do
  @moduledoc false
  # A policy with something to lose: it reads the admitted resources a
  # vector names under `policyReads` and reports, per spec/05 §7, the
  # generation it read each at. That is the whole mechanism a real engine
  # needs — the kernel re-checks those generations under the append lock
  # and retries the decision if one moved — and it is the only way a
  # vector can exercise the policy half of the commit protocol without an
  # engine.
  @behaviour R5e.Policy

  @impl true
  def authorize(_request) do
    generations =
      for ref <- Application.get_env(:r5e, :vector_policy_reads, []),
          {:ok, g, v, k, name} <- [R5e.Refs.split_kind_ref(ref)],
          {:ok, entry, _lineage} <- [R5e.ResourceStore.get(g, v, k, name)],
          into: %{} do
        {ref, entry["admissionSeq"]}
      end

    {:ok,
     %{
       "engine" => "vector-reading",
       "decision" => "allow",
       "bundle" => nil,
       "bundleRef" => nil,
       "matched" => [],
       "generations" => generations
     }}
  end
end

defmodule R5e.Vectors.DerivingPolicy do
  @moduledoc false
  # An engine that writes kernel-derived objects (spec/05 §5) and reports
  # them, which is the only way a vector can exercise the replay half of
  # the class: `R5e.RefIndex.register_derived/2` alone lives in memory,
  # and the point of the contract key is that the *record* carries it.
  #
  # Three knobs, because §5 makes three different claims checkable:
  #
  #   * `:vector_policy_derives` — bytes the engine writes to the CAS and
  #     then reports. The honest case.
  #   * `:vector_policy_reports` — addresses reported without writing
  #     anything. The kernel copies a claim it cannot falsify (amendment
  #     C6), so this is what a vector uses to say so.
  #   * `:vector_policy_denies` — a reason, so the vector can pin that a
  #     denial's evaluation record is carried too.
  @behaviour R5e.Policy

  @impl true
  def authorize(_request) do
    written =
      for bytes <- Application.get_env(:r5e, :vector_policy_derives, []),
          do: "bytes:" <> R5e.CAS.put(bytes)

    reported = Application.get_env(:r5e, :vector_policy_reports, [])

    meta = %{
      "engine" => "vector-deriving",
      "bundle" => nil,
      "bundleRef" => nil,
      "matched" => [],
      "generations" => %{},
      "derivedObjects" => written ++ reported
    }

    case Application.get_env(:r5e, :vector_policy_denies) do
      nil -> {:ok, Map.put(meta, "decision", "allow")}
      reason -> {:deny, reason, Map.put(meta, "decision", "deny")}
    end
  end
end

defmodule R5e.Vectors do
  @moduledoc false
  # Runner for the schema-lite v2 §12 conformance vectors. See
  # test/vectors/README.md for the file format.

  import ExUnit.Assertions
  import Bitwise

  # §1: every submission is signed. A vector that says nothing about keys
  # is signed by `$key.1`, with a fresh nonce and an `expires` an hour
  # out — so a vector written before this contract keeps testing exactly
  # what it tested, through the door the contract now requires.
  @doc """
  The Nth conformance key. Deterministic per index, so `$key.2` names the
  same key in `expect` as it signed with, and every vector runs on its own
  fresh kernel where these are the only keys there are.
  """
  def key(n) when is_integer(n), do: R5e.TestHelpers.key_for("vector-key-#{n}")

  def files do
    "test/vectors/**/*.json"
    |> Path.wildcard()
    |> Enum.reject(&String.starts_with?(&1, "test/vectors/gateway/"))
    |> Enum.sort()
  end

  def label(path), do: Path.relative_to(path, "test/vectors")

  def run(path) do
    vector = path |> File.read!() |> Jason.decode!()
    Process.put(:vector_path, path)

    prepare = fn dir ->
      # The seed events are part of a vector's chain too. Install its
      # clock before startup so role Endorsement terms do not depend on
      # the wall clock (and cannot cross the vector's later fixed time at
      # UTC midnight during a long suite run).
      if instant = vector["clock"], do: set_clock(instant)

      # §9's reports name key ids, so a report over generated keys cannot
      # be frozen; §10's legacy transition needs a chain to transition.
      # Both are decisions about what the kernel finds on disk, and this
      # is the only window before it looks. A corpus export is the same
      # decision for the same reason: a bundle whose key ids move every
      # run cannot be a conformance case.
      if vector["fixedKeys"] || vector["report"] || corpus_dir(),
        do: R5e.TestHelpers.write_fixed_keys(dir)

      if vector["legacyLog"], do: R5e.TestHelpers.write_legacy_log(dir)
    end

    with_fresh_kernel(
      fn ->
        try do
          run_vector(vector)
        after
          # §7's seams and the policy are process-wide config; a vector
          # that installs one leaves none behind.
          Application.put_env(:r5e, :before_record, nil)
          Application.put_env(:r5e, :substrate_hook, nil)
          Application.put_env(:r5e, :policy, R5e.Policy.AllowAll)
          Application.delete_env(:r5e, :commit_retries)
          Application.delete_env(:r5e, :vector_policy_reads)
          Application.delete_env(:r5e, :vector_policy_derives)
          Application.delete_env(:r5e, :vector_policy_reports)
          Application.delete_env(:r5e, :vector_policy_denies)
          Application.delete_env(:r5e, :clock)
          Process.delete(:vector_interleaved)
          Process.delete(:vector_record_attempts)
          Process.delete(:vector_last_request)
        end
      end,
      prepare: prepare
    )
  end

  # -- §9: the verifier, asked of a bundle this run produced -------------
  #
  # Everything §9 says is about a *bundle*, so a vector that pins a
  # verifier line or a finding builds a chain, exports it, and asks. Two
  # keys make the hostile cases reachable and neither touches the kernel:
  #
  #   * `inject` appends an **unauthenticated** event to the exported
  #     log — what a hostile assembler can do and what no kernel would
  #     write, which is the only way a `revocation-actor` finding exists;
  #   * `editPayload` rewrites one payload at the address the chain
  #     already names, which is the producer-and-record-disagree case the
  #     `projection` and `stale-shape` findings are for.
  #
  # `posture` and `trust` are the **reader's**, never the bundle's, so
  # they are arguments to the run and not properties of the chain.
  defp verify_step(vector, ctx) do
    block = vector["verify"]
    report_path = vector["report"]
    expected = (vector["expect"] || %{})["verifier"]

    if block || report_path || expected || corpus_dir() do
      dest = export_bundle()

      try do
        for edit <- List.wrap((block || %{})["editPayload"]), do: edit_payload(dest, edit, ctx)
        for injection <- List.wrap((block || %{})["inject"]), do: inject(dest, injection, ctx)

        result = run_verifier(dest, block || %{}, ctx)
        assert_verifier(result, expected, dest)
        assert_report(result, report_path, dest)
        export_corpus(vector, block || %{}, dest, ctx)
      after
        File.rm_rf(dest)
        if prior = Map.get(ctx, :prior), do: File.rm_rf(prior)
      end
    end
  end

  # -- the conformance corpus (r5e-core/conformance) ---------------------
  #
  # `R5E_EXPORT_CORPUS=<dir> MIX_ENV=test mix test test/vectors_test.exs`
  # writes, for every vector whose run ends in an exportable chain, the
  # bundle that run produced and the reader's own arguments beside it.
  # Nothing here changes what a vector asserts: the export happens after
  # every assertion, from the same bundle the verifier was just asked
  # about — including the `editPayload` and `inject` edits, because a
  # case that proves a verifier *finds* something has to carry the thing.
  #
  # It writes no expected output. The expected output of a conformance
  # case is the reference verifier's, recorded on the r5e-core side by
  # `conformance/record.sh` at a stated bookmark, so that the kit's
  # answer and the kit's question never come from one command.
  defp corpus_dir, do: System.get_env("R5E_EXPORT_CORPUS")

  defp export_corpus(vector, block, dest, ctx) do
    if root = corpus_dir() do
      path = Process.get(:vector_path)
      dir = Path.join(root, path |> label() |> String.replace(~r/\.json$/, ""))
      File.rm_rf!(dir)
      File.mkdir_p!(dir)

      # The reader's trust file is the reader's, not the bundle's; the
      # runner happens to write it inside the export directory, and a
      # conformance bundle carrying it would be a bundle with somebody
      # else's pins in it.
      File.rm(Path.join(dest, "trust.json"))
      File.cp_r!(dest, Path.join(dir, "bundle"))
      if prior = Map.get(ctx, :prior), do: File.cp_r!(prior, Path.join(dir, "prior"))

      meta = %{
        "vector" => path,
        "note" => vector["note"],
        "posture" => block["posture"],
        "trustKeys" => List.wrap(block["trustKeys"]),
        "trust" => substitute(List.wrap(block["trust"]), ctx),
        "trustFile" => substitute(List.wrap(block["trustFile"]), ctx),
        "edited" => List.wrap(block["editPayload"]) != [],
        "injected" => List.wrap(block["inject"]) != [],
        "hasPrior" => Map.has_key?(ctx, :prior),
        "expectVerifier" => (vector["expect"] || %{})["verifier"],
        "report" => vector["report"]
      }

      File.write!(Path.join(dir, "case.json"), Jason.encode!(meta, pretty: true))
    end
  end

  defp export_bundle do
    dest = Path.join(System.tmp_dir!(), "r5e-vector-bundle-#{System.unique_integer([:positive])}")
    {:ok, ^dest, _manifest} = R5e.Export.run(dest)
    dest
  end

  # The reader's own arguments. `trustFile` goes through
  # `RecurseVerify.Trust.load/2` — the closed schema, the duplicate-key
  # refusal — because that is the door a reader uses and a vector that
  # bypassed it would pin nothing about it.
  defp run_verifier(dest, block, ctx) do
    inline = for pin <- List.wrap(block["trust"]), do: substitute(pin, ctx)

    file =
      if pins = block["trustFile"] do
        path = Path.join(dest, "trust.json")
        File.write!(path, Jason.encode!(substitute(pins, ctx)))
        path
      end

    case RecurseVerify.Trust.load(List.wrap(block["trustKeys"]), file) do
      {:ok, loaded} ->
        RecurseVerify.run(dest, posture: block["posture"], trust: inline ++ loaded)

      {:error, message} ->
        {:error, message}
    end
  end

  defp assert_verifier(_result, nil, _dest), do: :ok

  defp assert_verifier(result, expected, _dest) do
    if reason = expected["error"] do
      assert {:error, message} = result

      assert message =~ reason,
             "expected the verifier to refuse with #{inspect(reason)}, got #{inspect(message)}"
    else
      assert {:ok, report} = result

      for {prefix, substring} <- expected["lines"] || %{} do
        line = Enum.find(report.checked, "", &String.starts_with?(&1, prefix <> ":"))

        assert line =~ substring,
               "the #{prefix} line does not contain #{inspect(substring)}: #{inspect(line)}"
      end

      for code <- List.wrap(expected["findings"]) do
        assert Enum.any?(report.findings, &String.starts_with?(&1, code <> ": ")),
               "expected a #{code} finding, got #{inspect(report.findings)}"
      end

      if expected["noFindings"] do
        assert report.findings == [], "expected no findings, got #{inspect(report.findings)}"
      end

      for substring <- List.wrap(expected["notChecked"]) do
        assert Enum.any?(report.not_checked, &(&1 =~ substring)),
               "expected a not-checked line containing #{inspect(substring)}"
      end

      for substring <- List.wrap(expected["absentFromNotChecked"]) do
        refute Enum.any?(report.not_checked, &(&1 =~ substring)),
               "the not-checked block still contains #{inspect(substring)}"
      end
    end
  end

  # A golden report is the verifier's whole output, byte for byte, with
  # the one line that names where the bundle happened to be written
  # normalized — a temporary directory is not part of what the report
  # says. `R5E_WRITE_GOLDEN=1` writes the file instead of comparing it;
  # that is how the three were produced, and each was then read line by
  # line before being frozen.
  defp assert_report(_result, nil, _dest), do: :ok

  defp assert_report({:ok, report}, path, dest) do
    full = Path.join("test/vectors", path)
    text = report |> RecurseVerify.format() |> String.replace(dest, "<bundle>")

    if System.get_env("R5E_WRITE_GOLDEN") do
      File.mkdir_p!(Path.dirname(full))
      File.write!(full, text)
    else
      assert File.exists?(full), "the golden report #{full} does not exist"

      assert File.read!(full) == text,
             "the report differs from the frozen one at #{full}:\n\n#{text}"
    end
  end

  defp edit_payload(dest, edit, ctx) do
    receipt = edited_receipt(edit["payloadOf"], ctx)
    event = Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))
    path = Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])
    payload = path |> File.read!() |> Jason.decode!()

    updated =
      Enum.reduce(edit["set"] || %{}, payload, fn {pointer, value}, acc ->
        pointer_put(acc, pointer, substitute(value, ctx))
      end)

    rebuild(dest, event, tampered(updated, edit["tamper"]))
  end

  @doc """
  Rewrite one payload inside an exported bundle **as a forging node
  would**: the new bytes go in at their own address, the old object is
  removed, every event from that one on is relinked, and the checkpoint
  is re-signed with the node key this run holds.

  Writing the new bytes over the old *file* would be a different and much
  weaker thing. A payload that no longer hashes to the address its event
  names is not that event's payload at all (spec/07 §1.6): the verifier
  reports it as a missing payload and never reads it, so every finding
  these vectors exist for — `signature`, `projection`, `stale-shape` —
  becomes unreachable. The producer-and-record-disagree case is a
  producer who *can* re-hash and re-sign, and this is it.
  """
  @spec rebuild(String.t(), map(), map()) :: :ok
  def rebuild(dest, event, payload) do
    bytes = R5e.Canonical.encode(payload)
    address = R5e.Canonical.hash_bytes(bytes)
    old = Path.join([dest, "cas", R5e.CAS.relative_path(event["payload"])])
    if address != event["payload"], do: File.rm(old)

    path = Path.join([dest, "cas", R5e.CAS.relative_path(address)])
    File.mkdir_p!(Path.dirname(path))
    File.write!(path, bytes)

    log = Path.join(dest, "log.jsonl")
    {:ok, events} = R5e.Chain.read_log(log)

    relinked =
      events
      |> Enum.reduce({[], R5e.Chain.genesis()}, fn e, {acc, prev} ->
        e = if e["seq"] == event["seq"], do: Map.put(e, "payload", address), else: e
        e = e |> Map.put("prev", prev) |> Map.delete("hash")
        e = Map.put(e, "hash", R5e.Chain.recompute_hash(e))
        {acc ++ [e], e["hash"]}
      end)
      |> elem(0)

    File.write!(log, Enum.map_join(relinked, "\n", &Jason.encode!/1) <> "\n")
    resign(dest, relinked)
  end

  # The checkpoint the export wrote attests the tree the log had before
  # the rewrite. A node that rewrites its own record signs the tree it
  # then has, so that is what a forged bundle carries and what the
  # verifier has to be caught by something else.
  defp resign(dest, events) do
    manifest_path = Path.join(dest, "manifest.json")
    manifest = manifest_path |> File.read!() |> Jason.decode!()
    leaves = Enum.map(events, & &1["hash"])

    claim = %{
      "treeSize" => length(events),
      "merkleRoot" => RecurseVerify.Merkle.hex(RecurseVerify.Merkle.root(leaves)),
      "chainHead" => List.last(leaves),
      "ts" => get_in(manifest, ["checkpoint", "checkpoint", "ts"])
    }

    checkpoint = %{
      "checkpoint" => claim,
      "envelope" =>
        R5e.DSSE.envelope(R5e.Log.checkpoint_payload_type(), R5e.Canonical.encode(claim)),
      "keyId" => R5e.SignerProvider.key_id()
    }

    File.write!(
      manifest_path,
      Jason.encode!(Map.put(manifest, "checkpoint", checkpoint), pretty: true)
    )
  end

  # `"instance"` (the act under test) or a setup index. Both are receipts
  # this run produced, so a vector never has to know an event hash.
  defp edited_receipt("instance", ctx), do: ctx.receipt
  defp edited_receipt(index, ctx) when is_integer(index), do: Enum.at(ctx.setup, index)

  # Flip one bit of signature 1 **inside the bundle**. The kernel verified
  # this envelope when it admitted the act, so the only way a bundle
  # carries a signature that does not verify is that somebody changed it
  # after the fact — which is the whole case the `signature` finding is
  # for.
  defp tampered(payload, "signature"), do: tampered(payload, %{"signature" => 1})

  defp tampered(payload, %{"signature" => n}) do
    update_in(payload, ["signed", "signatures"], fn signatures ->
      List.update_at(signatures, n - 1, fn entry ->
        {:ok, sig} = Base.decode64(entry["sig"])
        <<head::binary-size(63), last>> = sig
        %{entry | "sig" => Base.encode64(head <> <<Bitwise.bxor(last, 1)>>)}
      end)
    end)
  end

  defp tampered(payload, _none), do: payload

  defp pointer_put(document, "/" <> rest, value) do
    case String.split(rest, "/", parts: 2) do
      [key] ->
        Map.put(document, key, value)

      [key, tail] ->
        Map.put(document, key, pointer_put(Map.get(document, key, %{}), "/" <> tail, value))
    end
  end

  # An event nobody signed, appended to the exported log with a valid
  # hash chain. The kernel would refuse it at `authenticate`; a bundle is
  # a file, and this is what a reader is handed by somebody who wants a
  # chain to say something it does not.
  defp inject(dest, injection, ctx) do
    log = Path.join(dest, "log.jsonl")
    {:ok, events} = R5e.Chain.read_log(log)
    last = List.last(events)
    [group, version, kind] = String.split(injection["kind"], "/")

    payload = %{
      "actor" => %{"id" => substitute(injection["actor"], ctx)},
      "target" => %{
        "group" => group,
        "version" => version,
        "kind" => kind,
        "name" => injection["name"]
      },
      "outcome" => "admitted",
      "identity" => "signed",
      "spec" => substitute(injection["spec"], ctx),
      "resolvedRefs" => [],
      "scopeDefaulted" => false
    }

    bytes = R5e.Canonical.encode(payload)
    address = R5e.Canonical.hash_bytes(bytes)
    object = Path.join([dest, "cas", R5e.CAS.relative_path(address)])
    File.mkdir_p!(Path.dirname(object))
    File.write!(object, bytes)

    event = R5e.Chain.build_event(last["seq"] + 1, last["hash"], "admission.granted", address)
    File.write!(log, File.read!(log) <> Jason.encode!(event) <> "\n")
  end

  defp run_vector(vector) do
    # §8/§0/§7's fixtures are not admissions: they pin the encoder, the
    # key-id derivation, the origin derivation and the ed25519 profile,
    # each of which is a pure function the whole contract rests on. A
    # vector carrying one of these keys and nothing else is done here.
    canonical(vector["canonical"])
    derivations(vector["derivations"])
    ed25519(vector["ed25519"])

    cond do
      vector["instance"] != nil or vector["setup"] != nil ->
        run_admissions(vector)

      # §10's bootstrap transcript is an expectation about a chain nobody
      # submitted anything to: the ten events a fresh kernel writes before
      # any caller arrives.
      vector["expect"] != nil or vector["report"] != nil ->
        assert_chain((vector["expect"] || %{})["chain"])
        verify_step(vector, empty_ctx())

      true ->
        :ok
    end
  end

  # §10: the chain, event by event — seq, the Kind admitted, the name it
  # was granted under, and the key that signed. A vector writes only the
  # fields it means to pin.
  defp assert_chain(nil), do: :ok

  defp assert_chain(expected) do
    actual =
      for event <- R5e.Log.events(), {:ok, payload} <- [R5e.Log.payload(event)] do
        %{
          "seq" => event["seq"],
          "kind" => R5e.Admission.target_path(payload),
          "name" => payload["target"]["name"],
          "actor" => payload["actor"]["id"],
          "identity" => payload["identity"],
          "outcome" => payload["outcome"],
          "signers" => payload["signers"],
          "depth" => payload["depth"],
          "hasRandom" => Map.has_key?(payload, "random"),
          "hasOrigin" => Map.has_key?(payload, "origin")
        }
      end

    assert length(actual) == length(expected),
           "expected a chain of #{length(expected)} events, got #{length(actual)}"

    for {want, got} <- Enum.zip(expected, actual) do
      for {key, value} <- want do
        assert Map.fetch(got, key) == {:ok, substitute(value, empty_ctx())},
               "seq #{got["seq"]}: expected #{key} = #{inspect(value)}, got #{inspect(got[key])}"
      end
    end

    :ok
  end

  # §8's raw-input half: `rawJson` goes to the encoder as bytes, and the
  # vector says either what it must produce or how it must refuse.
  defp canonical(nil), do: :ok

  defp canonical(cases) when is_list(cases), do: Enum.each(cases, &canonical/1)

  defp canonical(%{"rawJson" => input} = c) do
    result = R5e.Canonical.encode_json(input)

    cond do
      expected = c["bytes"] ->
        assert result == {:ok, expected},
               "canonical(#{inspect(input)}): expected #{inspect(expected)}, got #{inspect(result)}"

      includes = c["error"] ->
        assert match?({:error, _}, result),
               "canonical(#{inspect(input)}): expected an error, got #{inspect(result)}"

        {:error, reason} = result

        assert reason =~ includes,
               "canonical(#{inspect(input)}): expected the error to include #{inspect(includes)}, got #{inspect(reason)}"

      same = c["sameAs"] ->
        assert result == R5e.Canonical.encode_json(same),
               "canonical: #{inspect(input)} and #{inspect(same)} must encode identically"
    end
  end

  # §0: the key id and the origin, each a hash over a tag-prefixed
  # concatenation nobody should have to re-read the code to reproduce.
  defp derivations(nil), do: :ok

  defp derivations(block) do
    for c <- block["keyIds"] || [] do
      {:ok, bytes} = Base.decode64(c["bytes"])
      result = R5e.DSSE.key_id(c["algorithm"] || "ed25519", bytes)

      if id = c["id"], do: assert(result == {:ok, id})

      if includes = c["error"] do
        assert {:error, reason} = result
        assert reason =~ includes
      end
    end

    for c <- List.wrap(block["origin"]) do
      {:ok, random} = Base.decode64(c["random"])
      {:ok, key} = Base.decode64(c["nodePublicKey"])
      assert R5e.Origin.derive(random, key) == c["origin"]
    end
  end

  # §7: the profile, including the small-order table copied from
  # libsodium and the RFC 8032 vectors it must still accept.
  defp ed25519(nil), do: :ok

  defp ed25519(cases) do
    for c <- cases do
      {:ok, key} = Base.decode16(c["publicKey"], case: :lower)
      {:ok, signature} = Base.decode16(c["signature"], case: :lower)
      {:ok, message} = Base.decode16(c["message"] || "", case: :lower)

      assert RecurseVerify.DSSE.verify_ed25519(message, signature, key) == c["valid"],
             "ed25519 #{inspect(c["note"])}: expected valid=#{c["valid"]}"
    end
  end

  defp run_admissions(vector) do
    # Supporting Kinds first: a ref needs a Kind to point at, and that
    # Kind is usually not the one under test.
    for definition <- vector["kinds"] || [] do
      {:ok, _} = admit_definition(definition)
    end

    if instant = vector["clock"], do: set_clock(instant)

    {group, version, kind} = target(vector["kind"])

    if is_map(vector["kind"]) do
      {:ok, _} = admit_definition(vector["kind"])
    end

    # §5: a `cas` entry is admitted — the same act `PUT /cas` performs,
    # through `R5e.CAS.admit/3`, which is the function the router calls.
    # `$cas.N` therefore names bytes somebody put on the record, and the
    # manifest entry citing it carries that admission's `event:` ref.
    #
    # `casRaw` is the other half of the pair: bytes written straight
    # into the CAS with no admission at all, which is what a pre-§5
    # deployment holds and what §5 now refuses to let a ref cite. There
    # is no other way to reach that denial, because the kernel no longer
    # offers a path that produces such an object.
    puts =
      for entry <- vector["cas"] || [] do
        {bytes, media_type} = cas_entry(entry)
        {:ok, receipt, address, _size} = cas_admit([key(1)], bytes, bytes, media_type)
        {address, receipt}
      end

    raw = for bytes <- vector["casRaw"] || [], do: "bytes:" <> R5e.CAS.put(bytes)

    # §5's kernel-derived class: bytes the kernel wrote inside an
    # admission, registered rather than admitted. No such object exists
    # yet (the first is §8's evaluation record), so a vector that needs
    # one registers it synthetically — the class is shipped with the
    # slice that defines it, not with the slice that first uses it.
    derived =
      for bytes <- vector["derivedObjects"] || [] do
        address = "bytes:" <> R5e.CAS.put(bytes)
        R5e.RefIndex.register_derived(address)
        address
      end

    ctx = %{
      setup: [],
      cas: Enum.map(puts, &elem(&1, 0)),
      casReceipts: Enum.map(puts, &elem(&1, 1)),
      raw: raw,
      derived: derived,
      # §5's other door: the addresses an engine is *about* to write and
      # report. The address is a hash of bytes the vector wrote down, so
      # it is computable here, before the act — which is what lets a
      # vector name it in `expect`.
      written:
        for(
          bytes <- vector["policyDerives"] || [],
          do: "bytes:" <> R5e.Canonical.hash_bytes(bytes)
        )
    }

    # §7's substrate-failure seam. It is armed for the whole run and
    # fires on a sentinel name, so the vector says which act fails by
    # naming it rather than by counting steps.
    substrate_failure(vector["substrateFailure"])

    ctx =
      Enum.reduce(vector["setup"] || [], ctx, fn step, ctx ->
        %{ctx | setup: ctx.setup ++ [setup_step(step, {group, version, kind}, ctx)]}
      end)

    # Everything §7 needs is installed after setup and before the
    # instance: a policy that reads (and therefore captures) admitted
    # resources, the retry budget, and the interleaving hook.
    policy_reads(vector["policyReads"])
    deriving_policy(vector, ctx)
    clock_at_record(vector["clockAtRecord"])
    if n = vector["commitRetries"], do: Application.put_env(:r5e, :commit_retries, n)
    interleave(vector["interleave"], {group, version, kind}, ctx)

    # §5: a scenario may need the clock to be one thing while the chain is
    # built and another when the act under test is submitted — a term that
    # was live at issuance and is not at citation.
    if instant = vector["clockAtInstance"], do: set_clock(instant)

    forget_before(vector["forgetBefore"], ctx)
    if vector["replayBeforeInstance"], do: R5e.Bootstrap.replay()

    # A conformance case for `--prior` needs the *same* chain twice, and
    # the only place two exports of one chain differ is here: before the
    # act under test lands. It costs an export per vector and only when
    # a corpus is being written.
    ctx = if corpus_dir(), do: Map.put(ctx, :prior, export_bundle()), else: ctx

    result = submit(group, version, kind, vector["instance"], ctx)
    Application.put_env(:r5e, :before_record, nil)
    ctx = Map.put(ctx, :interleaved, Process.get(:vector_interleaved, []))
    forget_after(vector["forgetAfter"], ctx)

    # §5: replay is the falsification. It resets the reference index and
    # rebuilds it from the chain alone, so anything still registered
    # afterwards is registered *because the record says so* — which is
    # the difference the whole `derivedObjects` key exists to make.
    if vector["replayAfterInstance"], do: R5e.Bootstrap.replay()

    check(result, vector["expect"], ctx, {group, version, kind})
    check_derived(result, vector["expect"] || %{}, ctx)
    sweep(vector["sweep"])
    verify_step(vector, Map.put(ctx, :receipt, elem(result, 1)))
  end

  # §5/§10: one run of the retention sweeper, through the real function —
  # so a vector that wants a `CasExpired` on its chain gets the one the
  # sweeper would write, signed by the retention key and citing event
  # 10's Endorsement, rather than a hand-written imitation of it. The TTL
  # is the deployment's; `nil` (the default) means the sweeper removes
  # nothing at all, which is why a vector has to say a number to see one.
  defp sweep(nil), do: :ok

  defp sweep(%{"ttlSeconds" => ttl}) do
    previous = Application.get_env(:r5e, :cas_ttl_seconds)
    Application.put_env(:r5e, :cas_ttl_seconds, ttl)

    try do
      R5e.Retention.sweep()
    after
      Application.put_env(:r5e, :cas_ttl_seconds, previous)
    end
  end

  # -- §7: the commit protocol's three test-only seams -------------------

  # A policy that reads admitted resources and reports the generation it
  # read them at, so `record` has something to re-check.
  defp policy_reads(nil), do: :ok

  defp policy_reads(refs) when is_list(refs) do
    Application.put_env(:r5e, :vector_policy_reads, refs)
    Application.put_env(:r5e, :policy, R5e.Vectors.ReadingPolicy)
  end

  # §5's kernel-derived class, through the door that survives a restart: an
  # engine that writes objects during `authorize` and reports their
  # addresses on its metadata, which `R5e.Admission` copies onto the
  # payload. `policyReports` is the same key carrying an address the
  # engine did *not* write — the claim the kernel copies verbatim and only
  # the verifier can falsify (amendment C6).
  defp deriving_policy(vector, ctx) do
    derives = vector["policyDerives"]
    reports = vector["policyReports"]

    if derives || reports do
      Application.put_env(:r5e, :vector_policy_derives, derives || [])
      Application.put_env(:r5e, :vector_policy_reports, substitute(reports || [], ctx))
      Application.put_env(:r5e, :vector_policy_denies, vector["policyDenies"])
      Application.put_env(:r5e, :policy, R5e.Vectors.DerivingPolicy)
    end
  end

  # Run another admission between `authorize` and `record` of the
  # instance — the interleaving §7 exists for, made deterministic. It
  # fires before each record attempt, up to `repeat` times (default 1),
  # so a vector chooses between "the generation moved once, and the retry
  # succeeded" and "it keeps moving, and the admission is contended".
  # Every receipt it produces is kept, and `$interleaved.N.<field>` names
  # one.
  # §6: the clock moves between `authorize` and `record`, so a vector can
  # pin `record: expired` — the re-check under the append lock — without
  # sleeping through a 300-second skew window.
  defp clock_at_record(nil), do: :ok

  defp clock_at_record(instant) do
    Application.put_env(:r5e, :before_record, fn _request -> set_clock(instant) end)
  end

  defp interleave(nil, _default_target, _ctx), do: :ok

  defp interleave(%{"admit" => step} = spec, default_target, ctx) do
    repeat = spec["repeat"] || 1
    {group, version, kind} = step_target(spec["kind"], default_target)
    Process.put(:vector_interleaved, [])
    Process.put(:vector_record_attempts, 0)

    Application.put_env(:r5e, :before_record, fn _request ->
      Process.put(:vector_record_attempts, Process.get(:vector_record_attempts, 0) + 1)
      done = Process.get(:vector_interleaved, [])

      if length(done) < repeat do
        case submit(group, version, kind, step, ctx) do
          {:ok, receipt} ->
            Process.put(:vector_interleaved, done ++ [receipt])

          {:denied, receipt} ->
            flunk("the interleaved admission was denied: #{receipt["reason"]}")
        end
      end
    end)
  end

  # The post-record substrate failure (§7): the `admit` step raises for
  # one sentinel name. The setup step that carries that name is marked
  # `"raises": true`, because a caller of a halted admission is owed the
  # failure — the act is on the chain and a denial receipt would say
  # otherwise.
  defp substrate_failure(nil), do: :ok

  defp substrate_failure(name) when is_binary(name) do
    Application.put_env(:r5e, :substrate_hook, fn request ->
      if request[:name] == name do
        raise File.Error,
          reason: :eio,
          action: "write to",
          path: "<injected substrate failure for #{name}>"
      end
    end)
  end

  # Each vector gets its own kernel: its own data directory, its own log,
  # bootstrapped from event one. Nothing a vector admits can reach another.
  #
  # `:prepare` is a 1-arity function called with the data directory
  # **after** it is configured and **before** the application starts —
  # the only window in which a vector can decide what the kernel will
  # find there: a pre-011 log to transition forward, or key material
  # chosen rather than generated, which is what makes a golden report
  # reproducible.
  def with_fresh_kernel(fun, opts \\ []) do
    previous = Application.fetch_env!(:r5e, :data_dir)
    dir = Path.join(System.tmp_dir!(), "r5e-vector-#{System.unique_integer([:positive])}")

    stop_r5e()
    Application.put_env(:r5e, :data_dir, dir)

    try do
      if prepare = opts[:prepare], do: prepare.(dir)
      {:ok, _} = Application.ensure_all_started(:r5e)
      fun.()
    after
      stop_r5e()
      Application.put_env(:r5e, :data_dir, previous)
      {:ok, _} = Application.ensure_all_started(:r5e)
      File.rm_rf(dir)
    end
  end

  defp stop_r5e do
    case Application.stop(:r5e) do
      :ok -> :ok
      {:error, {:not_started, :r5e}} -> :ok
    end
  end

  def admit_definition(definition) do
    submit("core.r5e.io", "v1", "KindDefinition", %{"spec" => definition}, empty_ctx())
  end

  defp empty_ctx,
    do: %{setup: [], cas: [], casReceipts: [], raw: [], derived: [], written: [], receipt: nil}

  # §2: the node clock a vector runs against, so an expiry boundary is
  # pinned rather than slept through.
  defp set_clock(instant) do
    {:ok, at} = RecurseVerify.Instant.parse(instant)
    Application.put_env(:r5e, :clock, at)
  end

  defp target(%{"group" => g, "version" => v, "kind" => k}), do: {g, v, k}

  defp target(path) when is_binary(path) do
    [g, v, k] = String.split(path, "/")
    {g, v, k}
  end

  # A setup step may target a different Kind than the instance, and may be
  # expected to be denied — a denied admission is a recorded act, and an
  # `outcome: any` event ref is entitled to cite one.
  defp setup_step(step, default_target, ctx) do
    {group, version, kind} = step_target(step["kind"], default_target)

    # §7: an admission whose substrate write failed raises rather than
    # returning a receipt — the act is on the chain and the caller is owed
    # the failure. A step that provokes one says so and keeps no receipt.
    if step["raises"] do
      assert_raise(File.Error, fn -> submit(group, version, kind, step, ctx) end)
      %{"raised" => true}
    else
      case {submit(group, version, kind, step, ctx), step["denied"]} do
        {{:ok, receipt}, nil} ->
          receipt

        {{:denied, receipt}, true} ->
          receipt

        {{:ok, receipt}, true} ->
          flunk("setup step was expected to be denied: #{inspect(receipt)}")

        {{:denied, receipt}, nil} ->
          flunk("setup step denied: #{receipt["reason"]}")
      end
    end
  end

  defp step_target(nil, default_target), do: default_target
  defp step_target(path, _default_target) when is_binary(path), do: target(path)

  # §1's door, and the CAS door beside it. A step says `door: "cas"` when
  # it is a `PUT /cas`; everything else is `POST /apis/...`.
  defp submit(_group, _version, _kind, %{"door" => "cas"} = step, ctx) do
    body = substitute(step["body"], ctx)
    signed_body = substitute(step["signBody"] || step["body"], ctx)
    media_type = (step["headers"] || %{})["content-type"]

    case cas_admit(signers(step, ctx), body, signed_body, media_type, step, ctx) do
      {:ok, receipt, _address, _size} -> {:ok, receipt}
      {:denied, receipt} -> {:denied, receipt}
    end
  end

  defp submit(group, version, kind, instance, ctx) do
    name = substitute(instance["name"], ctx)
    spec = substitute(instance["spec"], ctx)

    target = %{
      "group" => group,
      "version" => version,
      "kind" => kind,
      "name" => name
    }

    R5e.Admission.admit(%{
      envelope: envelope_for(instance, target, spec, ctx),
      group: group,
      version: version,
      kind: kind,
      name: name,
      spec: spec
    })
  end

  defp cas_admit(keys, body, signed_body, media_type, step \\ %{}, ctx \\ nil) do
    ctx = ctx || empty_ctx()
    spec = R5e.CAS.object_spec(signed_body, media_type)

    target = %{
      "group" => "core.r5e.io",
      "version" => "v1",
      "kind" => "CasObject",
      "name" => nil
    }

    envelope = envelope_for(Map.put(step, "keys", keys), target, spec, ctx)
    R5e.CAS.admit(envelope, body, media_type)
  end

  # -- §1: building the envelope a step is submitted under ----------------
  #
  # Six escape hatches, and each exists because a malformed case cannot be
  # authored any other way:
  #
  #   * `rawEnvelope` submits an arbitrary object verbatim (or `null`);
  #   * `requestPatch` / `requestDrop` change the request object **before**
  #     signing, so the signature is good and the *form* is wrong — which
  #     is the case that matters, because §2 checks form before signature
  #     and a well-signed malformed request must still be refused;
  #   * `tamperSignature` corrupts signature 1 after signing, which is the
  #     only way to author "the form is right and the signature is not";
  #   * `rawRequest` swaps the payload bytes after signing, for the
  #     non-canonical-encoding case;
  #   * `envelopePatch` replaces envelope keys after signing — the only
  #     way to author a bad `keyid`, a short `publicKeys` entry, a wrong
  #     `payloadType` or a non-canonical `sig`;
  #   * `specAddress`, `origin`, `actorId`, `nonce` and `expires` override
  #     one signed field each.
  defp envelope_for(step, target, spec, ctx) do
    # `Map.fetch` rather than `step["rawEnvelope"]`: an explicit `null` is
    # itself a case — "no envelope at all" — and must not read as absent.
    case Map.fetch(step, "rawEnvelope") do
      :error -> built_envelope(step, target, spec, ctx)
      {:ok, raw} -> substitute(raw, ctx)
    end
  end

  defp built_envelope(step, target, spec, ctx) do
    keys = step["keys"] || signers(step, ctx)

    request =
      R5e.Request.build(
        %{
          target: target,
          spec: spec,
          derived_from: substitute(step["derivedFrom"], ctx),
          authority: substitute(step["authority"] || [], ctx)
        },
        actor: substitute(step["actorId"], ctx) || R5e.Request.key_id(hd(keys)),
        origin: step["origin"] || R5e.Origin.current(),
        spec_address: substitute(step["specAddress"], ctx) || spec_address(spec),
        nonce: step["nonce"] || R5e.Request.fresh_nonce(),
        expires: expires_of(step)
      )

    request =
      request
      |> Map.merge(substitute(step["requestPatch"] || %{}, ctx))
      |> Map.drop(step["requestDrop"] || [])

    Process.put(:vector_last_request, %{
      signer: R5e.Request.key_id(hd(keys)),
      nonce: request["nonce"]
    })

    request
    |> R5e.Request.envelope(keys)
    |> tamper(step["tamperSignature"])
    |> raw_payload(substitute(step["rawRequest"], ctx))
    |> Map.merge(substitute(step["envelopePatch"] || %{}, ctx))
  end

  # One flipped bit in signature 1: the envelope is well formed and the
  # signature is not, which is the only way to reach §2's second refusal.
  defp tamper(envelope, true) do
    [first | rest] = envelope["signatures"]
    {:ok, sig} = Base.decode64(first["sig"])
    <<head::binary-size(63), last>> = sig
    flipped = Base.encode64(head <> <<bxor(last, 1)>>)
    Map.put(envelope, "signatures", [Map.put(first, "sig", flipped) | rest])
  end

  defp tamper(envelope, _), do: envelope

  defp raw_payload(envelope, nil), do: envelope

  defp raw_payload(envelope, bytes) do
    # The nonce the gate will see is the one in *these* bytes, so a vector
    # asking `nonceClaimed` of a tampered request is asking about what it
    # actually submitted.
    with {:ok, %{"nonce" => nonce, "actor" => actor}} <- R5e.Canonical.decode_json(bytes) do
      Process.put(:vector_last_request, %{signer: actor, nonce: nonce})
    end

    Map.put(envelope, "payload", Base.encode64(bytes))
  end

  # A spec §8 cannot encode has no address, and a vector that submits one
  # is testing exactly that: the signer names an address the spec cannot
  # have, and the gate says so.
  defp spec_address(spec) do
    R5e.CAS.spec_address(spec)
  rescue
    ArgumentError -> "sha256:" <> String.duplicate("0", 64)
  end

  defp expires_of(%{"expires" => "auto"}), do: R5e.Clock.in_seconds(3600)
  defp expires_of(%{"expires" => instant}) when is_binary(instant), do: instant
  defp expires_of(_step), do: R5e.Clock.in_seconds(3600)

  # `sign: [N…]` names the signers by index. A step that says nothing
  # signs with `$key.1`; a step carrying a legacy `actor` map signs with
  # the key that actor id maps to, so "another actor" still means another
  # key.
  # §10's two node-held keys, named rather than indexed: a vector that
  # needs the sweeper's authority has to sign with the sweeper's key.
  defp signers(%{"signAs" => "node"}, _ctx), do: [:node]
  defp signers(%{"signAs" => "retention"}, _ctx), do: [R5e.Bootstrap.retention_key()]

  # `sign` takes indexes, and the two node-held keys by name, so a
  # countersigned act one of whose signers is the node key (a Succession
  # of the node key itself) can be written down at all.
  defp signers(%{"sign" => indexes}, _ctx) when is_list(indexes),
    do: Enum.map(indexes, &signing_key/1)

  defp signers(%{"actor" => %{"id" => id}}, _ctx) when is_binary(id) and id != "",
    do: [R5e.TestHelpers.key_for(id)]

  defp signers(_step, _ctx), do: [key(1)]

  defp signing_key("node"), do: :node
  defp signing_key("retention"), do: R5e.Bootstrap.retention_key()
  defp signing_key(n) when is_integer(n), do: key(n)

  # -- substitution ------------------------------------------------------
  # `$setup.N.<field>` and `$cas.N` are replaced *inside* strings, at any
  # depth of a spec. Without this a vector could not name a ref target: an
  # event hash, a content-addressed name and a raw object's address are
  # all decided by the kernel at admission and cannot be written down in
  # advance.

  @token ~r/\$(setup\.\d+\.[A-Za-z]+|interleaved\.\d+\.[A-Za-z]+|key\.\d+(?:\.[A-Za-z]+)?|origin|nodeKey|retentionKey|retentionEndorsement|cas\.\d+|raw\.\d+|derived\.\d+|written\.\d+|casEvent\.\d+)/

  # A `cas` entry is either bare bytes or `{"bytes": …, "mediaType": …}`.
  defp cas_entry(bytes) when is_binary(bytes), do: {bytes, nil}
  defp cas_entry(%{"bytes" => bytes} = entry), do: {bytes, entry["mediaType"]}

  def substitute(value, ctx) when is_binary(value) do
    # A string that is *exactly* one token takes the token's value with
    # its type: `"$setup.0.seq"` is the integer 8, not the string "8". A
    # token embedded in longer text is still interpolated, because
    # `"bytes:$setup.0.payloadAddress"` has to keep working. Without the
    # first rule a vector could not pin a `generation` or a `seq` except
    # by writing down a number that changes whenever the seed set does.
    case Regex.run(@token, value, return: :index) do
      [{0, length}, _] when length == byte_size(value) ->
        resolve_token(String.slice(value, 1..-1//1), ctx)

      _ ->
        Regex.replace(@token, value, fn _match, token -> to_string(resolve_token(token, ctx)) end)
    end
  end

  def substitute(value, ctx) when is_map(value),
    do: Map.new(value, fn {k, v} -> {k, substitute(v, ctx)} end)

  def substitute(value, ctx) when is_list(value), do: Enum.map(value, &substitute(&1, ctx))
  def substitute(value, _ctx), do: value

  # §0's key id, and the raw public key beside it — what a `keyBytes`
  # property and a `matchesSigner` expectation are written in terms of.
  defp resolve_token("key." <> rest, _ctx) do
    case String.split(rest, ".") do
      [n] -> R5e.Request.key_id(key(String.to_integer(n)))
      [n, "id"] -> R5e.Request.key_id(key(String.to_integer(n)))
      [n, "bytes"] -> Base.encode64(R5e.Request.public_key(key(String.to_integer(n))))
    end
  end

  # This chain's origin — unknowable when a vector is written, and named
  # inside every signed request.
  defp resolve_token("origin", _ctx), do: R5e.Origin.current()

  # §10's event 10: the Endorsement every expiry cites. Its ref is settled
  # by bootstrap, so a vector can only name it.
  # The two keys this node holds: its own, and the sweeper's.
  defp resolve_token("nodeKey", _ctx), do: R5e.DSSE.node_key_id()
  defp resolve_token("retentionKey", _ctx), do: R5e.Retention.actor()["id"]

  defp resolve_token("retentionEndorsement", _ctx),
    do: R5e.Bootstrap.role_endorsement("retention", R5e.Retention.actor()["id"])

  defp resolve_token("cas." <> index, ctx), do: Enum.at(ctx.cas, String.to_integer(index))
  defp resolve_token("raw." <> index, ctx), do: Enum.at(ctx.raw, String.to_integer(index))
  defp resolve_token("derived." <> index, ctx), do: Enum.at(ctx.derived, String.to_integer(index))
  defp resolve_token("written." <> index, ctx), do: Enum.at(ctx.written, String.to_integer(index))

  # The `event:` ref of the Nth `PUT /cas`-equivalent admission — what a
  # bytes manifest entry's `casObjectEvent` must equal when it cites the
  # object that admission put on the record.
  defp resolve_token("casEvent." <> index, ctx),
    do: Enum.at(ctx.casReceipts, String.to_integer(index))["eventRef"]

  defp resolve_token("setup." <> rest, ctx), do: receipt_field(ctx.setup, rest)

  # The Nth admission the interleaving hook performed (§7) — how a vector
  # names the act that moved the generation under the instance's feet.
  defp resolve_token("interleaved." <> rest, ctx),
    do: receipt_field(Map.get(ctx, :interleaved, []), rest)

  defp receipt_field(receipts, rest) do
    [index, field] = String.split(rest, ".")
    receipt = Enum.at(receipts, String.to_integer(index))

    case field do
      "payloadAddress" -> event_of(receipt)["payload"]
      other -> Map.fetch!(receipt, other)
    end
  end

  defp event_of(receipt), do: Enum.find(R5e.Log.events(), &(&1["hash"] == receipt["event"]))

  # -- deliberate loss ---------------------------------------------------
  # Two hooks, because two checks are only reachable when something the
  # kernel wrote is gone: a `resolve` denial for a target whose payload is
  # missing, and the `$unresolved` hydration form.

  defp forget_before(nil, _ctx), do: :ok

  defp forget_before(%{"payloadOf" => index}, ctx) do
    receipt = Enum.at(ctx.setup, index)
    File.rm!(Path.join(R5e.CAS.root(), R5e.CAS.relative_path(event_of(receipt)["payload"])))
  end

  defp forget_after(nil, _ctx), do: :ok

  defp forget_after(%{"cas" => index}, ctx) do
    File.rm!(Path.join(R5e.CAS.root(), R5e.CAS.relative_path(Enum.at(ctx.cas, index))))
  end

  defp forget_after(%{"raw" => index}, ctx) do
    File.rm!(Path.join(R5e.CAS.root(), R5e.CAS.relative_path(Enum.at(ctx.raw, index))))
  end

  # -- expectations ------------------------------------------------------

  defp check({:ok, receipt}, %{"outcome" => "admitted"} = expect, ctx, target) do
    assert_name(receipt, expect, ctx)
    assert_commit(receipt, expect, ctx)
    assert_identity(receipt, expect, ctx)

    if address = expect["specAddress"], do: assert(receipt["specAddress"] == address)
    if from = expect["derivedFrom"], do: assert(receipt["derivedFrom"] == substitute(from, ctx))
    if expect["targetNameOmitted"], do: refute(Map.has_key?(payload_target(receipt), "name"))
    if expect["entryUnchanged"], do: assert_entry_unchanged(receipt, ctx, target)
    if index = expect["supersededBy"], do: assert_superseded(receipt, ctx, index, target)
    if refs = expect["resolvedRefs"], do: assert_manifest(receipt, refs, ctx)
    if hydrated = expect["hydrated"], do: assert_hydrated(receipt, hydrated, ctx, target)
    assert_objects(expect, ctx)

    :ok
  end

  defp check({:denied, receipt}, %{"outcome" => "denied"} = expect, ctx, _target) do
    assert_objects(expect, ctx)
    assert_commit(receipt, expect, ctx)
    assert_identity(receipt, expect, ctx)

    if stage = expect["stage"] do
      assert String.starts_with?(receipt["reason"], stage <> ": "),
             "expected a #{stage} denial, got: #{receipt["reason"]}"
    end

    if includes = expect["reasonIncludes"] do
      includes = substitute(includes, ctx)

      assert receipt["reason"] =~ includes,
             "expected the reason to include #{inspect(includes)}, got: #{receipt["reason"]}"
    end

    :ok
  end

  defp check({:denied, receipt}, %{"outcome" => "admitted"}, _ctx, _target),
    do: flunk("expected admission, was denied: #{receipt["reason"]}")

  defp check({:ok, receipt}, %{"outcome" => "denied"} = expect, _ctx, _target),
    do:
      flunk(
        "expected a denial at #{expect["stage"]}, was admitted as #{inspect(receipt["name"])}"
      )

  # -- §5's kernel-derived class ----------------------------------------
  #
  # Three questions, and they are asked of a *receipt* rather than of an
  # outcome, because a denial's evaluation record is evidence too and the
  # payload carries the key either way:
  #
  #   * `derivedObjects` — what the receipt and the recorded payload say,
  #     which must agree: a list returned to a caller but not recorded
  #     would be a claim with no record behind it;
  #   * `derivedRegistered` — what `R5e.RefIndex` holds, asked *after*
  #     `replayAfterInstance` when the vector set it, so the answer comes
  #     from the chain rather than from this process's memory;
  #   * `exportDerivedObjects` — what an export writes, which §5 makes the
  #     union over the payloads.
  defp check_derived(result, expect, ctx) do
    receipt = elem(result, 1)

    if expected = expect["derivedObjects"] do
      expected = substitute(expected, ctx)

      assert receipt["derivedObjects"] == expected,
             "expected derivedObjects #{inspect(expected)} on the receipt, " <>
               "got #{inspect(receipt["derivedObjects"])}"

      assert R5e.TestHelpers.payload_of(receipt)["derivedObjects"] == expected,
             "the receipt's derivedObjects and the recorded ones differ"
    end

    for address <- List.wrap(expect["derivedRegistered"]) do
      address = substitute(address, ctx)

      assert R5e.RefIndex.derived?(address),
             "#{address} is not registered as a kernel-derived object"

      refute R5e.RefIndex.unreferenced?(address),
             "#{address} is derived and should never be unreferenced (§5)"
    end

    if expected = expect["exportDerivedObjects"] do
      assert export_manifest()["derivedObjects"] == Enum.sort(substitute(expected, ctx))
    end

    :ok
  end

  defp export_manifest do
    dest = Path.join(System.tmp_dir!(), "r5e-vector-export-#{System.unique_integer([:positive])}")
    {:ok, ^dest, manifest} = R5e.Export.run(dest)
    File.rm_rf(dest)
    manifest
  end

  # §5: the bytes are the `admit` step, so what is on disk afterwards is
  # part of what a vector pins. `objectGone` is only reachable through a
  # granted `CasExpired`; `objectPresent` is what every refusal must leave
  # behind, and asserting it is how a vector says the refusal cost nothing.
  defp assert_objects(expect, ctx) do
    for address <- List.wrap(expect["objectGone"]) do
      address = substitute(address, ctx)
      refute R5e.CAS.exists?(address), "#{address} is still in the CAS"
    end

    for address <- List.wrap(expect["objectPresent"]) do
      address = substitute(address, ctx)
      assert R5e.CAS.exists?(address), "#{address} is not in the CAS"
    end
  end

  # §7. `recordAttempts` is how many times the pipeline reached `record`:
  # the interleaving hook fires once per attempt whether or not it admits
  # anything that time, so it counts them. A vector that says 2 is saying
  # "it was contended once and the retry succeeded".
  #
  # `policy` is asserted as a subset, deep: a vector pins the generations
  # the engine reported on the pass that committed and says nothing about
  # the rest of the block.
  defp assert_commit(receipt, expect, ctx) do
    if n = expect["recordAttempts"] do
      attempts = Process.get(:vector_record_attempts, 0)

      assert attempts == n,
             "expected #{n} record attempt(s), the pipeline reached record #{attempts} time(s)"
    end

    if policy = expect["policy"] do
      assert_subset(receipt["policy"], substitute(policy, ctx), "policy")
    end

    if expect["haltedAfter"] do
      assert R5e.Log.halted() != nil, "the node should be halted and is not"
    end

    if expect["notHalted"] do
      assert R5e.Log.halted() == nil, "the node is halted: #{R5e.Log.halted()}"
    end
  end

  defp assert_subset(actual, expected, where) when is_map(expected) do
    assert is_map(actual), "#{where}: expected a map, got #{inspect(actual)}"

    for {key, want} <- expected do
      assert_subset(Map.get(actual, key), want, "#{where}.#{key}")
    end
  end

  defp assert_subset(actual, expected, where),
    do:
      assert(
        actual == expected,
        "#{where}: expected #{inspect(expected)}, got #{inspect(actual)}"
      )

  # §1/§2: what the record says about who asked, and whether the asking
  # was recorded at all. `recorded: false` is the shape of an
  # unattributable refusal — no event, no nonce spent.
  defp assert_identity(receipt, expect, ctx) do
    if Map.has_key?(expect, "recorded") do
      assert receipt["recorded"] == expect["recorded"],
             "expected recorded=#{expect["recorded"]}, receipt says #{inspect(receipt["recorded"])}"
    end

    if identity = expect["identity"], do: assert(receipt["identity"] == identity)

    if Map.has_key?(expect, "depth") do
      assert receipt["depth"] == expect["depth"],
             "expected depth #{inspect(expect["depth"])}, got #{inspect(receipt["depth"])}"

      assert R5e.TestHelpers.payload_of(receipt)["depth"] == expect["depth"],
             "the receipt's depth and the recorded one differ"
    end

    if signers = expect["signers"] do
      assert receipt["signers"] == substitute(signers, ctx)
    end

    # §5: the whole derivation, deep-equal. A vector writes the chain it
    # expects link by link, so a kernel that resolved the same authority by
    # a different route is caught rather than credited.
    if authority = expect["resolvedAuthority"] do
      expected = substitute(authority, ctx)

      assert receipt["resolvedAuthority"] == expected,
             "resolvedAuthority: expected #{inspect(expected)}, " <>
               "got #{inspect(receipt["resolvedAuthority"])}"

      assert R5e.TestHelpers.payload_of(receipt)["resolvedAuthority"] == expected,
             "the receipt's resolvedAuthority and the recorded one differ"
    end

    if roots = expect["authorityRoots"] do
      chains = receipt["resolvedAuthority"] || []
      actual = chains |> Enum.map(&List.last(&1["chain"])["actor"]) |> Enum.uniq() |> Enum.sort()
      assert actual == Enum.sort(substitute(roots, ctx))
    end

    if spec = expect["payloadSpec"] do
      assert_subset(R5e.TestHelpers.payload_of(receipt)["spec"], substitute(spec, ctx), "spec")
    end

    if target = expect["submittedTarget"] do
      assert R5e.TestHelpers.payload_of(receipt)["submittedTarget"] == substitute(target, ctx)
    end

    # §5's `ts(s)`: the instant the log wrote for this act. A vector that
    # pins a term boundary against the clock is only pinning the contract's
    # rule if the record and the comparison used the same instant, so the
    # vector says which instant that was rather than trusting them to agree.
    if ts = expect["eventTs"] do
      assert R5e.TestHelpers.event_of(receipt)["ts"] == ts,
             "expected the recorded event to carry ts #{inspect(ts)}, " <>
               "got #{inspect(R5e.TestHelpers.event_of(receipt)["ts"])}"
    end

    if Map.has_key?(expect, "nonceClaimed") do
      %{signer: signer, nonce: nonce} = Process.get(:vector_last_request)

      assert R5e.NonceIndex.claimed?(signer, nonce) == expect["nonceClaimed"],
             "expected nonceClaimed=#{expect["nonceClaimed"]}"
    end
  end

  defp assert_name(receipt, expect, ctx) do
    if name = expect["name"] do
      assert receipt["name"] == substitute(name, ctx)
    end

    if pattern = expect["nameMatches"] do
      assert Regex.match?(Regex.compile!(pattern), receipt["name"])
    end
  end

  # The manifest is asserted entry by entry, in order, each expected entry
  # a subset of the recorded one: a vector pins what it means to pin and
  # says nothing about the rest. The receipt and the payload must agree —
  # a manifest returned to a caller but not recorded would be a claim with
  # no record behind it.
  defp assert_manifest(receipt, expected, ctx) do
    actual = receipt["resolvedRefs"]
    expected = substitute(expected, ctx)

    assert length(actual) == length(expected),
           "expected #{length(expected)} manifest entries, got #{inspect(actual)}"

    for {want, got} <- Enum.zip(expected, actual) do
      for {key, value} <- want do
        assert Map.fetch(got, key) == {:ok, value},
               "manifest entry #{inspect(got["path"])}: expected #{key} = #{inspect(value)}, " <>
                 "got #{inspect(Map.get(got, key))}"
      end
    end

    assert R5e.TestHelpers.payload_of(receipt)["resolvedRefs"] == actual,
           "the receipt's manifest and the recorded one differ"
  end

  defp assert_hydrated(receipt, expected, ctx, {group, version, kind}) do
    {:ok, entry, lineage} = R5e.ResourceStore.get(group, version, kind, receipt["name"], :deep)
    expected = substitute(expected, ctx)

    for {pointer, want} <- expected do
      assert pointer_get(entry["spec"], pointer) == want,
             "hydrated #{pointer}: expected #{inspect(want)}, " <>
               "got #{inspect(pointer_get(entry["spec"], pointer))}"
    end

    # The stored form is untouched: hydration is a computed view.
    {:ok, stored, []} = R5e.ResourceStore.get(group, version, kind, receipt["name"])
    assert stored["spec"] == R5e.TestHelpers.payload_of(receipt)["spec"]
    assert lineage != []
  end

  # RFC 6901, enough of it for a vector: "" is the whole document.
  defp pointer_get(value, ""), do: value

  defp pointer_get(value, "/" <> rest) do
    [segment | tail] = String.split(rest, "/")
    segment = segment |> String.replace("~1", "/") |> String.replace("~0", "~")
    tail = if tail == [], do: "", else: "/" <> Enum.join(tail, "/")

    case value do
      %{} -> pointer_get(Map.get(value, segment), tail)
      list when is_list(list) -> pointer_get(Enum.at(list, String.to_integer(segment)), tail)
      _ -> :missing
    end
  end

  defp assert_entry_unchanged(receipt, ctx, {group, version, kind}) do
    {:ok, entry, _} = R5e.ResourceStore.get(group, version, kind, receipt["name"])
    assert entry["admissionEvent"] == hd(ctx.setup)["eventRef"]
    refute entry["admissionEvent"] == receipt["eventRef"]
  end

  defp assert_superseded(receipt, ctx, index, {group, version, kind}) do
    displaced = R5e.ResourceStore.superseded(group, version, kind, receipt["name"])
    previous = Enum.at(ctx.setup, index)

    assert Enum.any?(displaced, &(&1["admissionEvent"] == previous["eventRef"]))

    assert Enum.any?(displaced, &(&1["supersededBy"] == receipt["eventRef"])),
           "the displaced entry does not record supersededBy"

    {:ok, entry, _} = R5e.ResourceStore.get(group, version, kind, receipt["name"])
    assert entry["supersedes"] == previous["eventRef"]
  end

  defp payload_target(receipt), do: R5e.TestHelpers.payload_of(receipt)["target"]
end

defmodule R5e.CommitInvariants do
  @moduledoc false
  # The property spec/05 §7 exists to buy, checked against a whole chain
  # rather than against one admission: **no granted receipt cites a
  # generation that had already been displaced at the seq the receipt was
  # written at.**
  #
  # "Generation" here is both places one appears: the `generations` a
  # policy engine reported reading, and the `generation` on every
  # `kind`-class manifest entry. For each, the generation that stood at
  # seq N is the highest seq below N at which a granted admission targeted
  # that ref — which the chain answers on its own, with no help from the
  # store, so this is a check of the record against itself.
  #
  # Denials are deliberately outside it. A `contended` denial's policy
  # block cites exactly the stale generation that got it refused: that is
  # the evidence for the refusal, and erasing it would make the denial
  # unreadable. A denial says what was read *and* that it was not enough.

  import ExUnit.Assertions

  def assert_no_stale_citation do
    chain =
      for event <- R5e.Log.events(),
          {:ok, bytes} <- [R5e.CAS.get(event["payload"] || "")],
          {:ok, payload} <- [Jason.decode(bytes)],
          do: {event, payload}

    granted = Enum.filter(chain, fn {_event, payload} -> payload["outcome"] == "admitted" end)

    for {event, payload} <- granted do
      seq = event["seq"]

      for {ref, generation} <- get_in(payload, ["policy", "generations"]) || %{} do
        check(granted, ref, generation, seq, "the policy block of seq #{seq}")
      end

      for entry <- payload["resolvedRefs"] || [], entry["class"] == "kind" do
        check(granted, entry["value"], entry["generation"], seq, "seq #{seq} at #{entry["path"]}")
      end
    end

    length(granted)
  end

  defp check(granted, ref, generation, seq, where) do
    assert generation < seq,
           "#{where} cites #{ref} at generation #{generation}, which is not below its own seq"

    stood = generation_as_of(granted, ref, seq)

    assert generation == stood,
           "#{where} cites #{ref} at generation #{generation}, but generation #{stood} stood " <>
             "at that position — a receipt citing a generation displaced before it was written"
  end

  defp generation_as_of(granted, ref, seq) do
    granted
    |> Enum.filter(fn {event, payload} -> event["seq"] < seq and target_path(payload) == ref end)
    |> List.last()
    |> case do
      nil -> nil
      {event, _payload} -> event["seq"]
    end
  end

  defp target_path(payload) do
    t = payload["target"] || %{}
    t["name"] && "#{t["group"]}/#{t["version"]}/#{t["kind"]}/#{t["name"]}"
  end
end
