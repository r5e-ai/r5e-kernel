defmodule R5e.Bootstrap.Refused do
  @moduledoc """
  An act this node had to record was refused, or could not be signed by
  the key the gate will check it against.

  Raised in place of a `MatchError` on `{:ok, _} = admit…`: failing closed
  is right, and failing closed as a match on a denial receipt dumped into a
  crash report leaves an operator with no reason and no recovery. The
  message names the act, the denial, and what to do.
  """
  defexception [:message]
end

defmodule R5e.Bootstrap do
  @moduledoc """
  Boot sequence: replay the log to rebuild the derived views (registry,
  resource store), then admit any core Kinds not yet on the chain — through
  the same admission pipeline as everything else.

  Self-hosting fixpoint: to validate the first KindDefinition the registry
  must already know what a KindDefinition is, so the meta-Kind is
  pre-registered in memory and then immediately admitted against itself.
  Only the admitted record is authoritative; the pre-registration is
  scaffolding that the first event on the chain retroactively covers.

  ## The schema-lite v2 transition (spec/05 §11)

  `priv/kinds/kind-definition.json` is now the v2 meta-Kind: naming `path`,
  substrate `resource`, and a schema that declares `naming` and
  `description`. A **fresh** log admits it directly, as event one. A log
  that already carries the v1 meta-Kind gets exactly one supersession act
  at boot — actor `system:bootstrap`, reason `schema-lite-v2 migration`,
  recorded through the ordinary pipeline like every other admission and
  visible on the chain as `transition` on its payload. It is the one
  exempt-by-design act: §1 denies a second definition of an identity unless
  it is byte-identical, and this one is not.

  Definitions replayed from before v2 carry no `naming`. They are loaded as
  `%{"mode" => "caller"}` with `legacy: true` (`R5e.Kind.from_map/2`,
  `replay: true`) — the v1 kernel's behaviour, named rather than invented —
  and never denied. A record is not retroactively invalid because the rules
  grew.
  """

  require Logger

  @order_file "order.json"
  @transition_reason "spec-011"
  @retention_role "retention"
  @retention_kinds ["core.r5e.io/v1/CasExpired"]
  @ten_years 10 * 365 * 24 * 60 * 60

  @doc """
  The actor of record on every bootstrap admission: **the node key**
  (spec 011 §10). There is no `system:bootstrap` principal any more, and
  no placeholder fingerprint — the seeds are signed like everything else,
  by a key a reader of the chain can name and check.
  """
  def seed_actor, do: %{"id" => R5e.DSSE.node_key_id()}

  def transition_reason, do: @transition_reason

  @doc """
  Submit a bootstrap admission: signed by the node key, `authority: []`,
  a fresh nonce, `expires` one hour out (§10). Every seed and every
  transition goes through here, so there is exactly one way this node
  signs its own vocabulary into existence.
  """
  @spec admit_as_node(String.t(), String.t(), String.t(), String.t() | nil, map(), keyword()) ::
          {:ok, map()} | {:denied, map()}
  def admit_as_node(group, version, kind, name, spec, extra \\ []) do
    ensure_node_key_held!("admitting #{act_path(group, version, kind, name)}")
    target = %{"group" => group, "version" => version, "kind" => kind, "name" => name}

    envelope = R5e.Request.sign(%{target: target, spec: spec}, [:node])

    R5e.Admission.admit(
      Enum.into(extra, %{
        envelope: envelope,
        group: group,
        version: version,
        kind: kind,
        name: name,
        spec: spec
      })
    )
  end

  @doc """
  Refuse to sign a node act with a key that is not the node key.

  `admit_as_node/6` signs with the **locally held** key; every node-key
  gate compares against the **head** of the succession chain. A node whose
  key was succeeded to a key it does not hold therefore signs acts that
  will be denied — and, before this check, the denial arrived at the next
  boot-time seed as a `MatchError` on `{:ok, _} = …`, days or a kernel
  upgrade after the succession that caused it.

  The two are the same key on every ordinary deployment, so this costs
  nothing there. Where they differ it names the successor, which is the one
  fact an operator needs.
  """
  @spec ensure_node_key_held!(String.t()) :: :ok
  def ensure_node_key_held!(act) do
    local = R5e.DSSE.local_key_id()
    node = R5e.DSSE.node_key_id()

    if local == node do
      :ok
    else
      raise R5e.Bootstrap.Refused, """
      refusing to act: this node signs with a key that is no longer the node key.

        act: #{act}
        node key (head of the succession chain): #{node}
        locally held signing key:                #{local}

      An admitted core.r5e.io/v1/Succession moved the node key to the key
      above, and this process does not hold its private half. Signing here
      would produce an act every node-key gate denies.

      Recovery: install the successor's private key as this node's signing key,
      under the same custody as the key it replaces, or record a further
      Succession to a key this node does hold. Both are acts on the chain; this
      refusal changes nothing and records nothing.
      """
    end
  end

  defp act_path(group, version, kind, nil), do: "#{group}/#{version}/#{kind}"
  defp act_path(group, version, kind, name), do: "#{group}/#{version}/#{kind}/#{name}"

  # Runs synchronously inside the supervision start sequence (before the
  # HTTP listener starts), then yields `:ignore` — no process to keep.
  def child_spec(_opts), do: %{id: __MODULE__, start: {__MODULE__, :start_link, []}}

  def start_link do
    run()
    :ignore
  end

  def run do
    replay()
    engine_build = R5e.Policy.KernelCedar.prepare_engine_build()

    if Application.get_env(:r5e, :seed_kernel_policy, true) do
      R5e.Policy.KernelCedar.with_bootstrap(
        fn ->
          # An upgraded chain already knows CasObject and may carry an older
          # active policy. Admit the current descriptor before asking that
          # policy to evaluate any changed core seed. A fresh chain reaches
          # the same admission after seed_core_kinds creates CasObject.
          R5e.Policy.KernelCedar.seed_engine_build_if_known(engine_build)
          seed_core_kinds()
          R5e.Policy.KernelCedar.seed(engine_build)
        end,
        engine_build
      )
    else
      seed_core_kinds()
    end

    :ok
  end

  @doc """
  Rebuild registry, resource store and reference index from the recorded
  chain, and clear a `halted` node (spec/05 §7) — the views are the thing
  that was behind, and this is what catches them up.

  The index (spec/05 §5) is rebuilt from **every** event, not only the
  granted ones: a denial's payload address is still bytes the kernel
  wrote, and a denial's resolution manifest is still part of the record of
  what was asked. Registry and store are rebuilt from grants alone, as
  before — a refused request changed no vocabulary and stored no entry.
  """
  def replay do
    R5e.RefIndex.reset()
    R5e.NonceIndex.reset()
    R5e.Authority.reset()
    R5e.Origin.reset_adoption()
    # spec/05 §7: a halt says the derived views may be behind the chain.
    # Rebuilding them from the chain is exactly what clears it, and this
    # is the only thing that does short of a restart.
    R5e.Log.resume()

    for event <- R5e.Log.read_events(),
        {:ok, payload} <- [R5e.Log.payload(event)] do
      R5e.RefIndex.observe(event, payload)
      R5e.Authority.observe(event, payload)
      replay_identity(event, payload)

      if event["kind"] == "admission.granted" do
        replay_event(event, payload)
      end
    end

    :ok
  end

  # The chain is the record of both identity views, and replay has to
  # rebuild them **as the live node held them** — not as a generous
  # reading of the log would allow.
  #
  # A nonce claim is re-taken from every recorded act *the live path would
  # have claimed for*, which `R5e.Admission.nonce_claimed?/1` decides from
  # the recorded reason: denials at or before the claim point claimed
  # nothing, everything else did. Claiming on every payload would refuse,
  # after a restart, envelopes the live node had left claimable — an
  # `actor mismatch` denial in particular, which deliberately does not
  # spend the named signer's nonce.
  #
  # The origin is adopted from whichever payload carries `random`. Exactly
  # one does: event 1 on a fresh chain, the meta-Kind transition on a
  # legacy one. The chain wins over the key file — a data directory that
  # disagrees with its own log follows the log.
  defp replay_identity(_event, payload) do
    if R5e.Admission.nonce_claimed?(payload) do
      R5e.NonceIndex.observe(
        get_in(payload, ["actor", "id"]),
        payload["nonce"],
        payload["expires"]
      )
    end

    if is_binary(payload["origin"]) and is_binary(payload["random"]) do
      R5e.Origin.adopt(payload["origin"], payload["random"])
    end
  end

  defp replay_event(event, payload) do
    target = payload["target"] || %{}
    spec = payload["spec"]

    if target["kind"] == "KindDefinition" do
      case R5e.Kind.from_map(spec, replay: true) do
        {:ok, kind} ->
          R5e.KindRegistry.force_put(%{kind | derived_from: payload["derivedFrom"]})

        {:error, _} ->
          :ok
      end
    end

    case R5e.KindRegistry.get(target["group"], target["version"], target["kind"]) do
      {:ok, %R5e.Kind{substrate: substrate}} when substrate != "event" ->
        replay_entry(event, payload, target, spec, substrate)

      _ ->
        :ok
    end
  end

  # §2 `server`: the recorded payload deliberately has no `target.name`, so
  # replay derives the name from the event exactly as `record` did — never
  # from the payload.
  defp replay_entry(event, payload, target, spec, substrate) do
    name = target["name"] || R5e.Admission.event_ref(event)

    entry =
      R5e.ResourceStore.entry(%{
        group: target["group"],
        version: target["version"],
        kind: target["kind"],
        name: name,
        substrate: substrate,
        spec: spec,
        actor: get_in(payload, ["actor", "id"]),
        event: event,
        resolved: payload["resolvedRefs"],
        derived_from: payload["derivedFrom"]
      })

    {g, v, k} = {target["group"], target["version"], target["kind"]}

    case R5e.ResourceStore.get(g, v, k, name) do
      {:error, :not_found} ->
        R5e.ResourceStore.put(g, v, k, name, entry)

      {:ok, existing, _lineage} ->
        # A byte-identical re-admission left the entry unchanged (§2,
        # `content` idempotent); anything else displaced it.
        if R5e.Canonical.encode(existing["spec"]) == R5e.Canonical.encode(spec),
          do: :ok,
          else: R5e.ResourceStore.supersede(g, v, k, name, entry)
    end
  end

  @doc """
  Admit the core Kind seeds that are not yet on the chain, transitioning
  any whose bytes changed under spec 011, then the retention Endorsement.

  ## Order is a manifest, not a directory listing

  Spec 011 §10 makes the seeding order an explicit `priv/kinds/order.json`
  rather than filename order. A chain's first ten events are its
  vocabulary and its first grant of authority, and reading them back
  should not require knowing how a directory sorted on the machine that
  wrote them:

  | seq | act |
  |---|---|
  | 1 | KindDefinition v3 — the payload also carries `origin` and `random` |
  | 2 | CasExpired (`requiresAuthority: true`) |
  | 3 | CasObject |
  | 4–9 | Principal, Endorsement, Badge, Succession, Revocation, Deployment |
  | 10 | the node key endorses the retention key for `CasExpired` |

  The meta-Kind is first because a KindDefinition is admitted *against*
  the meta-Kind: a chain whose first event is a `CasObject` definition
  validated against a Kind with no admission yet would record the fixpoint
  the wrong way round.

  Events 1–10 are acts, and they precede the Charter's "first act is to
  admit this charter" — a charter admission needs a Kind to be admitted
  under. That is a stated exception (§10), not a re-reading of "act"; the
  charter remains the first act of governance, as on the genesis chain.

  ## The same-identity transition (§10, §11)

  A KindDefinition is `path`-named, so a second definition of the same
  identity is denied unless byte-identical — **except** the same-identity
  transition, which is recorded as such on the payload. Every core seed
  whose bytes changed under this contract takes that path: the meta-Kind
  (v2 → v3) and `CasExpired` (v1 → v2, which gains `requiresAuthority`).
  It is signed by the node key like every other bootstrap act, and the
  payload carries `transition: "spec-011"` so a reader of the chain sees
  an exempt act declared as one rather than inferred.

  ## What an existing log does at its next boot

  The identity Kinds are core Kinds and are seeded exactly like the
  meta-Kind: a log that lacks them gets them on its next boot, as ordinary
  seed admissions signed by the node key, through the same pipeline as
  everything else. That includes logs this slice never opens — the
  r5e-core genesis log among them.

  **That is the correct behaviour, not a defect.** Nothing skips
  admission; new vocabulary enters through the door and leaves a record of
  having done so. The alternative — teaching bootstrap to withhold a core
  Kind from a log that predates it — would mean a deployment could hold a
  Kind the kernel enforces and the chain never records, which is the one
  thing this design exists to refuse. A reader of such a log sees two
  admissions with an actor, a position and a timestamp, and can say
  exactly when this deployment learned what a `CasObject` is.
  """
  def seed_core_kinds do
    [meta | _] = specs = manifest_specs()
    pre_register_meta(meta)
    Enum.each(specs, &seed/1)
    endorse_retention()
    :ok
  end

  @doc "The seed manifest (§10): the ordered filenames in `priv/kinds/order.json`."
  @spec manifest_files() :: [String.t()]
  def manifest_files do
    %{"files" => files} =
      :code.priv_dir(:r5e)
      |> Path.join("kinds/#{@order_file}")
      |> File.read!()
      |> Jason.decode!()

    files
  end

  defp manifest_specs do
    for file <- manifest_files() do
      :code.priv_dir(:r5e) |> Path.join("kinds/#{file}") |> File.read!() |> Jason.decode!()
    end
  end

  # Fresh log: pre-register the meta-Kind so its own admission can
  # validate against it. The first event on the chain retroactively covers
  # this; it is scaffolding, never the authority.
  defp pre_register_meta(spec) do
    {:ok, meta} = R5e.Kind.from_map(spec)

    case R5e.KindRegistry.get(meta.group, meta.version, meta.kind) do
      {:error, :unknown_kind} -> R5e.KindRegistry.force_put(meta)
      _ -> :ok
    end
  end

  defp seed(spec) do
    name = "#{spec["group"]}/#{spec["version"]}/#{spec["kind"]}"

    case R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", name) do
      {:error, :not_found} ->
        admit_seed!(spec, name, origin_fields())

      {:ok, entry, _lineage} ->
        # The bytes changed under this contract: the same-identity
        # transition, declared on the payload.
        unless entry["specAddress"] == R5e.CAS.spec_address(spec) do
          admit_seed!(spec, name, [transition: @transition_reason] ++ origin_fields())
        end
    end
  end

  defp admit_seed!(spec, name, extra) do
    case admit_as_node("core.r5e.io", "v1", "KindDefinition", name, spec, extra) do
      {:ok, receipt} ->
        receipt

      {:denied, receipt} ->
        raise R5e.Bootstrap.Refused, """
        refusing to start: this node could not seed a core Kind.

          core.r5e.io/v1/KindDefinition/#{name}
          denial: #{receipt["reason"]}

        The kernel policy bundle in force decided this. A node that cannot admit
        its own vocabulary cannot enforce it; core.r5e.io/v1/PolicyBundle is
        refused at admission when it would deny the node key's transition of the
        meta-Kind, so a chain that carries such a bundle predates that check.
        """
    end
  end

  # §10: the **first act this chain records under this contract** carries
  # the `random` its origin was derived from, so a reader with the node
  # public key re-derives the origin and checks that this deployment did
  # not simply pick one. Exactly one act carries it, and which one differs:
  # event 1 on a fresh chain, the meta-Kind transition on a legacy one,
  # whose earlier events predate origins entirely.
  #
  # "Has the chain got one yet" is `R5e.Origin.adopted?/0`, which replay
  # answers from the log; marking it here is what keeps the *next* seed in
  # this same boot from writing a second copy.
  defp origin_fields do
    if R5e.Origin.adopted?() do
      []
    else
      random = R5e.Origin.random()
      R5e.Origin.adopt(R5e.Origin.current(), random)
      [random: random]
    end
  end

  # -- roles (§10) --------------------------------------------------------

  @doc "This node's retention keypair — generated under the data directory on first use."
  @spec retention_key() :: map()
  def retention_key, do: R5e.Signer.Local.role_keypair(@retention_role)

  @doc """
  Event 10 and its renewals: the node key endorses a locally held role key
  for a named set of Kinds.

  Named by the contract (§10) so a co-located extension — the fold is the
  first — gets its authority the same way the retention sweeper does, by
  an Endorsement on the chain rather than by a constant in someone's
  source. `kinds` defaults to `["*"]`, `mayIssue` to `false`, and the term
  to ten years from now.
  """
  @spec endorse_role(binary(), String.t(), keyword()) :: {:ok, map()} | {:denied, map()}
  def endorse_role(public_key_bytes, role, opts \\ []) do
    now = R5e.Clock.now()

    spec = %{
      "subject" => RecurseVerify.DSSE.key_id!("ed25519", public_key_bytes),
      "subjectKey" => %{
        "algorithm" => "ed25519",
        "bytes" => Base.encode64(public_key_bytes)
      },
      "role" => role,
      "kinds" => Keyword.get(opts, :kinds, ["*"]),
      "mayIssue" => Keyword.get(opts, :may_issue, false),
      "notBefore" => RecurseVerify.Instant.to_string(now),
      "notAfter" =>
        RecurseVerify.Instant.to_string(
          DateTime.add(now, Keyword.get(opts, :term_seconds, @ten_years), :second)
        )
    }

    admit_as_node("core.r5e.io", "v1", "Endorsement", nil, spec)
  end

  @doc """
  The newest admitted Endorsement of `role` for `subject`, as an
  `event:sha256:…` ref — what the sweeper (and later the fold) cites.

  The newest **effective** one (§5): §10's renewal rule is that a new
  Endorsement is admitted before the old one's `notAfter`, so at any
  moment several may be on the chain and at most one of them is the one to
  cite. A revoked or out-of-term Endorsement is not cited merely because
  it is the most recent — citing it would produce a denial at `resolve`
  and leave the sweeper unable to say why.

  `nil` therefore means "nothing to cite", which is two different
  situations. `role_status/2` distinguishes them and says which.
  """
  @spec role_endorsement(String.t(), String.t()) :: String.t() | nil
  def role_endorsement(role, subject), do: role_status(role, subject)["endorsement"]

  @doc """
  What this chain says about `role` for the key this node holds for it:
  whether an Endorsement was ever recorded, whether the newest one is
  effective, and — when it is not — why, in the walk's own words.

  Three statuses, and the distinction between the first two is the whole
  point (spec 011 §10, review K4):

  * `"unendorsed"` — no Endorsement of this role for this subject has ever
    been recorded. Boot mints one.
  * `"effective"` — the newest recorded one passes §5's walk at this
    sequence and clock. `"endorsement"` carries its `event:sha256:…` ref.
  * `"withheld"` — one was recorded and is revoked or out of term. Boot
    **does not** mint over it: a revocation a restart reverses is a
    suspension, not a revocation.
  """
  @spec role_status(String.t()) :: map()
  def role_status(role),
    do: role_status(role, RecurseVerify.DSSE.key_id!("ed25519", role_key(role).public))

  @doc "As `role_status/1`, for an explicitly named subject key id."
  @spec role_status(String.t(), String.t()) :: map()
  def role_status(role, subject) do
    s = R5e.Succession.next_seq()
    ts = R5e.Clock.ts()

    case recorded_role_endorsements(role, subject) do
      [] ->
        status(role, subject, "unendorsed", nil, nil)

      refs ->
        case Enum.filter(refs, &R5e.Authority.effective(&1, s, ts).ok) do
          [] -> status(role, subject, "withheld", nil, withheld_reason(refs, s, ts))
          effective -> status(role, subject, "effective", List.last(effective), nil)
        end
    end
  end

  defp status(role, subject, state, endorsement, reason),
    do: %{
      "role" => role,
      "subject" => subject,
      "status" => state,
      "endorsement" => endorsement,
      "reason" => reason
    }

  # The lead is the walk's own words — "revoked at 15", "out of term" —
  # because "revoked" is not true of an expiry and the reason a reader
  # gets should be the one the chain supports.
  defp withheld_reason(refs, s, ts) do
    newest = List.last(refs)

    "the newest recorded Endorsement (#{newest}) is #{R5e.Authority.effective(newest, s, ts).reason}; " <>
      "explicit re-endorsement required. Boot does not mint over a recorded Endorsement — a " <>
      "revocation a restart reverses is a suspension. Recovery is an explicit act by the node " <>
      "key (`R5e.Bootstrap.endorse_role/3`), recorded on the chain like any other."
  end

  # **Every** recorded Endorsement of (role, subject), effective or not.
  # "Has this role ever been endorsed" is a different question from "is it
  # endorsed now", and boot needs the first one: a revoked Endorsement is a
  # `nil` answer to the second, which is why the old rule re-minted it.
  defp recorded_role_endorsements(role, subject) do
    for event <- R5e.Log.read_events(),
        event["kind"] == "admission.granted",
        {:ok, payload} <- [R5e.Log.payload(event)],
        R5e.Admission.target_path(payload) == "core.r5e.io/v1/Endorsement",
        payload["spec"]["role"] == role,
        payload["spec"]["subject"] == subject,
        do: R5e.Admission.event_ref(event)
  end

  defp role_key("retention"), do: retention_key()
  defp role_key(role), do: R5e.Signer.Local.role_keypair(role)

  # §10: role Endorsements are minted **at boot only**, and now only when
  # none was ever recorded. `R5e.Retention.sweep/0` cites the newest
  # effective one and, when there is none, refuses rather than minting — a
  # revocation the revoked party can undo by acting is not a revocation,
  # and the sweeper is the revoked party here. Boot was the other way the
  # revoked party got its authority back, without anyone deciding to give
  # it back; it is not any more.
  defp endorse_retention do
    key = retention_key()
    subject = RecurseVerify.DSSE.key_id!("ed25519", key.public)

    case role_status(@retention_role, subject) do
      %{"status" => "unendorsed"} ->
        endorse_role!(key.public, @retention_role, kinds: @retention_kinds, may_issue: false)

      %{"status" => "effective"} ->
        :ok

      %{"status" => "withheld", "reason" => reason} ->
        Logger.warning("the #{@retention_role} role is not effective: #{reason}")
    end

    :ok
  end

  defp endorse_role!(public_key_bytes, role, opts) do
    case endorse_role(public_key_bytes, role, opts) do
      {:ok, _receipt} ->
        :ok

      {:denied, receipt} ->
        raise R5e.Bootstrap.Refused, """
        refusing to start: this node could not endorse its #{role} role key.

          subject: #{RecurseVerify.DSSE.key_id!("ed25519", public_key_bytes)}
          denial: #{receipt["reason"]}

        The kernel policy bundle in force decided this. A bundle that denies the
        node key's admission of a core.r5e.io/v1/Endorsement leaves this node
        unable to grant any role its authority; core.r5e.io/v1/PolicyBundle is
        refused at admission when it would, so a chain that carries one predates
        that check.
        """
    end
  end
end
