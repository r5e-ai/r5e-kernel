defmodule R5e.Admission do
  @moduledoc """
  The single gate (core spec/02, pipeline amended by spec/05 §4):

      authenticate → validateStructure → resolve → authorize
                   → validateConstraints → record → admit

  There is no exempt path and no exempt actor — the core Kinds themselves
  enter here at bootstrap. Denials are recorded on the log too: requests
  are acts, and over-asking leaves a trail.

  Why the validation stage is split in two: **policy must see a
  structurally sound request, and must decide before the request's
  constraints are judged.** `validateStructure` establishes that the thing
  is the shape it claims (Kind lookup, `type`, the ref-wrapper form,
  `additionalProperties`, no floats, the limits) and settles the instance's
  *name* (§2). `resolve` then does pure lookups. Only then does policy run;
  `validateConstraints` (`required`, `nonEmpty`, `enum`, `pattern`,
  `minimum`/`maximum`, `exactlyOne`, `requires`) comes after it. A denial's
  reason is prefixed with the stage name, and those seven names are the
  contract.

  A request as it arrives at the gate is the *transport's* half of an
  admission — the route, the spec bytes, and the signed envelope that
  says who is asking and for what:

      %{
        envelope: map(),                            # §1's DSSE envelope
        group: ..., version: ..., kind: ...,        # the route
        name: nil | String.t(),                     # the body's name
        spec: map(),
        transition: nil | String.t(),               # §11, bootstrap only
        random: nil | String.t(),                   # §10, event 1 only
        cas_bytes: nil | binary()                   # §5, CasObject only
      }

  `authenticate` decodes the envelope and adds the identity half —
  `actor`, `signers`, `signed`, `origin`, `submitted_target`, `authority`,
  `nonce`, `expires`, `spec_address`, `derived_from` — all of them read
  from the signed request object and none of them from the transport.
  The route and the body `name` are compared against the signed target a
  stage later (`validateStructure: target mismatch`); they are how a
  caller addresses the request, never how the kernel decides what was
  asked.

  `cas_bytes` is not part of the request as a caller writes it and never
  reaches the spec: it is the body `R5e.CAS.admit/3` hashed to build the
  `CasObject` spec, carried to the `admit` step so the bytes are written
  **only** on a grant (§5).

  `derived_from` is an **envelope** field (§1): it is recorded beside
  `spec` on the payload, the store entry and the receipt, and is never an
  input to naming or to `specAddress` — so the authored file is the
  admitted bytes.

  ## What each stage delegates to

    * `resolve` (§4) → `R5e.Resolve`. Every ref value becomes one entry of
      the **resolution manifest**, which then rides on the request: policy
      reads it as `resolved`, `record` writes it beside `spec`, the
      receipt returns it. An empty manifest means what it says — this spec
      cites nothing.
    * `authorize` → `R5e.Policy`. Its metadata rides along from here, so a
      later stage that refuses a request the policy allowed still leaves a
      receipt saying who allowed it.
    * `record` (§7) → `R5e.Log.commit/4` and `R5e.Commit`. `authorize` ran
      with no lock, so everything the pipeline read is captured and
      re-checked under the append lock; a mismatch appends nothing and
      retries from `resolve`, `commit_retries/0` attempts later it is
      denied `contended`, and a post-record substrate failure halts the
      node until replay. The rules are §7's; what is here is the loop.
    * `admit` — the substrate write, and §5's two effects on raw objects:
      a granted `CasObject` writes its bytes, a granted `CasExpired`
      removes them. Both are the admit step of one act, not a second one.

  ## The receipt (§9), and `derivedObjects` (§5)

  The receipt is returned to the caller and mirrored on the recorded
  payload. Beyond §9's list it carries the assurance label — `"observed"`
  for this slice: the kernel saw the request pass by, nothing stronger —
  and the Kind's epistemic scope with its defaulted flag. A denial carries
  the requested `"name"` (nil when the request had none) and no
  `"specAddress"`: nothing was stored. `"policy"` is present exactly when
  the authorize stage ran, recorded verbatim.

  One key is *lifted out* of the policy block: `derivedObjects`, copied
  onto the payload as a sibling of `"policy"` whenever the engine reported
  a non-empty list, because it is not read as policy metadata —
  `R5e.RefIndex.observe/2` reads it back, live and at every replay, which
  is what makes §5's kernel-derived class survive a restart. Denials carry
  it too. The list is copied **verbatim**: `R5e.Policy.decide/1` checked
  the form of each address and nothing more (amendment C6).

  ## The two test-only seams

  §7 is a statement about interleaving, and interleaving cannot be
  provoked from outside the gate. Two optional callbacks exist for the
  conformance vectors and nothing else, both `nil` in every shipped
  config — and `R5e.Clock`'s `config :r5e, :clock` is the third seam, for
  the same reason: §2's expiry window and §6's re-check of it under the
  lock cannot be reached from outside without a clock a vector can move.

    * `config :r5e, :before_record` — a 1-arity function called with the
      request just before each `record` attempt. The vectors admit
      something else from it, which is how "the generation moved between
      authorize and record" becomes a deterministic test rather than a
      race the suite hopes to lose. Re-entrant calls are suppressed, so
      the admission the hook performs does not fire the hook again.
    * `config :r5e, :substrate_hook` — a 1-arity function called with the
      request at the top of the `admit` step. Raising from it is how the
      post-record substrate failure is injected.
  """

  @assurance "observed"

  # §1: the payload's identity block, written by the kernel and by
  # nothing else. Closed, and listed here so a reader of this module can
  # see the whole of what a signature is turned into on the record.
  @identity_fields ~w(identity signers signed origin submittedTarget authority resolvedAuthority nonce expires)

  # §2: the two recorded denials that happen **at or before** the nonce
  # claim. `actor mismatch` is decided before the claim is attempted;
  # `nonce replayed` *is* the claim being refused, and the earlier claim
  # is the one that stands. Every other recorded outcome — including
  # `wrong origin`, `expired`, and every later stage — happened after a
  # claim that succeeded.
  #
  # This list is used twice, which is the point of it being a list: once
  # to name the denials, and once by `R5e.Bootstrap.replay/0` to decide
  # which recorded acts re-take their claim. A replay that claimed on
  # every payload would refuse, after a restart, envelopes the live node
  # had left claimable.
  @before_claim ["actor mismatch", "nonce replayed"]

  @stages ~w(authenticate validateStructure resolve authorize validateConstraints record admit)

  @doc "The seven stage names, in order. Denial reasons are prefixed with one."
  def stages, do: @stages

  @spec admit(map()) :: {:ok, map()} | {:denied, map()}
  def admit(request) do
    request = Map.put_new(request, :name, nil)

    case run(request) do
      {:ok, kind, request, policy} ->
        commit(kind, request, policy, 0)

      {:deny, stage, reason, policy, request} ->
        denied(stage, reason, policy, request)

      {:refuse, stage, reason} ->
        {:denied, refused(stage, reason)}
    end
  end

  # §2/§12: an unattributable request is not an act. A malformed envelope
  # and an invalid signature are refused *before* anyone is known to have
  # asked, so there is no actor to record the asking against, no nonce is
  # claimed, and the caller gets a receipt that says so rather than one
  # that points at an event which does not exist.
  defp refused(stage, reason) do
    %{"outcome" => "refused", "recorded" => false, "reason" => "#{stage}: #{reason}"}
  end

  defp denied(stage, reason, policy, request) do
    kind = known_kind(request)
    reason = "#{stage}: #{reason}"
    event = record(request, kind, "admission.denied", reason, policy)
    {:denied, receipt("denied", event, kind, reason, policy, request, nil)}
  end

  defp run(request) do
    # §6: forget any earlier admission's capture, so the first read of the
    # succession relation in *this* one is the one that is recorded.
    R5e.Succession.rewind()

    with {:ok, request} <- stage_authenticate(request),
         {:ok, kind, request} <- from_validate_structure(request) do
      from_resolve(kind, request)
    end
  end

  # The other retry entry point (§6). `admitBy` and `readmitBy` read the
  # succession relation to settle the instance's *name*, so an admission
  # whose first read happened here re-runs from here — with the caller's
  # own name restored, because the previous pass replaced it with the one
  # it computed.
  defp from_validate_structure(request) do
    R5e.Succession.reading("validateStructure")
    stage_validate_structure(request)
  end

  # The retry entry point (§7): identity and shape are settled from the
  # request alone, so a contended admission re-runs from here and not
  # from the top.
  defp from_resolve(kind, request) do
    R5e.Succession.reading("resolve")

    with {:ok, request} <- stage_resolve(request, kind),
         {:ok, policy} <- stage_authorize(request),
         :ok <- stage_validate_constraints(request, kind, policy) do
      {:ok, kind, request, policy}
    end
  end

  # -- commit (§7) -------------------------------------------------------

  defp commit(kind, request, policy, attempt) do
    capture = R5e.Commit.capture(request, policy)
    before_record(request)

    case record_grant(request, kind, policy, capture) do
      {:ok, event, spec_address} ->
        request = assign_server_name(request, event)
        {:ok, receipt("admitted", event, kind, nil, policy, request, spec_address)}

      {:retry, moved} ->
        retry(kind, request, policy, attempt, moved, R5e.Commit.retry_from(capture))

      # §6's terminal refusals, decided under the append lock: recorded,
      # and never retried, because retrying cannot make them false.
      {:refused, reason} ->
        denied("record", reason, policy, request)

      {:halted, reason} ->
        denied("record", reason, policy, request)

      {:persistence_failed, _reason, error, stacktrace} ->
        # No durable acknowledgement means no receipt. The complete event
        # may or may not be visible after restart when a sync itself failed;
        # startup validates what remains and never truncates it.
        reraise error, stacktrace

      {:failed, _event, _reason, error, stacktrace} ->
        # The act is on the chain and the substrate write is not. The
        # caller is owed the failure: a denial receipt here would
        # contradict the record, which says the admission was granted.
        reraise error, stacktrace
    end
  end

  defp retry(kind, request, policy, attempt, moved, from) do
    if attempt + 1 <= commit_retries() do
      # §6: the capture is rewound first, so the retry's own first read of
      # the relation is what the next commit is checked against.
      R5e.Succession.rewind()

      case rerun(from, kind, request) do
        {:ok, kind, request, policy} -> commit(kind, request, policy, attempt + 1)
        {:deny, stage, reason, policy, request} -> denied(stage, reason, policy, request)
        {:refuse, stage, reason} -> {:refuse, stage, reason}
      end
    else
      denied("record", "contended: " <> moved, policy, request)
    end
  end

  defp rerun("validateStructure", _kind, request) do
    case from_validate_structure(unnamed(request)) do
      {:ok, kind, request} -> from_resolve(kind, request)
      other -> other
    end
  end

  defp rerun(_stage, kind, request), do: from_resolve(kind, request)

  # Naming replaces `:name` with the name it settled on, and `check_target`
  # compares that field against the signed target. Re-running the stage
  # therefore needs the caller's own name back, and the signed target is
  # where it is recorded — the one copy the caller put a signature on.
  defp unnamed(request), do: Map.put(request, :name, request[:submitted_target]["name"])

  @doc "How many times a contended admission re-runs from `resolve` (§7)."
  @spec commit_retries() :: non_neg_integer()
  def commit_retries, do: Application.get_env(:r5e, :commit_retries, 3)

  # -- authenticate (§2) -------------------------------------------------
  # Two refusals, then four recorded denials, in exactly this order.
  #
  # The first two — a malformed envelope and a signature that does not
  # verify — are **not acts**: nobody is known to have asked, so nothing
  # is recorded and no nonce is claimed. That is §12's amended sentence,
  # and it is why a caller whose signature was mangled in transit may
  # re-sign the same request with the same nonce.
  #
  # Everything after them is a recorded denial. The signer is known;
  # spec/02's "requests are acts" holds, and over-asking leaves a trail.
  defp stage_authenticate(request) do
    case R5e.Request.decode(request[:envelope]) do
      {:error, reason} ->
        {:refuse, "authenticate", "malformed envelope: " <> reason}

      {:ok, decoded} ->
        case R5e.Request.verify(decoded) do
          {:error, reason} -> {:refuse, "authenticate", "signature invalid: " <> reason}
          :ok -> authenticated(request, decoded)
        end
    end
  end

  defp authenticated(request, decoded) do
    %{request: object, signers: signers, public_keys: keys, envelope: envelope} = decoded
    signer_one = hd(signers)
    %{algorithm: algorithm, base64: public_key} = Map.fetch!(keys, signer_one)

    request =
      Map.merge(request, %{
        actor: %{"id" => signer_one, "algorithm" => algorithm, "publicKey" => public_key},
        signers: signers,
        signed: envelope,
        identity: "signed",
        origin: object["origin"],
        submitted_target: object["target"],
        authority: object["authority"],
        nonce: object["nonce"],
        expires: object["expires"],
        spec_address: object["specAddress"],
        derived_from: object["derivedFrom"]
      })

    with :ok <- check_actor(object, signer_one),
         :ok <- claim_nonce(signer_one, object),
         :ok <- check_origin(object),
         :ok <- check_expires(object["expires"]) do
      {:ok, request}
    else
      {:deny, reason} -> {:deny, "authenticate", reason, nil, request}
    end
  end

  # The actor is a claim the request makes about itself; signer 1 is what
  # the envelope proves. They must agree, and the disagreement is checked
  # before the nonce is claimed — a request that names somebody else has
  # not spent that somebody's nonce.
  defp check_actor(%{"actor" => actor}, signer_one) when actor == signer_one, do: :ok

  defp check_actor(%{"actor" => actor}, signer_one),
    do:
      {:deny,
       "actor mismatch: the request names #{inspect(actor)}, signer 1 is #{inspect(signer_one)}"}

  # §2: claimed atomically, and the claim stands through every later
  # outcome — denials included. A refused request has still spent its
  # nonce; resubmitting the same envelope is a replay.
  defp claim_nonce(signer_one, %{"nonce" => nonce, "expires" => expires}) do
    case R5e.NonceIndex.claim(signer_one, nonce, expires) do
      :ok ->
        :ok

      {:error, :replayed} ->
        {:deny,
         "nonce replayed: this chain has already recorded #{inspect(nonce)} from this signer; " <>
           "the earlier claim stands"}
    end
  end

  # The origin is inside the signature, so an envelope admitted on one
  # chain cannot be replayed onto another: the request is addressed.
  defp check_origin(%{"origin" => origin}) do
    ours = R5e.Origin.current()

    if origin == ours,
      do: :ok,
      else: {:deny, "wrong origin: this chain is #{ours}, the request names #{origin}"}
  end

  # §2's window: 300 s of tolerated skew behind, 24 h of reach ahead.
  defp check_expires(expires) do
    {:ok, at} = RecurseVerify.Instant.parse(expires)
    now = R5e.Clock.now()

    cond do
      DateTime.compare(at, DateTime.add(now, -expiry_skew(), :second)) != :gt ->
        {:deny, "expired: #{expires} is more than #{expiry_skew()} s behind this node's clock"}

      DateTime.compare(at, DateTime.add(now, expiry_reach(), :second)) == :gt ->
        {:deny, "expires too far: #{expires} is more than #{expiry_reach()} s ahead"}

      true ->
        :ok
    end
  end

  @doc "The skew `authenticate` tolerates behind the clock — 300 s (§2)."
  def expiry_skew, do: 300

  @doc "How far ahead an `expires` may reach — 24 h (§2)."
  def expiry_reach, do: 24 * 60 * 60

  # -- validateStructure -------------------------------------------------
  # Everything that can be decided from the request alone: which Kind, the
  # shape of the spec, the envelope, and the name the instance will carry.
  defp stage_validate_structure(request) do
    with {:ok, kind} <- lookup_kind(request),
         :ok <- check_signature_count(request, kind),
         :ok <- check_spec_address(request, kind),
         :ok <- check_target(request),
         :ok <- schema(R5e.Kind.validate_structure(kind, request.spec)),
         :ok <- check_kind_definition(request),
         {:ok, request} <- apply_naming(request, kind),
         :ok <- check_requires_authority(request, kind) do
      {:ok, kind, request}
    else
      {:deny, reason} -> {:deny, "validateStructure", reason, nil, request}
    end
  end

  defp lookup_kind(%{group: g, version: v, kind: k}) do
    case R5e.KindRegistry.get(g, v, k) do
      {:ok, kind} ->
        {:ok, kind}

      {:error, :unknown_kind} ->
        {:deny, "unknown Kind #{g}/#{v}/#{k} — Kinds enter through admission first"}
    end
  end

  # §1/§2: how many signatures this Kind takes is a property of the Kind,
  # not of the envelope — one signature is the default, two is a
  # countersigned act (a Badge the subject accepts, a Succession the
  # successor proves possession for).
  defp check_signature_count(request, kind) do
    expected = kind.signatures
    got = length(request[:signers])

    if got == expected do
      :ok
    else
      {:deny,
       "signature count: #{R5e.Kind.name(kind)} is admitted on #{expected} signature(s), " <>
         "this envelope carries #{got}"}
    end
  end

  # §1 (r4.1): **keyids need not be distinct.** The only two-signature
  # Kinds are Badge, where issuer = subject is a self-issued Badge and a
  # real act, and Succession, where one key is refused later and by name
  # at `resolve: self succession`. On a one-signature Kind the same key
  # twice is still two signatures and fails the count above, so a
  # distinctness check had no reachable input and is gone.

  # The signature covers the *address* of the spec, not the spec: the
  # bytes travel beside the envelope and this is what binds them to it.
  #
  # A spec §8 cannot encode has no address at all, so there is nothing to
  # compare. The base checks are what *name* the offending value, and a
  # denial that says "/list/1/y: floats are not admissible" is worth more
  # than one that says two hashes differ — so they are run here, early,
  # for that case alone.
  defp check_spec_address(request, kind) do
    case safe_spec_address(request.spec) do
      {:ok, actual} when actual == :erlang.map_get(:spec_address, request) ->
        :ok

      {:ok, actual} ->
        {:deny,
         "spec address mismatch: the signed request names #{request[:spec_address]}, " <>
           "the submitted spec hashes to #{actual}"}

      :error ->
        case schema(R5e.Kind.validate_structure(kind, request.spec)) do
          {:deny, reason} -> {:deny, reason}
          :ok -> {:deny, "spec address mismatch: the submitted spec has no canonical encoding"}
        end
    end
  end

  defp safe_spec_address(spec) do
    {:ok, R5e.CAS.spec_address(spec)}
  rescue
    ArgumentError -> :error
  end

  # The route and the body `name` are how a caller addresses a request;
  # the signed target is what was asked. They must be the same thing.
  defp check_target(request) do
    signed = request[:submitted_target]

    addressed = %{
      "group" => request.group,
      "version" => request.version,
      "kind" => request.kind,
      "name" => request[:name]
    }

    if signed == addressed do
      :ok
    else
      {:deny,
       "target mismatch: the signed target is #{inspect(signed)}, " <>
         "the request was addressed to #{inspect(addressed)}"}
    end
  end

  # Both halves of instance validation report the same way; only the stage
  # that names the denial differs.
  defp schema(:ok), do: :ok
  defp schema({:error, errors}), do: {:deny, "schema: " <> Enum.join(errors, "; ")}

  # §1's `derivedFrom` — the address of the natural-language document the
  # definition was derived from — is now a *signed* field, and its form is
  # settled by `R5e.Request` at `authenticate`: a malformed one never
  # reaches this stage. Whether it is **backed** is `resolve`'s question,
  # one stage later, and that check is still here.

  # A KindDefinition instance must itself be a well-formed definition
  # (§1 meta-checks) before it is recorded: nothing a KindDefinition
  # declares may be accepted-but-ignored.
  defp check_kind_definition(%{kind: "KindDefinition", spec: spec}) do
    with :ok <- R5e.Kind.check_definition(spec),
         {:ok, _parsed} <- R5e.Kind.from_map(spec) do
      :ok
    else
      {:error, reason} -> {:deny, reason}
    end
  end

  defp check_kind_definition(_request), do: :ok

  # §4/KS-4: `requiresAuthority: true` says every admission of this Kind
  # carries non-empty `authority`, and that is all this check asks —
  # deliberately, because it is a *structural* fact about the request and
  # `validateStructure` is where structural facts are settled. Whether the
  # cited events are effective authority covering this Kind is §5's
  # question, asked one stage later at `resolve` by
  # `R5e.Authority.resolve/2` (`authority subject`, `authority
  # ineffective`, `kind outside authority`). Both run; this one names the
  # request that cited nothing at all, which `resolve` would otherwise
  # pass silently.
  defp check_requires_authority(_request, %R5e.Kind{requires_authority: false}), do: :ok

  defp check_requires_authority(%{authority: [_ | _]}, _kind), do: :ok

  defp check_requires_authority(_request, kind) do
    {:deny,
     "authority required: #{R5e.Kind.name(kind)} is admitted only under cited authority, " <>
       "and this request cites none"}
  end

  # -- naming (§2) -------------------------------------------------------
  # Six modes. The name is settled here, before policy sees the request —
  # except for `server` creates, whose name is the admission event's own
  # hash and so cannot exist until `record`.
  defp apply_naming(request, kind) do
    mode = R5e.Kind.naming_mode(kind)

    with {:ok, name} <- rendered_name(mode, request, kind),
         :ok <- check_name(name),
         {:ok, action, previous} <- readmit(mode, request, kind, name),
         :ok <- check_admit_by(action, request, kind) do
      {:ok,
       request
       |> Map.put(:name, name)
       |> Map.put(:naming_action, action)
       |> Map.put(:previous, previous)
       |> Map.put(:server_named, mode == "server" and is_nil(name))}
    end
  end

  defp rendered_name("content", %{name: nil, spec: spec}, _kind),
    do: {:ok, R5e.Canonical.hash(spec)}

  defp rendered_name("content", _request, _kind),
    do:
      {:deny,
       "naming mode \"content\" names an instance by its content; a caller-supplied name is not admissible"}

  defp rendered_name("path", request, _kind) do
    spec = request.spec

    with {:ok, path} <- spec_path(spec) do
      match_caller(request[:name], path, "path")
    end
  end

  defp rendered_name("literal", request, kind),
    do: match_caller(request[:name], kind.naming["value"], "literal")

  defp rendered_name("derived", request, kind) do
    case R5e.Kind.render_derived(kind.naming["derive"], request.spec) do
      {:ok, rendered} -> match_caller(request[:name], rendered, "derived")
      {:error, reason} -> {:deny, "naming mode \"derived\": #{reason}"}
    end
  end

  # Absent: a create, named after the admission event once it exists.
  # Present: a replace of an existing server-named instance (checked in
  # `readmit/4`) — the kernel never lets a caller mint a new server name.
  defp rendered_name("server", %{name: nil}, _kind), do: {:ok, nil}
  defp rendered_name("server", request, _kind), do: {:ok, request[:name]}

  defp rendered_name("caller", %{name: nil, spec: spec}, _kind),
    do: {:ok, R5e.Canonical.hash(spec)}

  defp rendered_name("caller", request, _kind), do: {:ok, request[:name]}

  defp spec_path(%{"group" => g, "version" => v, "kind" => k})
       when is_binary(g) and is_binary(v) and is_binary(k),
       do: {:ok, "#{g}/#{v}/#{k}"}

  defp spec_path(_spec),
    do: {:deny, "naming mode \"path\" needs string group, version and kind on the spec"}

  defp match_caller(nil, computed, _mode), do: {:ok, computed}
  defp match_caller(computed, computed, _mode), do: {:ok, computed}

  defp match_caller(given, computed, mode),
    do:
      {:deny,
       "naming mode #{inspect(mode)} names this instance #{inspect(computed)}; the request said #{inspect(given)}"}

  defp check_name(nil), do: :ok

  defp check_name(name) do
    if R5e.Kind.valid_name?(name),
      do: :ok,
      else:
        {:deny,
         "#{inspect(name)} is not a legal name: [A-Za-z0-9._:@*-]+(/[A-Za-z0-9._:@*-]+)*, at most 255 bytes"}
  end

  # §4/KS-4: `admitBy: "nodeKey"` gates **creation** only. A Kind the
  # deployment itself declares — its own Deployment record — is not
  # something a caller may mint; what happens to an existing one is
  # `readmitBy`'s question and is asked separately.
  defp check_admit_by(:create, request, kind) do
    if R5e.Kind.Naming.node_key_only?(kind.naming) and
         request[:actor]["id"] != R5e.DSSE.node_key_id() do
      {:deny,
       "admitBy: #{R5e.Kind.name(kind)} is created by the node key alone; " <>
         "this request is signed by #{request[:actor]["id"]}"}
    else
      :ok
    end
  end

  defp check_admit_by(_action, _request, _kind), do: :ok

  # The readmit column of §2. Events have no store entry to change, so a
  # re-admission of one is simply another event.
  defp readmit(_mode, _request, %R5e.Kind{substrate: "event"}, _name), do: {:ok, :create, nil}
  defp readmit("server", _request, _kind, nil), do: {:ok, :create, nil}

  defp readmit(mode, request, kind, name) do
    case R5e.ResourceStore.get(request.group, request.version, request.kind, name) do
      {:error, :not_found} when mode == "server" ->
        {:deny,
         "naming mode \"server\" assigns names; #{inspect(name)} is not an admitted instance to replace"}

      {:error, :not_found} ->
        {:ok, :create, nil}

      {:ok, entry, _lineage} ->
        readmit_existing(mode, request, kind, entry)
    end
  end

  # §4/KS-4: a declared `readmitBy` **overrides the mode's readmit
  # column**. It is illegal on `content` and `path` (checked at
  # definition), so what it can override is `server`'s actor-of-record
  # test and the free supersession `literal`, `derived` and `caller`
  # otherwise allow.
  defp readmit_existing(mode, request, kind, entry) do
    case R5e.Kind.Naming.readmit_by(kind.naming) do
      nil -> readmit_by_mode(mode, request, kind, entry)
      rule -> readmit_by_rule(rule, mode, request, entry)
    end
  end

  defp readmit_by_rule("none", _mode, _request, entry) do
    {:deny, "readmitBy: none: #{inspect(entry["name"])} is admitted once and never superseded"}
  end

  defp readmit_by_rule("nodeKey", mode, request, entry) do
    if request[:actor]["id"] == R5e.DSSE.node_key_id(),
      do: readmit_action(mode, entry),
      else: {:deny, "readmitBy: nodeKey: #{inspect(request[:actor]["id"])} is not the node key"}
  end

  defp readmit_by_rule("actorOfRecord", mode, request, entry) do
    if entry["actor"] == request[:actor]["id"],
      do: readmit_action(mode, entry),
      else:
        {:deny,
         "readmitBy: actorOfRecord: #{inspect(request[:actor]["id"])} is not the actor of " <>
           "record (#{inspect(entry["actor"])}) on #{inspect(entry["name"])}"}
  end

  # §0/§4: the actor of record, **or a key that actor succeeded to**. This
  # is `matches/3`, the same predicate authority and `sameActor` use: a
  # profile follows its subject across a key change, and it follows in one
  # direction only — forward, to whoever the recorded key named.
  defp readmit_by_rule("actorOfRecordOrSuccessor", mode, request, entry) do
    submitter = request[:actor]["id"]

    if R5e.Succession.matches(entry["actor"], submitter, R5e.Succession.next_seq()) do
      readmit_action(mode, entry)
    else
      {:deny,
       "readmitBy: actorOfRecordOrSuccessor: #{inspect(submitter)} is neither the actor of " <>
         "record (#{inspect(entry["actor"])}) on #{inspect(entry["name"])} nor a key it " <>
         "was succeeded by"}
    end
  end

  defp readmit_action("server", entry), do: {:ok, :replace, entry}
  defp readmit_action(_mode, entry), do: {:ok, :supersede, entry}

  # `content`: a byte-identical spec is the only spec that can share the
  # name, so re-admission is idempotent — a new event, the entry unchanged.
  defp readmit_by_mode("content", _request, _kind, entry), do: {:ok, :idempotent, entry}

  # `path`: deny unless byte-identical (§1's duplicate rule). The §11
  # meta-Kind transition is the one exempt-by-design act, and it is recorded
  # as such on the payload and the receipt.
  defp readmit_by_mode("path", request, _kind, entry) do
    cond do
      identical?(entry, request.spec) -> {:ok, :idempotent, entry}
      transition?(request, entry) -> {:ok, :supersede, entry}
      true -> {:deny, duplicate_reason(request)}
    end
  end

  # `server`: replace, by the actor of record only.
  defp readmit_by_mode("server", request, _kind, entry) do
    if entry["actor"] == request.actor["id"] do
      {:ok, :replace, entry}
    else
      {:deny,
       "naming mode \"server\": #{inspect(request.actor["id"])} is not the actor of record " <>
         "(#{inspect(entry["actor"])}) on #{inspect(entry["name"])}"}
    end
  end

  # `literal`, `derived`, `caller`: supersede — any authenticated actor,
  # subject to policy.
  defp readmit_by_mode(_mode, _request, _kind, entry), do: {:ok, :supersede, entry}

  defp identical?(entry, spec),
    do: R5e.Canonical.encode(entry["spec"]) == R5e.Canonical.encode(spec)

  defp duplicate_reason(%{kind: "KindDefinition", spec: spec}) do
    "a KindDefinition for #{spec["group"]}/#{spec["version"]}/#{spec["kind"]} is already admitted; " <>
      "a second definition with the same identity is denied unless byte-identical"
  end

  defp duplicate_reason(_request),
    do: "naming mode \"path\": this name is already admitted with a different spec"

  # §10/§11: the **same-identity transition**, and nothing else, may
  # supersede under `path`. Two actors may perform one:
  #
  #   * the node key — which is how the kernel's own seeds move, and how a
  #     **legacy** chain's v3 transition works, where the actor of record
  #     is the pre-011 `system:bootstrap` string and not a key at all;
  #   * the **actor of record on the existing definition** — contract r4.5
  #     extends the rule to a co-located extension's seeds, and this is the
  #     narrowest reading of "same identity" that reaches them: whoever put
  #     this definition on the chain may replace it with a changed one
  #     under the same identity, and nobody else may.
  #
  # The second clause is deliberately *not* "any actor citing authority
  # over KindDefinition". Root issuance is ungated (§5), so that reading
  # would let a stranger self-endorse and then supersede the meta-Kind —
  # which is exactly the silent redefinition `path` naming's duplicate
  # rule exists to prevent.
  #
  # `transition` is a transport field, not a signed one, so it cannot be
  # the gate; it is the *declaration* that this act is a transition, and
  # it is recorded on the payload so the act is legible. The gate is the
  # actor.
  defp transition?(request, entry) do
    is_binary(request[:transition]) and
      request[:actor]["id"] in [R5e.DSSE.node_key_id(), entry["actor"]]
  end

  # -- resolve (§4) ------------------------------------------------------
  # Pure lookups, no writes; `R5e.Resolve` holds the per-class rules. The
  # manifest rides on the request from here on.
  defp stage_resolve(request, kind) do
    with {:ok, manifest} <- R5e.Resolve.run(kind, request.spec, request),
         :ok <- R5e.Resolve.derived_from(request[:derived_from]),
         :ok <- R5e.Succession.check_admission(request, kind),
         {:ok, authority, visited} <- R5e.Authority.resolve(request, kind),
         {:ok, depth} <- R5e.Authority.issuance(request, kind) do
      {:ok,
       request
       |> Map.put(:resolved, manifest)
       |> Map.put(:resolved_authority, authority)
       |> Map.put(:authority_visited, visited)
       |> Map.put(:depth, depth)
       |> with_policy_view(authority)}
    else
      {:error, reason} -> {:deny, "resolve", reason, nil, request}
    end
  end

  # KS-7, the kernel half: what a policy engine is handed about the actor,
  # settled before `authorize` runs. `authorityRefs` is always present —
  # `[]` says "acted as itself", which is a fact a rule may want, and an
  # absent key would make that indistinguishable from an engine that
  # forgot to look.
  defp with_policy_view(request, authority) do
    request
    |> Map.put(:authority_refs, authority |> Enum.map(& &1["value"]) |> Enum.sort())
    |> Map.put(
      :authority_roots,
      authority |> Enum.map(&root_of/1) |> Enum.reject(&is_nil/1) |> Enum.uniq() |> Enum.sort()
    )
  end

  defp root_of(%{"chain" => chain}) when chain != [], do: List.last(chain)["actor"]
  defp root_of(_entry), do: nil

  # -- authorize ---------------------------------------------------------
  # The policy's metadata rides along from here: a later stage may refuse a
  # request the policy allowed, and that receipt should still say who allowed it.
  defp stage_authorize(request) do
    case R5e.Policy.decide(request) do
      {:ok, meta} -> {:ok, meta}
      {:deny, reason, meta} -> {:deny, "authorize", reason, meta, request}
    end
  end

  # -- validateConstraints -----------------------------------------------
  defp stage_validate_constraints(request, kind, policy) do
    with :ok <-
           schema(
             R5e.Kind.validate_constraints(kind, request.spec, %{
               signers: request[:signers],
               authority: request[:authority]
             })
           ),
         :ok <- check_partition(request),
         :ok <- check_expiry(request) do
      :ok
    else
      {:deny, reason} -> {:deny, "validateConstraints", reason, policy, request}
    end
  end

  # §5's two constraint checks on raw objects. Both are asked of the
  # `address` a core `CasObject`/`CasExpired` spec carries, and both are
  # one `R5e.RefIndex` lookup — which `record` has already updated for
  # this very event by the time `admit` runs.
  defp cas_address(%{group: "core.r5e.io", version: "v1", kind: kind, spec: spec}, kind) do
    if is_map(spec) and is_binary(spec["address"]), do: spec["address"], else: nil
  end

  defp cas_address(_request, _kind), do: nil

  # Amendment C4: §4's partition was enforced only where a ref cited an
  # address, which left the other end open — admit one side onto the other,
  # then cite it. The address is the hash of the body, so reaching this
  # denial means somebody submitted bytes byte-identical to a canonical
  # payload or an admitted spec. That is not a collision; it is an attempt
  # to pass one act off as another, and the reason says which side.
  defp check_partition(request) do
    with address when is_binary(address) <- cas_address(request, "CasObject"),
         {:error, side} <- R5e.RefIndex.partition(address) do
      {:deny,
       "the address #{address} is already #{partition_side(side)} on this chain; raw bytes " <>
         "and kernel-written objects are told apart by the act that admitted them, and one " <>
         "address cannot be both (§5)"}
    else
      _ -> :ok
    end
  end

  defp partition_side(:payload), do: "an event payload address"
  defp partition_side(:spec), do: "an admitted specAddress"

  # A `CasExpired` claims the object was cited by nothing at the recorded
  # position — that is its whole epistemic scope — so admitting one for an
  # object something still cites would record a claim the chain itself
  # contradicts. The denial names the citing seq, because "still
  # referenced" is not actionable and "referenced by seq 41 at
  # /sourceRef" is. A `public-record` citation is the stronger refusal and
  # is reported as such.
  defp check_expiry(request) do
    address = cas_address(request, "CasExpired")

    cond do
      address == nil ->
        :ok

      (public = R5e.RefIndex.public_record_citations(address)) != [] ->
        {:deny,
         "the object at #{address} is cited with retention \"public-record\" by " <>
           cited_by(public) <> "; a public-record object is never expired (§5)"}

      (cites = R5e.RefIndex.citations(address)) != [] ->
        {:deny,
         "the object at #{address} is still cited by " <>
           cited_by(cites) <>
           "; a CasExpired claims the object was cited by nothing at the recorded position (§5)"}

      true ->
        :ok
    end
  end

  defp cited_by(citations) do
    citations
    |> Enum.map(fn c ->
      "seq #{c["seq"]} (#{c["kind"]}#{if c["path"], do: " at #{c["path"]}", else: ""})"
    end)
    |> Enum.join(", ")
  end

  # -- record ------------------------------------------------------------
  # The event is appended BEFORE any substrate write: if the process dies
  # between record and admit, the log shows a granted admission with no
  # substrate entry — a legible gap — never a substrate entry with no record.
  defp record(request, kind, event_kind, reason, policy) do
    payload = payload(request, kind, event_kind, reason, policy)
    event = R5e.Log.append(event_kind, payload)

    # The reference index (§5) is a view of the chain, so it is fed from
    # the chain: the same `{event, payload}` pair replay hands it, at the
    # same point in the act. Denials feed it too — their payload address
    # is bytes the kernel wrote, and their resolution manifest is part of
    # the record of the asking.
    R5e.RefIndex.observe(event, payload)
    R5e.Authority.observe(event, payload)
    event
  end

  # A grant's record and its substrate write are one call on the append
  # lock (§7): `R5e.Log.commit/4` re-checks the capture, appends, and runs
  # the `admit` step, in that order, with nothing else able to append in
  # between. See `R5e.Log` for why the substrate write moved inside.
  defp record_grant(request, kind, policy, capture) do
    payload = payload(request, kind, "admission.granted", nil, policy)

    R5e.Log.commit("admission.granted", payload, capture, fn event ->
      R5e.RefIndex.observe(event, payload)
      R5e.Authority.observe(event, payload)
      do_admit(assign_server_name(request, event), kind, event)
    end)
  end

  defp payload(request, kind, event_kind, reason, policy) do
    %{
      "actor" => request[:actor] || %{},
      "target" => target(request),
      "outcome" => if(event_kind == "admission.granted", do: "admitted", else: "denied"),
      "assurance" => @assurance,
      "spec" => recordable_spec(request[:spec], event_kind),
      "resolvedRefs" => request[:resolved] || [],
      "scopeDefaulted" => kind && kind.scope_defaulted
    }
    |> put_if(reason != nil, "reason", reason)
    |> with_identity(request)
    |> with_depth(request)
    |> with_envelope(request, policy)
  end

  # §1: `depth` is kernel-derived and recorded on every Endorsement and
  # Badge — 0 for a root, the parent's depth + 1 otherwise. It is on the
  # record rather than computed by readers because §5 caps a chain at 16
  # and a cap nobody can check from the payload is not a cap.
  #
  # Both arms are recorded. `resolve` derives the parented one — the
  # parent's depth is a fact about an admitted event and §5's issuance
  # check is what looks it up — and hands it back on the request, so the
  # value written here is the one the cap was enforced against rather
  # than a second derivation that could disagree with it.
  defp with_depth(map, request) do
    case authority_depth(request) do
      nil -> map
      depth -> Map.put(map, "depth", depth)
    end
  end

  # Which Kinds are authority is §5's, and it is asked of the one module
  # that answers it for the kernel and the verifier alike.
  defp authority_depth(%{group: g, version: v, kind: k} = request) do
    if RecurseVerify.Authority.authority_kind?("#{g}/#{v}/#{k}"),
      do: recorded_depth(request),
      else: nil
  end

  defp authority_depth(_request), do: nil

  defp recorded_depth(request) do
    case request[:depth] do
      depth when is_integer(depth) -> depth
      # A denial refused before `resolve` never derived one. A root is
      # still 0 there, because that much is readable from the spec alone.
      _ -> if R5e.Kind.exists?(request[:spec] || %{}, "parent"), do: nil, else: 0
    end
  end

  # §1's identity block: written when the request carried an envelope,
  # absent otherwise. Events admitted before this contract carry no
  # `identity` field at all, and the verifier renders them `unsigned` —
  # so the *absence* of the key is the legacy marker, and a defaulted
  # `"unsigned"` would erase the difference between a chain that predates
  # signatures and one that stopped using them.
  defp with_identity(map, %{identity: identity} = request) when is_binary(identity) do
    map
    |> Map.put("identity", identity)
    |> Map.put("signers", request[:signers])
    |> Map.put("signed", request[:signed])
    |> Map.put("origin", request[:origin])
    |> Map.put("submittedTarget", request[:submitted_target])
    |> Map.put("authority", request[:authority])
    |> Map.put("nonce", request[:nonce])
    |> Map.put("expires", request[:expires])
    |> Map.put("resolvedAuthority", request[:resolved_authority] || [])
    |> put_if(request[:random] != nil, "random", request[:random])
  end

  defp with_identity(map, _request), do: map

  @doc "The identity keys `record` writes on a signed payload (§1)."
  def identity_fields, do: @identity_fields

  @doc """
  Did this recorded act take the `(signer 1, nonce)` claim (§2)?

  Read off the recorded reason, because the claim is not a payload field:
  every recorded outcome claimed, except the two denials that happen at or
  before the claim point. `R5e.Bootstrap.replay/0` asks this of every
  payload so the rebuilt index is the one the live node held.
  """
  @spec nonce_claimed?(map()) :: boolean()
  def nonce_claimed?(payload) do
    case payload["reason"] do
      "authenticate: " <> rest -> not Enum.any?(@before_claim, &String.starts_with?(rest, &1))
      _ -> true
    end
  end

  # The keys the payload and the receipt carry identically, so a reader of
  # one is reading the other: the policy block, §5's `derivedObjects`
  # lifted out of it, and §1's two envelope fields.
  defp with_envelope(map, request, policy) do
    map
    |> put_if(policy != nil, "policy", policy)
    |> put_derived_objects(policy)
    |> put_if(request[:derived_from] != nil, "derivedFrom", request[:derived_from])
    |> put_if(request[:transition] != nil, "transition", request[:transition])
  end

  # §8 and spec/05 §3 collide on exactly one input: a spec carrying a
  # float is denied at `validateStructure` **and** its denial is recorded,
  # but a float has no canonical encoding, so the payload that would carry
  # it cannot be written. The denial is the part that matters — the record
  # of an asking, and the reason names the offending value and its path —
  # so the spec is recorded as `null` and the reason carries what was
  # wrong with it. A grant never reaches this: a spec that passed
  # `validateStructure` encodes.
  defp recordable_spec(spec, "admission.granted"), do: spec

  defp recordable_spec(spec, _denied) do
    _ = R5e.Canonical.encode(spec)
    spec
  rescue
    ArgumentError -> nil
  end

  # §5/§9: the engine's account of what it wrote. Absent when the engine
  # wrote nothing, which is §9's wording — "when the engine registered
  # any" — and keeps the key from meaning both "none" and "the policy
  # predates the contract".
  defp put_derived_objects(map, policy) when is_map(policy) do
    case policy["derivedObjects"] do
      [_ | _] = list -> Map.put(map, "derivedObjects", list)
      _ -> map
    end
  end

  defp put_derived_objects(map, _policy), do: map

  # §2, `server`: the payload's `target.name` is omitted at record, because
  # the name *is* this event's hash and cannot be inside its own payload.
  # Replay derives it the same way, from the event — never from the payload.
  defp target(%{server_named: true} = request) do
    %{"group" => request[:group], "version" => request[:version], "kind" => request[:kind]}
  end

  defp target(request) do
    %{
      "group" => request[:group],
      "version" => request[:version],
      "kind" => request[:kind],
      "name" => request[:name]
    }
  end

  defp assign_server_name(%{server_named: true} = request, event),
    do: Map.put(request, :name, event_ref(event))

  defp assign_server_name(request, _event), do: request

  # -- admit (substrate write) -------------------------------------------
  # Returns the spec's CAS address: computed once here, stored on the
  # entry and handed back to the caller on the receipt.
  defp do_admit(request, %R5e.Kind{substrate: substrate}, event) do
    substrate_hook(request)
    spec_addr = R5e.CAS.put_spec(request.spec)

    entry =
      R5e.ResourceStore.entry(%{
        group: request.group,
        version: request.version,
        kind: request.kind,
        name: request.name,
        substrate: substrate,
        spec: request.spec,
        actor: request.actor["id"],
        event: event,
        resolved: request[:resolved],
        derived_from: request[:derived_from]
      })

    # Event-substrate instances live on the log alone; resource and
    # artifact instances are additionally indexed for retrieval. The
    # stored spec is the refs form exactly as admitted — refs-first.
    if substrate != "event" do
      store(request, entry)
    end

    # Self-hosting: an admitted KindDefinition extends the vocabulary.
    if request.kind == "KindDefinition" do
      {:ok, parsed} = R5e.Kind.from_map(request.spec)
      R5e.KindRegistry.force_put(%{parsed | derived_from: request[:derived_from]})
    end

    cas_effect(request)
    spec_addr
  end

  # §5's two substrate effects on raw objects, both of them here in
  # `admit` and reachable only from a grant. The bytes of a `CasObject`
  # are written after its event is on the chain; the object a `CasExpired`
  # names is removed after its event is on the chain. Neither is a
  # separate act: they are the admit step of one.
  defp cas_effect(%{kind: "CasObject", group: "core.r5e.io", cas_bytes: bytes})
       when is_binary(bytes) do
    R5e.CAS.put(bytes)
  end

  defp cas_effect(%{kind: "CasExpired", group: "core.r5e.io", spec: %{"address" => address}})
       when is_binary(address) do
    R5e.CAS.delete(address)
  end

  defp cas_effect(_request), do: :ok

  defp store(request, entry) do
    case request[:naming_action] do
      # The store entry is unchanged: the re-admission is a new event and
      # nothing else. The entry keeps the admissionEvent it was created by.
      :idempotent ->
        :ok

      action when action in [:supersede, :replace] ->
        R5e.ResourceStore.supersede(
          request.group,
          request.version,
          request.kind,
          request.name,
          entry
        )

      _create ->
        R5e.ResourceStore.put(request.group, request.version, request.kind, request.name, entry)
    end
  end

  defp receipt(outcome, event, kind, reason, policy, request, spec_address) do
    %{
      "outcome" => outcome,
      "event" => event["hash"],
      "eventRef" => event_ref(event),
      "seq" => event["seq"],
      "name" => request[:name],
      "assurance" => @assurance,
      "resolvedRefs" => request[:resolved] || [],
      "epistemicScope" => kind && kind.epistemic_scope,
      "scopeDefaulted" => kind && kind.scope_defaulted,
      "recorded" => true
    }
    |> put_if(request[:identity] != nil, "identity", request[:identity])
    |> put_if(request[:signers] != nil, "signers", request[:signers])
    |> put_if(authority_depth(request) != nil, "depth", authority_depth(request))
    |> put_if(request[:identity] != nil, "resolvedAuthority", request[:resolved_authority] || [])
    |> put_if(spec_address != nil, "specAddress", spec_address)
    |> put_if(reason != nil, "reason", reason)
    |> with_envelope(request, policy)
  end

  @doc "The `event:sha256:<hex>` form of an event (§6)."
  @spec event_ref(map()) :: String.t()
  def event_ref(%{"hash" => hash}), do: "event:" <> hash

  @doc """
  The API path a recorded payload's `target` names — what §4's `event` ref
  class compares its declared `g/v/K` against, what §7's anchor head is
  computed over, and what a halt reason says failed.
  """
  @spec target_path(map()) :: String.t()
  def target_path(payload) do
    target = payload["target"] || %{}
    "#{target["group"]}/#{target["version"]}/#{target["kind"]}"
  end

  # The Kind a denial reports its scope from, when there is one: a denial
  # may name a Kind that was never admitted, and says so with `nil`.
  defp known_kind(%{group: _, version: _, kind: _} = request) do
    case lookup_kind(request) do
      {:ok, kind} -> kind
      {:deny, _reason} -> nil
    end
  end

  defp known_kind(_request), do: nil

  # -- the two §7 seams --------------------------------------------------
  # Both are `nil` in every shipped config; see the moduledoc.

  defp before_record(request) do
    fun = Application.get_env(:r5e, :before_record)

    if is_function(fun, 1) and not Process.get(:r5e_before_record, false) do
      Process.put(:r5e_before_record, true)

      try do
        fun.(request)
      after
        Process.delete(:r5e_before_record)
      end
    end

    :ok
  end

  defp substrate_hook(request) do
    case Application.get_env(:r5e, :substrate_hook) do
      fun when is_function(fun, 1) -> fun.(request)
      _ -> :ok
    end
  end

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, false, _key, _value), do: map
end
