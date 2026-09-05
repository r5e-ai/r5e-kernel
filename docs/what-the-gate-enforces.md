# What the gate enforces

Reference for the admission pipeline as it stands at bookmark
`verifier-spec-07-r2` (2026-09-02). The normative texts are
`r5e-core/spec/05-kind-schema.md`, `spec/06-identity.md` and
`spec/07-verifier.md`; this page says which of their rules this kernel runs
and where each is pinned.

Every rule below is pinned by at least one of the 440 conformance vectors
under [`../test/vectors/`](../test/vectors/README.md).

## The seven stages

| Stage | Decides |
|---|---|
| `authenticate` | the envelope parses, the signature verifies, the origin is this chain's, the actor matches the signer, the nonce is unspent, the request is unexpired |
| `validateStructure` | signature count, the spec against the Kind's schema, the naming mode's shape, `specAddress` and target agreement |
| `resolve` | every typed ref looks up; authority is walked; the resolution manifest is built |
| `authorize` | the policy engine decides, holding no lock |
| `validateConstraints` | the Kind's declared constraints against what resolved |
| `record` | the capture is re-checked under the append lock; the event is appended |
| `admit` | the substrate write |

No exempt path, no exempt actor. Denials are recorded — a request is an act.
The two exceptions are refusals, not denials: a malformed envelope and a
signature that does not verify are unattributable, so nothing is written and
no nonce is spent (`"recorded": false`).

Structure is judged before policy runs and constraints after it, so a policy
engine never sees a malformed request and never has its decision pre-empted by
one.

## The signed request

Eight keys, always present, a nullable one carrying `null`:

```json
{ "origin": "sha256:<this chain's origin>", "actor": "key:ed25519:sha256:<hex>",
  "target": {"group": "…", "version": "…", "kind": "…", "name": null},
  "specAddress": "sha256:<canonical hash of the spec>",
  "derivedFrom": null, "authority": [],
  "nonce": "<base64 of 16 bytes>", "expires": "<RFC 3339 with an offset>" }
```

The signature covers the address of the spec, not the spec, so the bytes
travel beside the envelope and the address binds them to it. The origin is
inside the signature, so an envelope admitted on one chain cannot be replayed
onto another. The nonce is claimed atomically and stands through every later
outcome, denials included.

Signatures are ed25519 over a DSSE PAE of the canonical request object, under
an explicit profile: RFC 8032 with pre-checks for non-canonical and
small-order public keys and for `S >= L`.

The recorded payload carries `identity`, `signers`, `signed` (the envelope
verbatim), `origin`, `submittedTarget`, `authority`, `resolvedAuthority`,
`nonce` and `expires`.

## Schema-lite v2 (spec/05)

Enforced now:

- §0's two predicates — `exists` against `nonEmpty`; `[]`, `{}` and `""` are
  values, an explicit `null` is an absence;
- every §3 keyword, in both halves of the split validation; the recursive
  no-float rule; the §3 limits; the RE2 subset for `pattern`, so a definition
  cannot mean one thing here and another on a conformant RE2 kernel;
- §1's meta-checks on a submitted KindDefinition, so no definition can declare
  something the gate would ignore;
- all six naming modes of §2 with their re-admission rules — idempotent, deny,
  supersede, replace — the duplicate-Kind rule, and the `derivedFrom` envelope;
- §4's typed refs: a `$ref` is admissible only where the declared type is
  `ref`, its form is fixed by the declaration's class, and `resolve` looks
  every one of them up. A ref that does not resolve denies at `resolve`,
  naming the JSON pointer, the declared target and what was found. What
  resolved is the resolution manifest — sorted by pointer, one entry per ref
  value, written beside `spec` on the event payload and the store entry, handed
  to the policy engine as `resolved`, and returned on the receipt.

`?resolution=deep` hydrates each class per §6: a resource to its entry, an
event to its envelope plus decoded payload, an object to its JSON value where
the declaration says `json` and to `{size, base64}` otherwise. Hydration is a
computed view carrying its lineage; the stored form stays refs-first.

## Raw bytes (spec/05 §5)

`core.r5e.io/v1/CasObject` and `core.r5e.io/v1/CasExpired` are core Kinds,
seeded at bootstrap through admission like the meta-Kind. A `bytes:` ref
resolves only when a `CasObject` admission put the object on the record, and
the manifest entry names that admission.

A reference index over §5's four citation sources answers both §4's partition
and §5's "unreferenced" for the retention sweeper.

The one class of object with no admission of its own is the **kernel-derived**
one — bytes the kernel writes inside an admission, §8's policy evaluation
record being the first. An engine reports the addresses it wrote on its policy
metadata; the gate copies the list verbatim onto the event payload beside
`policy`, on denials too; `R5e.RefIndex` reads it back live and at replay. The
export manifest lists the union under `derivedObjects`. The kernel checks only
the *form* of those addresses — whether the bytes are present is the offline
verifier's question.

## Retention

```elixir
config :r5e, cas_ttl_seconds: 86_400   # a day
config :r5e, cas_ttl_seconds: nil      # the default: never expire
```

`R5e.Retention.sweep/0` submits one `CasExpired` per expired address through
the full pipeline, signed by the **retention key** — a second locally held
keypair, endorsed by the node key at event 10 for `core.r5e.io/v1/CasExpired`
and nothing else — citing that Endorsement on every sweep. `CasExpired`
declares `requiresAuthority`, so an expiry naming no authority is refused
whoever signed it, the node key included.

The bytes are removed by the `admit` step of the granted admission and by
nothing else, so an object that is gone has an event saying who removed it and
on what claim. An object is expired only when the reference index finds it
cited by nothing, and a citation that declared `retention: "public-record"`
makes the expiry impossible — denied at `validateConstraints`, naming the
citing seq.

Nothing calls `sweep/0` on a timer (debt #21).

## Commit (spec/05 §7)

`authorize` runs optimistically, holding no lock, and everything the pipeline
read is captured: the `generations` the policy engine reports, every
`kind`-ref `generation` in the resolution manifest, and every `sameAnchor`
head. At `record` the append lock is taken and the capture is re-checked. If
anything moved, nothing is appended and the admission re-runs from `resolve`
— not from `authenticate`: identity and shape were settled from the request
alone.

```elixir
config :r5e, commit_retries: 3   # the default; 0 means "deny on the first mismatch"
```

After the budget the admission is denied at `record` with reason
`contended: <what moved>`. That denial carries no captured generations, so it
appends unconditionally and cannot in turn be contended.

A substrate failure **after** the event is appended halts the node: every
later granted admission is denied at `record` with reason `halted: …` until
`R5e.Bootstrap.replay/0` or a restart makes the derived views agree with the
chain again. Denials keep being recorded while halted. All of it is per node;
multi-node is out of scope and §7 says so.

## Identity and authority (spec/06)

The six identity Kinds — `Principal`, `Endorsement`, `Badge`, `Succession`,
`Revocation`, `Deployment` — are seeded, and the schema grammar they use is
enforced: `matchesSigner`, `derives.keyIdOf`, `keyBytes`, `ordered`,
`atMostOne`, nested `requires` groups, the `{envelope: "authority"}`
condition, `signatures`, `requiresAuthority`, `admitBy` and `readmitBy`.

Citing an `Endorsement` or `Badge` is checked against §5's walk: the cited
event must be an admitted authority event, its subject must be the actor or a
key the actor succeeded, it must be unrevoked and in term with every link to
its root, and the Kind being admitted must be inside every authority cited.
Issuing one narrows monotonically on three axes — the right to issue, the
Kinds covered, the term — to a depth of at most 16. The whole derivation is
recorded as `resolvedAuthority`, link by link to the root. §6 re-checks the
revocation state and the term of every event the walk visited under the append
lock.

Succession is a set of disjoint simple paths: one outgoing edge per
predecessor, one incoming per successor, no self-edge, no cycle. A successor
stands in for its predecessor everywhere the contract says `matches`, and in
that direction only. Revoking a Succession removes the edge for every position
after the Revocation's — it is still live at the Revocation's own seq — and
reopens both slots.

§0's succession relation and §5's effectiveness walk are implemented **once**,
in `RecurseVerify.Authority`, the verifier package this kernel depends on.
`R5e.Authority` adds only what a live chain has: §6's version counter, the seq
about to be written, and event 1's signer. `R5e.Succession` holds no state.

## Bootstrap

A fresh chain's first ten events are its vocabulary and its first grant of
authority, in `priv/kinds/order.json`'s order: the meta-Kind v3 (whose payload
alone carries the `random` the chain's origin was derived from), `CasExpired`,
`CasObject`, `Principal`, `Endorsement`, `Badge`, `Succession`, `Revocation`,
`Deployment`, then the node key's Endorsement of the retention key. All ten are
signed and admitted through the same gate as everything else.

A log that predates any seed gets it at the next boot as an ordinary admission
signed by the node key. A seed whose *bytes* changed under spec 011 — the
meta-Kind (v2 → v3) and `CasExpired` (v1 → v2) — arrives as the same-identity
transition, declared `transition: "spec-011"` on its payload. That includes the
r5e-core genesis log.

A Kind whose definition predates schema-lite v2 carries no `naming`; it is
replayed as `{mode: "caller"}`, flagged legacy, and never denied.

## HTTP surface

| Route | Does |
|---|---|
| `POST /apis/<group>/<version>/<Kind>` | admit; body `{envelope, spec, name?}` |
| `PUT /cas` | admit a `CasObject`; envelope in `x-r5e-request` (base64, at most 8 KiB) |
| `GET /cas/<address>` | the object, under its recorded `mediaType` |
| `GET /apis` | admitted Kinds with their epistemic scopes and spec addresses |
| `GET /apis/<g>/<v>/<K>[/<name>][?resolution=deep]` | list, or one instance |
| `GET /events` | the chain |
| `GET /proof/inclusion?seq=N` | RFC 9162 audit path for one event |
| `GET /proof/consistency?from=N&to=M` | append-only proof between two tree sizes |
| `POST /export` | write a bundle; returns its path |

A `PUT /cas` request whose envelope header is absent or unreadable is a **400
with no receipt** — a transport error is not an act. A body over
`cas_max_bytes` is a **413 with no receipt**: nothing was submitted to the
gate. Putting bytes already present is a *new* admission of the same
content-named spec — another event, the same address, no rewrite.

## Configuration

| Key | Default | Means |
|---|---|---|
| `data_dir` | `.r5e` | CAS, log, keys, exports (`R5E_DATA_DIR`) |
| `http_port` | `4545` | (`R5E_PORT`) |
| `start_server` | `true` | `false` under `MIX_ENV=test` |
| `cas_max_bytes` | 16 MiB | the `PUT /cas` ceiling |
| `cas_ttl_seconds` | `nil` | never expire |
| `commit_retries` | `3` | §7 retries before `contended` |
| `policy` | `R5e.Policy.KernelCedar` | must implement the `R5e.Policy` behaviour; `R5e.Policy.AllowAll` under `MIX_ENV=test` |
| `seed_kernel_policy` | `true` | `false` under `MIX_ENV=test`, for the pre-policy vectors |
| `kernel_policy_recover` | `false` | re-admit the shipped default over the bundle in force (`R5E_KERNEL_POLICY_RECOVER=1`) |
| `before_record`, `substrate_hook` | `nil` | §7's two vector-only seams; unreachable from HTTP |

## Not implemented here

§8's PolicyShape grammar and evaluation record are the fold's, not the
kernel's (`r5e-enterprise/apps/recurse_fold`). The verifier prints its own
gaps in the not-checked block on every run; a claim this page does not make
is a claim the kernel does not support.
