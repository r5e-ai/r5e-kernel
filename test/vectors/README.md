# Conformance vectors

The discriminator for schema-lite v2 (spec/05 §12) and identity (spec/06):
440 cases, 204 of them under `identity/`. Two implementations agree iff they
agree on every vector here.

Over the 300-line reference budget, deliberately: every key the runner accepts
is documented exactly once, and a second implementer reading this page must not
have to reconstruct the set from two.

Each `<keyword-or-mode>/<case>.json` is one vector:

```jsonc
{
  "note":  "optional prose — why this case exists",
  "kinds": [ { …a KindDefinition… } … ],  // supporting Kinds, admitted first
  "kind":  { …a KindDefinition… }        // admitted next, then the instance
         | "core.r5e.io/v1/KindDefinition" // the instance IS a KindDefinition
         | "group/version/Kind",           // a Kind that is deliberately absent
  "cas":   [ "raw bytes" | {"bytes": "…", "mediaType": "…"}, … ],
                                          // admitted as CasObjects ($cas.N names one)
  "casRaw":[ "raw bytes", … ],            // written to the CAS, admitted by nobody ($raw.N)
  "derivedObjects": [ "raw bytes", … ],   // registered as kernel-derived ($derived.N)
  "setup": [ { "kind"?, "name"?, "spec", "actor"?, "denied"?, "raises"? } … ],
  "fixedKeys": true,                      // §9: chosen node/retention keys, so a report can be frozen
  "legacyLog": true,                      // §10: boot over the pre-011 log fixture
  "sweep": { "ttlSeconds": 86400 },       // §5: one run of the real retention sweeper, after the instance
  "forgetBefore": { "payloadOf": 0 },     // drop that setup step's payload object
  "policyReads": [ "g/v/K/name", … ],     // §7: the engine reads these and reports the generation
  "policyDerives": [ "raw bytes", … ],    // §5: the engine writes each and reports it ($written.N)
  "policyReports": [ "bytes:sha256:…" ],  // §5: reported on the meta, written by nobody
  "policyDenies": "reason",               // §5: and it denies, so a denial's record is pinned too
  "commitRetries": 2,                     // §7: the retry budget for this vector
  "interleave": { "before": "record", "repeat": 1,
                  "kind"?: "g/v/K", "admit": { …a step… } },   // §7, below
  "substrateFailure": "boom",             // §7: the admit step raises for that name
  "replayBeforeInstance": true,           // §7: R5e.Bootstrap.replay/0 before the instance
  "replayAfterInstance": true,            // §5: and after it — the restart, made deterministic
  "instance": { "name"?, "spec", "sign"?, "actor"?, "derivedFrom"?, … },
  "forgetAfter":  { "cas": 0 } | { "raw": 0 },  // drop that object, after admission
  "verify": {                             // §9: export the chain and ask the verifier
    "posture": "house" | "commons",       //   the reader's stance (required by an admitted Badge)
    "trust":     [ { "key": "$nodeKey", "label"?, "kinds"?, "notBefore"?, "notAfter"? } … ],
    "trustKeys": [ "KEY=LABEL", … ],      //   the `--trust` flag spelling, so its parsing is pinned
    "trustFile": [ { …the same pins… } … ],  //   written to a file and loaded through --trust-file
    "editPayload": [ { "payloadOf": "instance" | <setup index>,
                       "set": { "/pointer": <value> },
                       "tamper"?: "signature" | { "signature": N } } … ],
    "inject": [ { "kind": "g/v/K", "actor": "$key.3", "name"?, "spec" } … ]
  },
  "report": "reports/<name>.txt",         // §9: the whole verifier output, byte for byte
  "expect": {
    "outcome": "admitted" | "denied",
    "stage": "authenticate|validateStructure|resolve|authorize|validateConstraints|record|admit",
    "reasonIncludes": "substring of the denial reason",
    "name": "the admitted name",          // "$setup.N.name" refers back to a setup step
    "nameMatches": "regex the admitted name must match",
    "specAddress": "sha256:…",
    "derivedFrom": "bytes:sha256:…",
    "targetNameOmitted": true,            // §2 server: no target.name on the payload
    "entryUnchanged": true,               // §2 content: the store entry was not rewritten
    "supersededBy": 0,                    // the displaced setup entry records this admission
    "resolvedRefs": [ { "path": "/x", "class": "kind", … } … ],  // §4, in order
    "hydrated": { "/pointer": <value> },  // §6, ?resolution=deep
    "objectGone": "$cas.0",               // §5: the bytes are no longer in the CAS
    "objectPresent": "$cas.0",            // §5: they still are (both take a list too)
    "recordAttempts": 2,                  // §7: how many times the pipeline reached record
    "policy": { "generations": { … } },   // §7: a deep subset of the receipt's policy block
    "derivedObjects": [ "$written.0" ],   // §5: on the receipt and on the recorded payload
    "derivedRegistered": "$written.0",    // §5: R5e.RefIndex holds it (a list too)
    "exportDerivedObjects": [ … ],        // §5: the export manifest's union over the payloads
    "haltedAfter": true,                  // §7: the node is halted afterwards
    "notHalted": true,                    // §7: and here it is not
    "eventTs": "2026-09-02T00:00:00Z",    // §5: the `ts` the log wrote for the recorded event
    "verifier": {                         // §9, asked of the bundle `verify` exported
      "lines":  { "signatures"|"endorsements"|"identities": "substring" },
      "findings": [ "projection", … ],    // codes that must be present
      "noFindings": true,
      "notChecked": [ "substring", … ],
      "absentFromNotChecked": [ "substring", … ],
      "error": "substring"                // the run is refused (exit 2) — posture, duplicate pins
    }
  }
}
```

Every vector runs against a **fresh kernel**: its own data directory, its own
log, bootstrapped from event one.

    MIX_ENV=test mix test test/vectors_test.exs
    # 440 tests, 0 failures

## Identity (spec 011): every submission is signed

Since sub-slice 2a every admission goes through the signed door, so the
runner **synthesizes an envelope for every step**: signed by `$key.1`, a
fresh nonce, `expires` an hour out, this chain's origin, and the address of
the spec the step submits. A vector written before this contract therefore
keeps testing exactly what it tested, through the door the contract now
requires.

A step may say more, and each key exists because a case cannot be authored
any other way:

| key | does |
|---|---|
| `sign: [N…]` | signs with those conformance keys, in signature order |
| `actor: {"id": …}` | the older spelling: signs with the key that actor id maps to, so "another actor" still means another key |
| `nonce`, `expires`, `origin`, `specAddress`, `actorId` | override one signed field (`expires: "auto"` is the default hour) |
| `authority`, `derivedFrom` | signed fields, substituted like any other |
| `requestPatch` / `requestDrop` | change the request object **before** signing, so the signature is good and the form is wrong — the case that matters, because §2 checks form before signature |
| `tamperSignature: true` | flips a bit of signature 1 after signing: the only way to author "the form is right and the signature is not" |
| `rawRequest: "<bytes>"` | replaces the payload bytes after signing (the non-canonical-encoding case) |
| `rawEnvelope: <any>` | submits an arbitrary envelope verbatim; an explicit `null` means "no envelope at all" |
| `envelopePatch: {…}` | replaces envelope keys after signing — a bad `keyid`, a short `publicKeys` entry, a wrong `payloadType`, a non-canonical `sig` |
| `door: "cas"` with `body`, `signBody`?, `headers`? | the `PUT /cas` path: the spec is built from `signBody` (default `body`) and signed, then `body` is submitted |
| `signAs: "node" \| "retention"` | signs with one of the two keys this node holds, rather than a conformance key |
| `sign: ["node", 2]` | the same two keys are also legal *inside* `sign`, so a countersigned act one of whose signers is the node key — a `Succession` of the node key itself — can be written down |

Vector-level keys: `clock` sets the node clock for the whole run,
`clockAtInstance` moves it after the setup chain is built and before the
act under test (a term live at issuance and dead at citation), and
`clockAtRecord` moves it between `authorize` and `record` — which is how
§6's `record: expired` is pinned without sleeping through a 300-second skew
window.

`$key.N` substitutes the Nth conformance key's id; `$key.N.id` is the same
and `$key.N.bytes` is its base64 public key. `$origin` is this chain's
origin, which is not knowable when a vector is written.

New `expect` keys: `identity`, `signers`, `submittedTarget`, `nonceClaimed`,
`recorded` (false is the shape of an unattributable refusal — no event, no
nonce spent), `payloadSpec` (a deep subset of the recorded spec) and
`resolvedAuthority` (§5's whole derivation, deep-equal, and the recorded
one must match the receipt), `authorityRoots`, `depth`, `eventTs` (the
`ts` the log wrote for the recorded event — §5's `ts(s)`, which is what a
term is compared against, so a vector pinning a term boundary can pin the
instant the comparison used), and
`chain` (§10's bootstrap transcript — a list of `{seq, kind, name, actor,
identity, outcome, signers, hasRandom, hasOrigin}` subsets, checked against
the whole chain in order). A vector carrying only `expect.chain` submits
nothing: what it pins is the ten events a fresh kernel writes before any
caller arrives.

Three more tokens name what only the running node knows: `$nodeKey` and
`$retentionKey` are the two key ids it holds, and `$retentionEndorsement`
is the `event:` ref of event 10 — the Endorsement every expiry cites.

### Asking the verifier (spec 011 §9)

Everything §9 says is about a **bundle**, so a vector that pins a verifier
line, a finding or a whole report builds a chain, exports it, and asks
`RecurseVerify.run/2` — the same function the escript's `main/1` calls.
The reader's own arguments (`posture`, `trust`, `trustKeys`, `trustFile`)
go on the run and never on the chain, because that is where they come
from; `trustKeys` goes through the `--trust KEY[=LABEL]` parser and
`trustFile` through `--trust-file`, so both doors a reader uses are
exercised rather than bypassed.

Two keys make the hostile cases reachable, and **neither touches the
kernel** — a finding exists precisely for the case where the producer and
the record disagree, which no kernel would write:

* `editPayload` rewrites one payload inside the bundle, at the address the
  chain already names (`projection`, `signature`, `stale-shape`);
* `inject` appends an unauthenticated event to the exported log, with a
  valid hash link (`revocation-actor`).

Three vectors carry `report`, and each freezes the verifier's **whole
output** byte for byte under `test/vectors/reports/`: a fresh bootstrap
chain, a working chain, and a legacy chain transitioned forward. A report
names key ids and carries a checkpoint timestamp, so those two inputs are
fixed rather than generated — `fixedKeys` writes chosen node and retention
keys under the data directory before the kernel boots, and `clock` fixes
the clock. The one line normalized before comparison is the first, which
names the temporary directory the bundle happened to be written to.
`R5E_WRITE_GOLDEN=1 mix test` writes the files instead of comparing them;
that is how the three were produced, and each was read line by line and
reviewed in `handbook/design/spec-011-implementation-notes.md` before
being frozen.

`legacyLog: true` boots the vector's kernel over the pre-011 log fixture
instead of an empty directory, which is the only way to produce a chain
with `U > 0`. `sweep: {"ttlSeconds": N}` runs the real retention sweeper
after the instance, so a chain that wants a `CasExpired` gets the one the
sweeper writes — signed by the retention key, citing event 10 — rather
than an imitation of it.

### Vectors that are not admissions

Three pure functions the whole contract rests on are pinned directly, by a
vector carrying one of these keys and no `instance`:

* `canonical` — one case or a list of `{rawJson, bytes | error | sameAs}`:
  §8's raw-input half, which is the only door that can see a duplicate key,
  a `-0`, a `1.0` or a `\/`, because a decoder has already thrown those
  distinctions away;
* `derivations` — `{keyIds: [{algorithm, bytes, id | error}…], origin: {random, nodePublicKey, origin}}`;
* `ed25519` — `[{note, publicKey, signature, message, valid}…]`, hex, for §7's
  profile. `identity/ed25519/small-order-points.json` additionally carries
  libsodium's blacklist table verbatim, with its citation.

## Naming what the kernel decides

A ref target's identity is not knowable when a vector is written: an event
hash, a `content`-named instance's name and a raw object's address are all
settled by the kernel at admission. So a vector writes a **token**, and the
runner substitutes it inside any string, at any depth of a spec or a name:

| token | is replaced by |
|---|---|
| `$setup.N.name` | the name the Nth setup admission was granted under |
| `$setup.N.eventRef` | its `event:sha256:…` — the only way to cite an event |
| `$setup.N.event` | the same hash without the `event:` prefix |
| `$setup.N.specAddress` | the address of the spec it admitted |
| `$setup.N.payloadAddress` | the address of its event payload |
| `$cas.N` | `bytes:sha256:…` of the Nth `cas` entry — bytes a `CasObject` admission put on the record |
| `$casEvent.N` | the `event:sha256:…` of that admission — what a bytes manifest entry's `casObjectEvent` must equal |
| `$raw.N` | `bytes:sha256:…` of the Nth `casRaw` entry — bytes in the CAS that nobody admitted |
| `$derived.N` | `bytes:sha256:…` of the Nth `derivedObjects` entry |
| `$written.N` | `bytes:sha256:…` of the Nth `policyDerives` entry — the object the engine writes and reports |
| `$interleaved.N.<field>` | the same fields, on the Nth receipt the `interleave` hook produced |

Substitution is inside strings, so `"bytes:$setup.0.payloadAddress"` names an
event payload address *in bytes-ref form* — which is exactly what §4's
partition rule exists to refuse.

A string that is **exactly** one token takes the token's value with its type:
`"generation": "$setup.0.seq"` pins an integer, not the string `"8"`. Without
that, a vector could only pin a `seq` or a `generation` by writing down a
number that moves whenever the core seed set does.

`setup` steps may name a different `kind` than the instance (a ref needs
something to point at, and it is usually not the Kind under test) and may be
marked `"denied": true` — a denied admission is a recorded act, and an
`outcome: any` event ref is entitled to cite one.

## Deliberate loss

Two checks are reachable only when something the kernel wrote is gone, so two
hooks remove exactly one object each: `forgetBefore` (before the instance is
submitted — this is how a `resolve` denial for a missing target payload is
reached) and `forgetAfter` (after admission, before hydration is checked —
this is how the `$unresolved` form is reached). Nothing else in the runner
deletes anything.

## Raw bytes, three ways (§5)

`cas`, `casRaw` and `derivedObjects` are the three states a raw object can be
in, and the vectors need all three because §5's rule is about which one it is:

* **`cas`** — admitted. Each entry is put on the record by `R5e.CAS.admit/3`,
  the function `PUT /cas` calls, so a `$cas.N` ref resolves and its manifest
  entry names the `CasObject` admission (`$casEvent.N`).
* **`casRaw`** — present and admitted by nobody: what a deployment holds if
  bytes were written without an act. A ref to one is denied at `resolve`.
  There is no other way to produce such an object, because the kernel no
  longer offers a path that does.
* **`derivedObjects`** — the kernel-derived class: bytes written *inside* an
  admission, which therefore have no `CasObject` of their own. A ref resolves
  with `casObjectEvent: null` and `derived: true`. This key registers one
  **synthetically**, through `R5e.RefIndex.register_derived/2` alone, which is
  the in-memory door: it is how a `cas/` vector gets a member of the class to
  cite without an engine. `policyDerives` is the other door, below.

## The kernel-derived class, and the door that survives a restart (§5)

`register_derived/2` puts an object in the class *in this process*. The
contract's key puts it **on the record**: an engine reports the addresses it
wrote on its policy metadata, `R5e.Admission` copies the list verbatim onto
the event payload as `derivedObjects` beside `policy`, and `R5e.RefIndex`
reads it back — live, and again at every replay. `derived/` is the vector set
for that path, and `R5e.Vectors.DerivingPolicy` is the engine it installs:

* **`policyDerives`** — bytes the engine writes to the CAS during `authorize`
  and then reports. `$written.N` names one; the address is a hash of bytes the
  vector wrote down, so it is knowable before the act.
* **`policyReports`** — addresses reported without writing anything. The
  kernel copies the form-checked list and no more (amendment C6), so this is
  how a vector pins both halves of the line it draws: a well-formed address
  the engine never wrote is *recorded*, and the verifier is what falsifies it;
  a string that is not a `bytes:sha256:<hex>` address at all is a malformed
  policy answer and denies at `authorize`.
* **`policyDenies`** — the engine refuses. A denial's evaluation record is
  evidence of the refusal, so its payload carries the key too.

`replayAfterInstance` is what makes the class's replayability falsifiable
rather than asserted: it runs `R5e.Bootstrap.replay/0` after the admission,
which resets the index and rebuilds it from the chain alone. An object
registered only in memory is gone by the time `derivedRegistered` and
`exportDerivedObjects` are asked.

Two §5 behaviours are **not** vectors, because the vector runner submits
admissions and they are not admissions: `PUT /cas`'s body ceiling (a 413 with
no receipt — an HTTP refusal before the gate is reached) and `GET /cas`. Both
are pinned in `test/router_test.exs`, and the sweeper's own scheduling and
TTL arithmetic in `test/retention_test.exs`.

## Interleaving, and the two other §7 seams

§7 is a statement about what happens *between* `authorize` and `record`,
and that window cannot be reached from outside the gate. Three optional
keys reach it, through hooks the kernel exposes only for this purpose
(`config :r5e, :before_record` / `:substrate_hook`, both `nil` in every
shipped config — see `R5e.Admission`):

* **`interleave`** runs another admission before each `record` attempt of
  the instance. `repeat` (default 1) caps how many times it actually
  admits, which is the difference between the two shapes of the story:
  `repeat: 1` moves the generation once, so the retry finds a settled
  world and commits; a `repeat` above the retry budget keeps moving it,
  so the admission is denied `contended`. Every receipt it produces is
  kept and named by `$interleaved.N.<field>`; `expect.recordAttempts`
  counts the attempts themselves, whether or not the hook admitted
  anything that time.
* **`policyReads`** installs a policy that reads the named admitted
  resources and reports, per §7, the generation it read each at. Without
  a policy that reads something, the policy half of the capture is empty
  and nothing about it can be tested — `R5e.Policy.AllowAll` reports
  `{}` because a constant is not a read.
* **`substrateFailure`** names an instance whose `admit` step raises,
  which is the post-record substrate failure. The setup step that carries
  that name is marked `"raises": true`: the caller of such an admission
  gets the failure, not a receipt, because the act is already on the
  chain and a denial receipt would say otherwise. `replayBeforeInstance`
  is the other half — replay is what clears the halt.

`gateway/` is not vectors: it holds the nine `gateway.r5e.io/v1alpha1` seeds
verbatim, as fixtures for `R5e.GatewaySeedsTest` and `R5e.StoryOneTest` — the
shapes the validator must accept, and the sequence they were written for.
