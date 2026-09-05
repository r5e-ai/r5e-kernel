# Why the gate is shaped this way

Explanation, not reference. What the kernel enforces is in
[what-the-gate-enforces.md](what-the-gate-enforces.md); the normative texts
are in `r5e-core/spec/`.

## Denials are recorded because requests are acts

A gate that answers "no" and writes nothing has converted a governed refusal
into a private one. The record then says what was allowed, and the reader has
to trust the operator about the rest. So a denial takes the same path as an
admission: it is signed, appended, exported, and verified offline like any
other event.

The two exceptions prove the rule rather than weakening it. A malformed
envelope and a signature that does not verify are unattributable — nobody is
known to have asked — so recording them would attribute an act to a key that
may not have acted. They are refused, not denied, and the receipt says
`"recorded": false`.

## The verifier is the fixed point

The kernel depends on the verifier package; the verifier depends on nothing of
the kernel's. Canonical encoding, the chain, the Merkle tree, the ed25519
profile, instants, and — since spec 011 — the succession relation and the
authority walk have exactly one implementation, and it is the one a stranger
runs. A chain therefore cannot be admitted under one reading of the rules and
reported under another. Where the two ever disagreed, the verifier's reading
would win and the kernel's copy would go.

## The append lock is the commit lock

`authorize` runs holding no lock: a policy engine may be slow, and it has no
business holding up the chain. Everything the pipeline read is captured, and
the capture is re-checked under the lock at `record`. If anything moved,
nothing is appended and the admission re-runs from `resolve`.

`R5e.Log` performs the substrate write inside the same call that appends, in
that order, so no other admission can observe the store between an event
landing and its effect. Without that, "the generation I read has not moved"
would be a claim about a store that is behind the chain by an unbounded
amount.

## A halted node is a legible gap kept legible

A substrate failure after the event is appended leaves the record saying an
admission was granted while the substrate has no entry for it. That gap is
legible by construction. A node that kept admitting on top of a gap it knows
about would be converting a legible gap into an illegible one, so it halts:
every later granted admission is denied at `record` with `halted: …`, and
denials keep being recorded, because refusing to admit is not refusing to
answer. The caller of the admission that failed gets the failure rather than a
receipt, because a denial receipt would contradict the record.

## Root issuance is ungated, by design

Any key may admit a parentless `Endorsement` or `Badge` — including one naming
itself, with `kinds: ["*"]` and `mayIssue: true` — and the kernel records it
without objection. There is no key the kernel could consult to say otherwise
without becoming the root of trust itself.

A root is worth exactly what a reader has pinned it at. The verifier resolves a
chain only to a root the reader named with `--trust`, and an unpinned root
resolves to nothing. What the kernel does enforce is everything *below* the
root: a delegate never holds more than its endorser granted, on all three axes
spec/03 names, to a bounded depth.

## Vocabulary enters through the door, including on an old log

A log that predates a core seed gets it at its next boot, as an ordinary
signed admission — and a seed whose bytes changed under spec 011 arrives as a
declared same-identity transition. That includes the r5e-core genesis log.

This is the correct behaviour rather than a defect. A reader of that chain can
say exactly when the deployment learned what a `CasObject` is. The alternative
— vocabulary the kernel enforces and the chain never records — is the one
thing this design exists to refuse.

## The kernel-derived class had to become replayable

Bytes the kernel writes *inside* an admission have no `CasObject` of their
own, so the export has to declare them. Registering them in memory alone did
not survive a boot: the fold's first export after a restart listed none of its
evaluation records, and the verifier reported 24 findings, each a receipt
citing an object nothing accounted for.

The fix put the class on the record. An engine reports the addresses it wrote;
the gate copies the list verbatim onto the event payload, on denials too,
because a refused decision's record is the evidence for the refusal; the index
reads it back at every replay. The kernel checks only the form of the
addresses. Whether the bytes are present is the offline verifier's question,
which is what makes the claim falsifiable.

## Separation of the deleting key

The acts that delete bytes are done under an authority scoped to deleting
bytes. The retention key is a second locally held keypair, endorsed by the
node key at event 10 for `core.r5e.io/v1/CasExpired` and nothing else, and
`CasExpired` declares `requiresAuthority` — so an expiry naming no authority
is refused whoever signed it, the node key included.

Nothing calls the sweeper on a timer. When deletion happens is an operational
decision, and the kernel does not make one on the operator's behalf.
