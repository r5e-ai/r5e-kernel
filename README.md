# r5e-kernel

The reference implementation of the r5e protocol: `core.r5e.io/v1` served
over HTTP, with a signed admission gate in front of three substrates. It
solves no domain problem; extensions do that, through the same gate. AGPL-3.0-only,
self-hostable. An offline reader can verify its exported evidence with core's
verifier and inspect the checks and limits that program reports.

## Start here

```sh
MIX_ENV=test mise exec -- mix test
```

Then [docs/quickstart.md](docs/quickstart.md): start an isolated HTTP example
with the actual kernel policy, or exercise the packaged enterprise path.

## The shape

One gate and three substrates.

- **admission** — `authenticate → validateStructure → resolve → authorize →
  validateConstraints → record → admit`; no exempt path, no exempt actor, and
  denials are recorded too.
- **resource graph** — refs-first storage; hydration is a computed view
  carrying its lineage, never the stored form.
- **event log** — append-only, hash-chained, with an RFC 9162 Merkle tree over
  the event hashes; checkpoints are DSSE-signed tree heads, and inclusion and
  consistency proofs are served over HTTP.
- **CAS** — content-addressed payloads; the hash is the identity.

Vocabulary is the extension mechanism: a Kind enters through the same
pipeline as everything else, carrying its epistemic scope — what its
attestations claim and what they must not be read as claiming — and its
naming mode.

Every admission is a signed request object in a DSSE envelope. An export
bundle verifies with no connection to any r5e service, using the standalone
Apache-licensed verifier in [`../r5e-core/verifier`](../r5e-core/verifier/).
The kernel depends on that package; it does not depend back. Shared routines
and conformance tests check agreement between writer and verifier.

## Pages

| Page | For |
|---|---|
| [docs/quickstart.md](docs/quickstart.md) | development checks, isolated HTTP example, packaged enterprise path |
| [docs/what-the-gate-enforces.md](docs/what-the-gate-enforces.md) | reference: the seven stages, the request object, spec/05 coverage, retention, commit, identity, the HTTP surface, configuration |
| [docs/design-notes.md](docs/design-notes.md) | why the gate is shaped this way |
| [docs/kernel-policy.md](docs/kernel-policy.md) | the admitted Cedar bundle, bootstrap boundary, and recorded evaluation evidence |
| [test/vectors/](test/vectors/README.md) | the conformance vectors and how to write one |
| [../r5e-core/spec/](../r5e-core/spec/00-kernel.md) | the normative protocol |
| [../r5e-core/verifier/](../r5e-core/verifier/README.md) | what the offline verification proves, and what it does not |

Source layout: `lib/r5e/admission.ex` is the gate; `refs.ex`/`resolve.ex` the
typed refs and the resolution manifest; `commit.ex` what an admission read,
re-checked under the append lock; `log.ex`/`chain.ex` the event log, the
Merkle tree and the one lock; `cas.ex` with `ref_index.ex` and `retention.ex`;
`authority.ex` and `succession.ex`, thin adapters over the verifier's walk;
`policy/kernel_cedar.ex` the Cedar decision and evidence path. `priv/kinds/`
holds the nine legacy-compatible core seeds listed in `order.json`;
`priv/policy/` holds the separately admitted PolicyBundle definition and
default source.

## Status — 2026-09-04

Self-hosted from event one. The suite includes the conformance vectors under
`test/vectors/` and three golden verifier reports frozen byte for byte.
Release acceptance and dated test results are recorded with the coordinated
enterprise candidate; a passing verifier report applies to its input bundle.

The Recurse Charter was admitted through this kernel as the first act on its
own log on 2026-09-01; the receipt, bundle and offline verification are in
[`../r5e-core/genesis/`](../r5e-core/genesis/). The ceremony script
`genesis.sh` predates the signed door of spec 011 and no longer runs against
this kernel — it submits an unsigned body and is refused at `authenticate`
(debt #55). The genesis record itself is unaffected.

Implemented: schema-lite v2 (spec/05) whole, including §4 typed refs, §5 raw
bytes and retention, and §7's commit protocol; spec/06 identity whole —
signed requests, the six identity Kinds, the authority walk, succession and
revocation; and the verifier's §9 output, pinned here by
`test/verifier_identity_test.exs` and by the `verify` block the vectors carry.

The kernel now records generic Cedar evaluation inputs for the policy bundle
that governs kernel and maintenance admission. Kind-specific PolicyShape
presentation remains in the fold (`r5e-enterprise/apps/recurse_fold`).
What is still deferred is listed under "Not implemented here" in
[docs/what-the-gate-enforces.md](docs/what-the-gate-enforces.md), and the
verifier prints its own gaps in the not-checked block on every run. A
Succession edge is withdrawn only when its predecessor or that actor's current
successor signs the Revocation, including when a verifier encounters an entry
that bypassed kernel admission.

What this kernel does and does not prove is printed by the verifier on every
run. The not-checked block is part of the output for exactly that reason.

## License

Copyright (c) 2026 r5e Inc. Licensed **`AGPL-3.0-only`** ([LICENSE](LICENSE),
scope in [LICENSE.md](LICENSE.md)), per ADR-0004: run a modified closed service
on this code and the network clause opens your source. Not "or any later
version". The protocol next door is Apache-2.0 on purpose; the asymmetry is the
design.

Contributions take the Developer Certificate of Origin and the contributor
agreement in [CLA.md](CLA.md); [CONTRIBUTING.md](CONTRIBUTING.md) has the two
commands. [Security](SECURITY.md) · [Code of conduct](CODE_OF_CONDUCT.md)

## Steward keys

Releases of this repository are signed by the steward, r5e Inc., with keys held on hardware.

- **Root key** (signs the release freight, and later governance acts on the public chain): `key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc`
- **Release signing key** (signs tags; a device key, not the root): `sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIBtRc8IONTDUOq5HioZEa1qpH9XT4z80VM0tcdJ8lSImAAAAD3NzaDpyNWUtcmVsZWFzZQ== Thomas Jones (gitlab.com)`

To check a tag: put the line `thomas@runr5e.ai namespaces="git" sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAIBtRc8IONTDUOq5HioZEa1qpH9XT4z80VM0tcdJ8lSImAAAAD3NzaDpyNWUtcmVsZWFzZQ== Thomas Jones (gitlab.com)` in a file, then `git -c gpg.format=ssh -c gpg.ssh.allowedSignersFile=<that file> tag -v v0.9.0`. To check a release's freight: download `freight.dsse.json` and `verify-freight.py` from the release and run `python3 verify-freight.py freight.dsse.json key:ed25519:sha256:aeb2f4f7d81d87ce8e9f437fa5bada43d41d7cf5badcceffdf37403ddfee53fc` (needs the `cryptography` package). The freight for v0.9.0 is `bytes:sha256:7c9d09d5128ba090ff339455db150091fd6fd7b2dbf1ce1e9e2297831ae288fd`.
