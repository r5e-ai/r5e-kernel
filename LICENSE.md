# License

Copyright (c) 2026 r5e Inc.

r5e-kernel is licensed `AGPL-3.0-only`: the GNU Affero General Public License,
version 3, whose full text is in [LICENSE](LICENSE). Not "or any later
version" — a later AGPL covers this code only when the copyright holder says
so.

The asymmetry is the design (ADR-0004). The protocol surface in r5e-core — the
charter, the specs, the conformance kit and the reference verifier — is
Apache-2.0, so a second implementation can be written, run and sold without
asking. This repository is the reference implementation, and it is AGPL.

One directory carries a different license, stated in a `LICENSE` file beside
it: `priv/kinds/`, the KindDefinition JSON, is Apache-2.0. It is the wire
shape a second implementation must match, which makes it protocol.

The genesis record — `genesis-receipt.real.json` and
`genesis-verification.real.txt` — is the same record that r5e-core publishes
under Apache-2.0. The bytes are duplicated across the two licenses on purpose;
either copy is the record.

Third-party components and their licenses are listed in the release's
`THIRD_PARTY_NOTICES.md`, at the r5e-enterprise root.
