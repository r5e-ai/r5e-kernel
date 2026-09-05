# Kernel policy

The kernel owns the upstream policy decision for every admission delegated to
it. A caller that also has workload policy evaluates the kernel bundle first,
then applies the narrower workload bundle within the same admission. A tenant
permit therefore cannot override a kernel denial or decide whether a core
management act enters the chain.

The policy in force is an admitted resource:

```text
core.r5e.io/v1/PolicyBundle/active
```

Its Kind uses literal naming and both `admitBy: nodeKey` and
`readmitBy: nodeKey`. Its `sourceRef` is a bytes reference with
`public-record` retention. On a fresh chain, bootstrap admits the Kind
definition, a measured engine descriptor as a `CasObject`, the Cedar source
as another `CasObject`, and the active bundle.

The initial Cedar rule permits a request when the signer is the effective
node key or the request's resolved authority has that key as its root. The
kernel derives both facts before authorization. An extension can narrow the
authority with its own Kind scope and `requiresAuthority`; the Cedar rule does
not turn an unrelated endorsement into authority.

Bootstrap has two fixpoint cases. While the synchronous seed process is
running and the active bundle is absent, the kernel permits only a node-signed
core seed. When an older bundle is active during an upgrade, the kernel also
permits the node-signed `CasObject` whose bytes and spec exactly match the
engine descriptor measured for that boot. The process-local marker and
measurement are cleared in an `after` block.

## Admitting a bundle

A candidate bundle is evaluated against the four acts the node key needs in
order to keep governing the chain: superseding this bundle, admitting an
`Endorsement`, transitioning the meta-Kind, and admitting the measured engine
descriptor. Each is presented to the candidate's own Cedar source exactly as
`authorize` presents a live request.

A candidate that denies any of them is refused at admission, and the denial
names the acts:

```text
authorize: candidate would deny the node key's governance acts: admission of core.r5e.io/v1/Endorsement; ...
```

The check runs on the bootstrap path as well as the ordinary one, so the first
bundle a chain records is held to the same rule as its successors. It does not
run backwards: a chain admitted before this check can carry a bundle that
fails it.

A refusal of the candidate is recorded with `decision: "deny"` and a note
naming the cause. Nothing was handed to Cedar about the request itself, and
the receipt does not say otherwise.

## Seeding and recovery

Bootstrap admits the shipped default only when no active bundle exists, so an
admitted supersession survives a restart. A kernel upgrade that changes
`priv/policy/default.cedar` does not replace an operator's bundle.

`R5E_KERNEL_POLICY_RECOVER=1` re-admits the shipped default over the bundle in
force. It is an ordinary admission by the node key: the bundle it replaces
decides it, and the act is on the chain like any other. Any other value for
the variable refuses the boot rather than being read as off.

A boot-time admission this node cannot get granted, or cannot sign because a
`Succession` moved the node key to a key it does not hold, refuses the boot
with the act, the denial and the recovery named.

For each Cedar evaluation, the receipt records the active bundle and source
addresses, matched policy ids, the bundle generation, and a derived object
containing the exact request and entity JSON handed to Cedar. The commit path
checks the captured bundle generation again under the append lock. The kernel
refuses an evaluation unless the boot-cached engine address still names an
admitted descriptor with intact CAS bytes.

The engine descriptor measures this build's Cargo lockfile, deployed NIF,
policy module beam, Cedar crate version, and OTP architecture. Equal
descriptor addresses mean those measured artifacts are equal. The descriptor
does not prove that the artifacts came from a particular source checkout or
that Cedar made a correct decision; a reproducible build and replay are
separate checks.

Tests which preserve the pre-policy conformance vectors set
`seed_kernel_policy: false` and use `R5e.Policy.AllowAll` explicitly. A normal
configuration seeds the bundle and uses `R5e.Policy.KernelCedar`.
