import Config

config :r5e,
  # Root of the on-disk substrates: CAS under <data_dir>/cas, log at <data_dir>/log.jsonl.
  data_dir: ".r5e",
  http_port: 4545,
  start_server: true,
  # spec/05 §5: the ceiling on a `PUT /cas` body. Over it the request is
  # refused with 413 before it reaches the admission gate, so there is no
  # receipt — nothing was submitted.
  cas_max_bytes: 16 * 1024 * 1024,
  # spec/05 §5: how long a raw object is kept once nothing cites it, in
  # seconds. `nil` means never expire, and is the default: a deployment
  # that has not stated a retention period keeps what it was given.
  cas_ttl_seconds: nil,
  # spec/05 §7: how many times a contended admission re-runs from
  # `resolve` before it is denied at `record` with reason `contended`.
  # Zero means "never retry": the first mismatch is a denial.
  commit_retries: 3,
  # spec/05 §7's two test-only seams (see `R5e.Admission`). Both stay
  # `nil` outside the conformance vectors: they exist so interleaving and
  # a post-record substrate failure can be provoked deterministically,
  # and neither is reachable from the HTTP surface.
  before_record: nil,
  substrate_hook: nil,
  # Test harnesses which intentionally replay the pre-policy genesis sequence
  # can turn this off explicitly.
  seed_kernel_policy: true,
  # Re-admit the shipped default kernel policy over the bundle already in
  # force. Off, and it stays off unless an operator sets
  # `R5E_KERNEL_POLICY_RECOVER=1` for a boot: the kernel's bundle is seeded
  # on **presence**, so an admitted supersession survives a restart, and
  # replacing it is an explicit, recorded act rather than a side effect of
  # upgrading `priv/policy/default.cedar`. The bundle in force decides the
  # recovery admission like any other; a denial refuses the boot with the
  # reason and the bundle address.
  kernel_policy_recover: false,
  # Authorization policy module (must implement the R5e.Policy behaviour).
  policy: R5e.Policy.KernelCedar

import_config "#{config_env()}.exs"
