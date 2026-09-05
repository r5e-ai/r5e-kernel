import Config

config :r5e,
  data_dir:
    Path.join(
      System.tmp_dir!(),
      "r5e-test-#{System.os_time(:millisecond)}-#{:rand.uniform(100_000)}"
    ),
  start_server: false,
  seed_kernel_policy: false,
  # Existing conformance vectors predate the admitted policy bundle. Tests
  # that exercise production authorization opt into KernelCedar explicitly.
  policy: R5e.Policy.AllowAll
