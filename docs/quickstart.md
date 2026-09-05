# Kernel development quickstart

Validated in the OSS candidate on 2026-09-04/05. Requires Elixir 1.19,
Erlang/OTP 28 and Rust 1.92 with Cargo; `.tool-versions` pins them.
The sibling `r5e-core` repository provides the verifier dependency.

## Run the checks

From the kernel root:

```sh
MIX_ENV=test mise exec -- mix test
```

The suite uses temporary data directories and includes signed admission,
kernel/workload jurisdiction, persistence failure, restart, export and
offline verification. The full working-chain report is checked against
`test/vectors/reports/working-chain.txt`.

## Start an isolated HTTP example

The ordinary test configuration disables the listener and uses a permissive
test policy. The following command explicitly enables the real kernel policy
and listener while using a fresh temporary directory. It leaves any existing
kernel history untouched.

```sh
R5E_DATA_DIR=$(mktemp -d /private/tmp/r5e-kernel-doc-server.XXXXXX) R5E_PORT=45983 MIX_ENV=test mise exec -- mix run --no-start -e 'Application.put_env(:r5e, :start_server, true); Application.put_env(:r5e, :seed_kernel_policy, true); Application.put_env(:r5e, :policy, R5e.Policy.KernelCedar); {:ok, _} = Application.ensure_all_started(:r5e); Process.sleep(:infinity)'
```

The temporary-directory template above is for the macOS validation host;
on another host use an existing writable temporary parent. Select an unused
port if the example port is occupied.

In another terminal:

```sh
curl -fsS http://localhost:45983/events | jq '.events | length'
curl -fsS http://localhost:45983/apis
```

The validated fresh boot produced:

```text
14
```

The API response lists the admitted Kind definitions. Caller writes require
signed requests and authority; the server does not sign requests for callers.
[The gate reference](what-the-gate-enforces.md) describes the request object,
and [kernel policy](kernel-policy.md) explains its governing policy.

Stop the example with Ctrl-C. To keep a deployment across restarts, retain its
data directory and signing keys; generating a fresh directory creates a
different chain and identity.

## Exercise enterprise traffic

The [enterprise quickstart](../../r5e-enterprise/docs/quickstart-claude-code.md)
runs the packaged gateway, admits model and tool requests, and exports the
kernel chain. Its [evidence guide](../../r5e-enterprise/docs/fold-evidence.md)
shows how to invoke the core verifier separately from the writer.

The [older signing-client walkthrough](history/quickstart-spec07-r2.md)
preserves a run against the 2026-09-02 pre-policy bookmark. Its sequence
numbers, policy behavior and build output are historical.
