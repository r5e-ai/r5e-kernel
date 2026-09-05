defmodule R5e.Export do
  @moduledoc """
  Writes an offline-verifiable bundle directory:

      bundle/
        log.jsonl        — the full chain, byte-for-byte
        cas/…            — every CAS object the chain references (event
                           payloads, admitted specs, and every `sha256:` or
                           `bytes:sha256:` address cited inside them, bare
                           or inside a `$ref`) that this deployment holds
        kinds/…json      — the admitted KindDefinitions
        manifest.json    — counts + the checkpoint placeholder

  Objects the deployment does not hold are listed under
  `manifest.missingObjects` — a bundle states its gaps rather than papering
  over them; the verifier reports them as findings.

  `manifest.derivedObjects` (spec/05 §5) lists the kernel-derived objects:
  bytes the kernel wrote *inside* an admission, which therefore carry no
  `CasObject` admission of their own. Every other `bytes:` object in a
  bundle must be backed by one, and the verifier reports one that is not;
  this list is what keeps that check from firing on the one class that
  legitimately cannot have an admission.

  It is the **union over the payloads**: `R5e.RefIndex` holds the class,
  and it holds it because every admission that wrote such an object
  recorded the addresses on its own payload (`R5e.Admission`,
  `derivedObjects` beside `policy`). So the list an export writes is a
  function of the chain and not of how long this node has been up — the
  same bundle comes out of a node that has just replayed the log as out
  of the node that admitted it. The verifier re-derives the same union
  from the payloads and reports a manifest that disagrees with it.

  ## Into an empty directory, or not at all

  A bundle is a *whole* claim: the manifest counts the objects beside it,
  and the verifier reads every file in `cas/` as something the chain must
  account for. Writing into a directory that already holds files would
  produce one log beside another run's objects, which the verifier would
  report as objects nothing on this chain put there — and it would be
  right. So a non-empty destination is refused with
  `{:error, {:non_empty, dest}}` and nothing is written.
  """

  @spec run(Path.t() | nil) :: {:ok, Path.t(), map()} | {:error, term()}
  def run(dest \\ nil) do
    dest = dest || default_dest()

    with :ok <- File.mkdir_p(dest),
         :ok <- empty?(dest) do
      events = R5e.Log.events()
      File.cp!(R5e.Log.log_path(), Path.join(dest, "log.jsonl"))

      derived = R5e.RefIndex.derived_objects()
      {copied, missing} = copy_objects(events, derived, dest)
      kinds = write_kinds(dest)

      manifest = %{
        "exportedAt" => R5e.Clock.ts(),
        "events" => length(events),
        "objects" => copied,
        "missingObjects" => missing,
        "derivedObjects" => derived,
        "kinds" => kinds,
        "checkpoint" => R5e.Log.checkpoint(),
        "signer" => %{
          "keyId" => R5e.SignerProvider.key_id(),
          "publicKey" => Base.encode64(R5e.SignerProvider.public_key()),
          "algorithm" => "ed25519"
        }
      }

      File.write!(Path.join(dest, "manifest.json"), Jason.encode!(manifest, pretty: true))
      {:ok, dest, manifest}
    end
  end

  defp default_dest do
    Path.join([
      Application.fetch_env!(:r5e, :data_dir),
      "exports",
      "bundle-#{System.os_time(:second)}"
    ])
  end

  defp empty?(dest) do
    case File.ls(dest) do
      {:ok, []} -> :ok
      {:ok, [_ | _]} -> {:error, {:non_empty, dest}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp copy_objects(events, derived, dest) do
    addrs =
      events
      |> Enum.flat_map(&[&1["payload"] | cited_addrs(&1)])
      # A kernel-derived object (§5) is cited from a payload like any
      # other `bytes:` address, so the sweep already reaches it; it is
      # added here so a bundle carries the objects its own
      # `derivedObjects` list names even before anything cites them.
      |> Kernel.++(Enum.map(derived, &R5e.CAS.object_hash/1))
      |> Enum.uniq()
      |> Enum.filter(&R5e.CAS.object_address?/1)

    Enum.reduce(addrs, {0, []}, fn addr, {copied, missing} ->
      case R5e.CAS.get(addr) do
        {:ok, bytes} ->
          target = Path.join([dest, "cas", R5e.CAS.relative_path(addr)])
          File.mkdir_p!(Path.dirname(target))
          File.write!(target, bytes)
          {copied + 1, missing}

        {:error, _} ->
          {copied, [addr | missing]}
      end
    end)
  end

  defp cited_addrs(event) do
    case R5e.Log.payload(event) do
      {:ok, payload} -> collect_addrs(payload |> without_name() |> without_identity())
      :error -> []
    end
  end

  # A `target.name` is a **name**, not a citation. `content` naming spells
  # one exactly like an address (§2), and on a *denial* there is no object
  # behind it at all — nothing was admitted, so nothing was written.
  # Sweeping it would have every content-named denial report a missing
  # object the chain never claimed to hold, and a bundle's stated gaps are
  # only worth reading if every one of them is real.
  defp without_name(%{"target" => target} = payload) when is_map(target),
    do: %{payload | "target" => Map.delete(target, "name")}

  defp without_name(payload), do: payload

  # Spec 011 §1's identity block is not a citation either. `origin` is
  # spelled exactly like an object address and names a **chain**; the
  # signed envelope carries base64, not addresses; `submittedTarget.name`
  # is a name for the same reason `target.name` is. Sweeping any of them
  # would have every signed event report a missing object the chain never
  # claimed to hold.
  defp without_identity(payload), do: Map.drop(payload, R5e.Admission.identity_fields())

  # The sweep (spec/05 §6): every `sha256:` and `bytes:sha256:` string
  # anywhere in a payload is a candidate object, whether it is a bare
  # value (a policy bundle address, an envelope `derivedFrom`, a manifest
  # entry's `value`) or a ref value's `$ref` — the walk recurses into maps
  # and lists, so both are reached the same way and neither needs a
  # special case. A `bytes:` address is swept as the object it names:
  # same tree, same layout, and only the act that put it there differs.
  #
  # `event:sha256:` strings are deliberately absent: an event hash names a
  # position on the log, and the log is copied whole. There is nothing to
  # copy for it, and reaching for one would be reaching for a file that
  # was never written.
  defp collect_addrs(%{} = map), do: Enum.flat_map(map, fn {_k, v} -> collect_addrs(v) end)
  defp collect_addrs(list) when is_list(list), do: Enum.flat_map(list, &collect_addrs/1)
  defp collect_addrs("sha256:" <> _ = addr), do: [addr]
  defp collect_addrs("bytes:sha256:" <> hex), do: ["sha256:" <> hex]
  defp collect_addrs(_), do: []

  defp write_kinds(dest) do
    kinds_dir = Path.join(dest, "kinds")
    File.mkdir_p!(kinds_dir)

    for kind <- R5e.KindRegistry.list() do
      name = R5e.Kind.name(kind) |> String.replace("/", "_")

      File.write!(
        Path.join(kinds_dir, name <> ".json"),
        Jason.encode!(R5e.Kind.to_map(kind), pretty: true)
      )

      R5e.Kind.name(kind)
    end
  end
end
