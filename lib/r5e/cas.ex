defmodule R5e.CAS do
  @moduledoc """
  File-backed content-addressed store (spec/01 §3). The address is the
  sha256 of the bytes; the hash is the identity. Objects live under
  `<data_dir>/cas/<aa>/<rest-of-hex>` and are immutable once written.

  Write side lives here; addressing rules and read-from-root helpers are
  delegated to `RecurseVerify.CAS` (the standalone verifier package) so
  the store and its checker share one layout by construction.

  Three address forms exist (spec/05 §6) and only two of them name
  objects: `sha256:<hex>` and `bytes:sha256:<hex>` are the same tree and
  the same layout, distinguished by the act that admitted them, while
  `event:sha256:<hex>` names a position on the log and is never read from
  here. `object_address?/1` is the predicate for "can this be fetched";
  `valid_address?/1` answers the wider question "is this a well-formed
  address at all".

  ## Putting bytes on the record (spec/05 §5)

  `put/1` is the *write*, and a write is not an admission. Raw bytes enter
  the record through `admit/3`: the kernel hashes the body, builds a
  `core.r5e.io/v1/CasObject` spec from what it computed rather than from
  what the caller said, runs the **full** pipeline, and writes the bytes
  as the `admit` step — only on a grant. `PUT /cas` is that function with
  an HTTP surface around it.

  So `put/1` still exists and is still called: by the log for event
  payloads, by the admission gate for admitted specs, and by `admit/3`
  itself at the end of a granted pipeline. What it no longer is, is a way
  for a caller to put raw content into the deployment without a record of
  who did it. Objects written by `put/1` alone — kernel-written payloads
  and specs — are on the other side of §4's partition, and `R5e.RefIndex`
  is what tells the two apart.

  A put returns only after the object bytes and the directory entry naming
  them have been synced. Existing objects are checked against their address
  and synced as well. This makes the event-log ordering explicit: an event's
  payload reaches the CAS durability barrier before the event line reaches
  the log durability barrier.

  `delete/1` exists for exactly one caller: the `admit` step of a granted
  `CasExpired` (§5). Nothing else in the kernel removes an object.
  """

  defdelegate valid_address?(addr), to: RecurseVerify.CAS
  defdelegate object_address?(addr), to: RecurseVerify.CAS
  defdelegate object_hash(addr), to: RecurseVerify.CAS
  defdelegate relative_path(addr), to: RecurseVerify.CAS

  @doc "Fetch from an explicit CAS root (e.g. a bundle's `cas/`)."
  defdelegate get(cas_root, addr), to: RecurseVerify.CAS

  @doc "Store bytes; returns the `sha256:<hex>` address. Idempotent."
  @spec put(binary()) :: String.t()
  def put(bytes) when is_binary(bytes) do
    addr = R5e.Canonical.hash_bytes(bytes)
    path = object_path(root(), addr)

    if File.exists?(path),
      do: R5e.Persistence.sync_existing!(path, bytes),
      else: R5e.Persistence.write_atomic!(path, bytes)

    addr
  end

  @doc """
  The address of a spec (§6): the sha256 of its canonical encoding.

  The one derivation. Three places need it and used to spell it two ways —
  the `admit` step writing the spec, `R5e.Bootstrap` replaying it, and
  `R5e.RefIndex` recording the `specAddress` citation — and a spec that is
  recorded under one spelling and replayed under another is a store that
  disagrees with its own log.
  """
  @spec spec_address(term()) :: String.t()
  def spec_address(spec), do: R5e.Canonical.hash(spec)

  @doc """
  Write a spec's canonical bytes; returns `spec_address/1`. `put/1`
  returns the sha256 of what it stored and those bytes *are* the canonical
  encoding, so the two agree by construction (pinned by a test).
  """
  @spec put_spec(term()) :: String.t()
  def put_spec(spec), do: put(R5e.Canonical.encode(spec))

  @doc """
  The `CasObject` spec these bytes admit under (spec 011 §1). The kernel
  builds it from what it computed and never from what the caller said:
  the address is the hash of the body, the size is its byte size, the
  class is `raw`, and `mediaType` is `String.trim/1` of the
  `content-type` header — **omitted** when no header arrived, because
  "no label" and "an empty label" are different claims.

  It is public because the caller has to sign this spec's address before
  the kernel ever sees the request, and a client deriving the shape by
  hand would be a second implementation of it.
  """
  @spec object_spec(binary(), String.t() | nil) :: map()
  def object_spec(bytes, media_type \\ nil) when is_binary(bytes) do
    spec = %{
      "address" => "bytes:" <> R5e.Canonical.hash_bytes(bytes),
      "size" => byte_size(bytes),
      "class" => "raw"
    }

    case media_type do
      label when is_binary(label) ->
        case String.trim(label) do
          "" -> spec
          trimmed -> Map.put(spec, "mediaType", trimmed)
        end

      _ ->
        spec
    end
  end

  @doc """
  Admit raw bytes as a `core.r5e.io/v1/CasObject` (§5) — the kernel
  function `PUT /cas` is a thin HTTP wrapper around.

  The caller supplies the **signed envelope** (the `x-r5e-request`
  header), the bytes, and at most a `mediaType` label. The spec is
  `object_spec/2`; the envelope's `specAddress` must equal that spec's
  address and its target must be `{core.r5e.io, v1, CasObject, null}`, and
  both are checked by the ordinary gate at `validateStructure` — this
  route has no private door.

  Returns `{:ok, receipt, address, size}` on a grant, `{:denied, receipt}`
  otherwise. On a denial nothing was written: the bytes are the `admit`
  step, which a denial never reaches.
  """
  @spec admit(map(), binary(), String.t() | nil) ::
          {:ok, map(), String.t(), non_neg_integer()} | {:denied, map()}
  def admit(envelope, bytes, media_type \\ nil) when is_binary(bytes) do
    spec = object_spec(bytes, media_type)

    request = %{
      envelope: envelope,
      group: "core.r5e.io",
      version: "v1",
      kind: "CasObject",
      name: nil,
      spec: spec,
      cas_bytes: bytes
    }

    case R5e.Admission.admit(request) do
      {:ok, receipt} -> {:ok, receipt, spec["address"], byte_size(bytes)}
      {:denied, receipt} -> {:denied, receipt}
    end
  end

  @doc """
  Remove an object. The `admit` step of a granted `CasExpired` and nothing
  else (§5): the record of the removal is appended before the bytes go,
  so a crash in between leaves a chain that says the object was expired
  and an object still on disk — legible — never the reverse.
  """
  @spec delete(String.t()) :: :ok
  def delete(addr) do
    if object_address?(addr), do: R5e.Persistence.delete!(object_path(root(), addr))
    :ok
  end

  @doc "Fetch bytes by address."
  @spec get(String.t()) :: {:ok, binary()} | {:error, :not_found | :bad_address}
  def get(addr), do: RecurseVerify.CAS.get(root(), addr)

  @spec exists?(String.t()) :: boolean()
  def exists?(addr), do: exists?(root(), addr)

  @spec exists?(Path.t(), String.t()) :: boolean()
  def exists?(cas_root, addr) do
    object_address?(addr) and File.exists?(object_path(cas_root, addr))
  end

  @spec root() :: Path.t()
  def root, do: Path.join(Application.fetch_env!(:r5e, :data_dir), "cas")

  defp object_path(cas_root, addr), do: Path.join(cas_root, relative_path(addr))
end
