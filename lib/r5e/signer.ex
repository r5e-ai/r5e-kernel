defmodule R5e.SignerProvider do
  @moduledoc """
  The seam between the kernel and whatever holds its signing key.

  A provider signs raw bytes and exposes its public key and a stable key
  id. The kernel never sees private key material through this interface —
  a provider may keep it in a local file, an HSM, or a remote KMS; the
  admission and checkpoint code cannot tell the difference and must not
  try.

  **Self-custody is the paved road.** Per the charter, a deployment's
  evidence should be checkable without trusting any third party's key
  service: the default provider (`R5e.Signer.Local`) generates and holds
  an ed25519 keypair on the node's own disk. Remote/KMS providers are
  legitimate future implementations of this behaviour for operators with
  different custody requirements — the behaviour is the seam; nothing
  else in the kernel may know which custody model is in use.

  Configure with `config :r5e, signer: {module, opts}`.
  """

  @doc "Sign `message` bytes; returns the raw signature bytes."
  @callback sign(opts :: term(), message :: binary()) :: binary()

  @doc "The raw public key bytes for the signing key."
  @callback public_key(opts :: term()) :: binary()

  @doc "Stable identifier for the key (the public key's sha256 fingerprint)."
  @callback key_id(opts :: term()) :: String.t()

  @spec active() :: {module(), term()}
  def active, do: Application.get_env(:r5e, :signer, {R5e.Signer.Local, []})

  def sign(message), do: with({mod, opts} <- active(), do: mod.sign(opts, message))
  def public_key, do: with({mod, opts} <- active(), do: mod.public_key(opts))
  def key_id, do: with({mod, opts} <- active(), do: mod.key_id(opts))
end

defmodule R5e.Signer.Local do
  @moduledoc """
  Default signer: an ed25519 keypair on the node's own disk (self-custody,
  the paved road — see `R5e.SignerProvider`).

  Key material lives under `<data_dir>/keys/`:

    * `node_ed25519.key` — 32-byte private key, file mode 0600, generated
      on first boot and never transmitted anywhere.
    * `node_ed25519.pub` — 32-byte public key, world-readable; exported
      into bundles so verifiers can check checkpoint signatures offline.

  Signing uses Erlang `:crypto` (eddsa/ed25519) directly — no external
  dependencies, nothing to audit beyond OTP itself.

  Both key files and their directory entries cross the persistence barrier
  before first use. Later loads verify that the two halves match. A partial
  pair is refused, and a missing node pair is never regenerated over a
  nonempty event log: acknowledged history keeps its original identity or the
  deployment stays down for explicit operator recovery.
  """

  @behaviour R5e.SignerProvider

  @impl true
  def sign(opts, message) when is_binary(message) do
    {priv, _pub} = load_or_generate!(opts)
    :crypto.sign(:eddsa, :none, message, [priv, :ed25519])
  end

  @impl true
  def public_key(opts) do
    {_priv, pub} = load_or_generate!(opts)
    pub
  end

  @impl true
  def key_id(opts), do: fingerprint(public_key(opts))

  @doc "Verify an ed25519 signature (delegated to the verifier package)."
  @spec verify(binary(), binary(), binary()) :: boolean()
  defdelegate verify(message, signature, public_key_bytes),
    to: RecurseVerify.DSSE,
    as: :verify_ed25519

  @doc "sha256 fingerprint of raw public key bytes — the key id."
  @spec fingerprint(binary()) :: String.t()
  defdelegate fingerprint(public_key_bytes), to: RecurseVerify.DSSE

  @doc "Generate the keypair now if absent (called at boot; also lazy)."
  def ensure_keys!(opts \\ []), do: load_or_generate!(opts) && :ok

  @doc """
  A locally held keypair for a named **role** (spec 011 §10): the
  retention key, and later the fold key. Same directory, same custody,
  same generate-once-on-first-use rule as the node key — and, like the
  node key, the private half never leaves this node.

  A role key is not a second node key. It signs only the acts its role
  Endorsement covers, and the chain records which key signed what, so a
  reader can tell the node's own acts from the sweeper's.

  First use may create a new role key even after bootstrap has written core
  vocabulary. Once this node has endorsed a subject for that role, losing or
  replacing the pair is a recovery condition: the kernel refuses instead of
  granting the same role name to new filesystem bytes.
  """
  @spec role_keypair(String.t(), keyword()) :: %{
          public: binary(),
          private: binary(),
          algorithm: String.t()
        }
  def role_keypair(role, opts \\ []) when is_binary(role) do
    dir = Keyword.get(opts, :key_dir, Path.join(Application.fetch_env!(:r5e, :data_dir), "keys"))
    priv_path = Path.join(dir, "#{role}_ed25519.key")
    pub_path = Path.join(dir, "#{role}_ed25519.pub")
    subjects = node_endorsed_role_subjects!(role)

    {priv, pub} =
      load_or_create_pair!(
        priv_path,
        pub_path,
        "role #{inspect(role)}",
        subjects == [],
        "an existing node-endorsed role identity"
      )

    subject = RecurseVerify.DSSE.key_id!("ed25519", pub)

    if subjects != [] and subjects != [subject] do
      raise "loaded role #{inspect(role)} signing key #{subject} does not match " <>
              "node-endorsed role identity history #{inspect(subjects)}"
    end

    %{public: pub, private: priv, algorithm: "ed25519"}
  end

  defp load_or_generate!(opts) do
    dir = Keyword.get(opts, :key_dir, Path.join(Application.fetch_env!(:r5e, :data_dir), "keys"))
    priv_path = Path.join(dir, "node_ed25519.key")
    pub_path = Path.join(dir, "node_ed25519.pub")

    load_or_create_pair!(priv_path, pub_path, "node", node_identity_may_be_created?())
  end

  defp load_or_create_pair!(
         priv_path,
         pub_path,
         label,
         may_create?,
         refusal \\ "a nonempty event log"
       ) do
    case {file_present!(priv_path), file_present!(pub_path)} do
      {true, true} ->
        load_and_validate_pair!(priv_path, pub_path, label)

      {false, false} when may_create? ->
        create_pair!(priv_path, pub_path)

      {false, false} ->
        raise "refusing to generate a new #{label} signing key for #{refusal}"

      {priv?, _pub?} ->
        missing = if priv?, do: pub_path, else: priv_path
        present = if priv?, do: priv_path, else: pub_path

        raise "incomplete #{label} signing keypair: #{present} exists but #{missing} is missing"
    end
  end

  defp create_pair!(priv_path, pub_path) do
    {pub, priv} = :crypto.generate_key(:eddsa, :ed25519)

    # The private-key temporary file is already 0600 before secret bytes are
    # written. Each half and its directory entry crosses a persistence barrier
    # before the pair is returned. A crash between the two installs leaves a
    # partial pair that the next boot refuses rather than silently replacing.
    R5e.Persistence.write_atomic!(priv_path, priv, mode: 0o600, replace: false)
    R5e.Persistence.write_atomic!(pub_path, pub, replace: false)
    {priv, pub}
  end

  defp load_and_validate_pair!(priv_path, pub_path, label) do
    priv = File.read!(priv_path)
    pub = File.read!(pub_path)

    unless byte_size(priv) == 32 and byte_size(pub) == 32 do
      raise "invalid #{label} signing keypair: both files must contain exactly 32 bytes"
    end

    {derived_pub, ^priv} = :crypto.generate_key(:eddsa, :ed25519, priv)

    unless derived_pub == pub do
      raise "invalid #{label} signing keypair: public key does not match private key"
    end

    # Upgrade legacy key files to the same persistence contract. The chmod is
    # intentional: old installs wrote before restricting the private file.
    File.chmod!(priv_path, 0o600)
    R5e.Persistence.sync_existing!(priv_path, priv)
    R5e.Persistence.sync_existing!(pub_path, pub)
    {priv, pub}
  end

  defp node_identity_may_be_created? do
    log_path = Path.join(Application.fetch_env!(:r5e, :data_dir), "log.jsonl")

    case File.stat(log_path) do
      {:ok, %{size: 0}} -> true
      {:ok, %{size: size}} when size > 0 -> false
      {:error, :enoent} -> true
      {:error, reason} -> raise File.Error, reason: reason, action: "inspect", path: log_path
    end
  end

  defp node_endorsed_role_subjects!(role) do
    log_path = Path.join(Application.fetch_env!(:r5e, :data_dir), "log.jsonl")

    events =
      case R5e.Chain.read_log(log_path) do
        {:ok, events} -> events
        {:error, :enoent} -> []
        {:error, reason} -> raise "cannot inspect role identity history: #{inspect(reason)}"
      end

    index = R5e.Authority.index()
    first_signer = R5e.Authority.first_signer()
    local_node = R5e.DSSE.local_key_id()

    subjects =
      events
      |> Enum.flat_map(fn event ->
        node_at_event = historical_node_key(index, first_signer, local_node, event["seq"])

        with "admission.granted" <- event["kind"],
             {:ok, payload} <- R5e.Log.payload(event),
             "core.r5e.io/v1/Endorsement" <- R5e.Admission.target_path(payload),
             ^role <- get_in(payload, ["spec", "role"]),
             "signed" <- payload["identity"],
             ^node_at_event <- get_in(payload, ["actor", "id"]),
             true <- node_at_event in (payload["signers"] || []),
             subject when is_binary(subject) <- get_in(payload, ["spec", "subject"]) do
          [subject]
        else
          _ -> []
        end
      end)
      |> Enum.uniq()
      |> Enum.sort()

    subjects
  end

  # The node key at an event is the head, at that event's position, of the
  # key that signed event 1. Looking only at today's node would forget role
  # bindings its legitimate predecessor issued. Legacy chains whose event 1
  # predates signatures use the locally held node identity, as `Succession`
  # does for the same case.
  defp historical_node_key(_index, nil, local_node, _seq), do: local_node

  defp historical_node_key(index, first_signer, _local_node, seq),
    do: RecurseVerify.Authority.head(index, first_signer, seq)

  defp file_present!(path) do
    case File.stat(path) do
      {:ok, _stat} -> true
      {:error, :enoent} -> false
      {:error, reason} -> raise File.Error, reason: reason, action: "inspect", path: path
    end
  end
end
