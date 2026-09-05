defmodule R5e.DSSE do
  @moduledoc """
  Signing side of DSSE (Dead Simple Signing Envelope, ITE-5) — assembles
  and signs envelopes with the active `R5e.SignerProvider`. PAE assembly
  and envelope verification live in `RecurseVerify.DSSE` (the standalone
  verifier package, originally ported from r5e-enterprise's Feature
  001/002 implementation, narrowed to ed25519 and freed of the KMS
  coupling) and are delegated, so signer and checker share one encoding
  by construction.
  """

  defdelegate pae(type, payload), to: RecurseVerify.DSSE
  defdelegate verify(envelope, public_key_bytes), to: RecurseVerify.DSSE

  @doc "Contract §0's algorithm registry, v1."
  defdelegate registry(), to: RecurseVerify.DSSE

  @doc "Contract §0's key id: `key:<alg>:sha256:<hex>` over the tag-prefixed key bytes."
  defdelegate key_id(algorithm, public_key_bytes), to: RecurseVerify.DSSE

  @doc "Whether a string has the shape of a §0 key id."
  defdelegate key_id?(id), to: RecurseVerify.DSSE

  @doc """
  The key id of the keypair **this node holds** — what `R5e.SignerProvider`
  signs with. Not the same question as `node_key_id/0`: a node that has
  succeeded its key still signs with the key it holds, while §0's node key
  is whoever now speaks for the key that signed event 1.
  """
  @spec local_key_id() :: String.t()
  def local_key_id, do: RecurseVerify.DSSE.key_id!("ed25519", R5e.SignerProvider.public_key())

  @doc """
  §0's **node key**: the terminal successor of the key that signed event 1,
  by admitted unrevoked Successions. Delegated to `R5e.Succession`, which
  holds the relation.

  `admitBy: "nodeKey"`, `readmitBy: "nodeKey"` and the §11 transition all
  rest on this, so a deployment that rotates its node key keeps the ability
  to admit its own `Deployment` and to transition its own seeds — which is
  the whole reason §0 defines it by succession rather than by whichever
  key a process happens to hold.
  """
  @spec node_key_id() :: String.t()
  def node_key_id, do: R5e.Succession.node_key()

  @doc "Sign `payload` under `type` with the active signer; returns the envelope map."
  @spec envelope(String.t(), binary()) :: map()
  def envelope(type, payload) do
    sig = R5e.SignerProvider.sign(pae(type, payload))

    %{
      "payloadType" => type,
      "payload" => Base.encode64(payload),
      "signatures" => [
        %{"keyid" => R5e.SignerProvider.key_id(), "sig" => Base.encode64(sig)}
      ]
    }
  end
end
