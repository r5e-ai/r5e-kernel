defmodule R5e.Request do
  @moduledoc """
  The signed request object and its envelope (spec 011 contract §1).

  A request is eight keys of canonical JSON (§8):

      { "origin": "sha256:<64 hex>", "actor": "<key id>",
        "target": { "group", "version", "kind", "name": <string|null> },
        "specAddress": "sha256:<64 hex>",
        "derivedFrom": "bytes:sha256:<64 hex>" | null,
        "authority": [ "event:sha256:<64 hex>", … ],
        "nonce": "<base64 of 16 bytes>", "expires": "<instant>" }

  **All eight are present, always** — a nullable one carries `null`. A
  missing key, an extra key, or a mistyped one is a form error, and a form
  error is `authenticate: malformed envelope`: unattributable, not an act,
  not recorded (§2, §12). The list is closed so that what a signature
  covers is fixed: a request whose shape could vary is a signature over an
  unknown set of claims.

  The envelope is DSSE with the key material carried on it:

      { "payloadType": "application/vnd.r5e.admission-request+json;v=1",
        "payload": "<base64 of the request bytes>",
        "signatures": [ {"keyid", "sig"}, … ],
        "publicKeys":  [ {"keyid", "algorithm", "bytes"}, … ] }

  One or two signatures; every signature's `keyid` has exactly one
  `publicKeys` entry, and that keyid **equals** `keyId(algorithm, bytes)`
  (§0) — so the id is not a label the submitter chose, it is a
  derivation anyone repeats. Keyid *distinctness* is a Kind property, not
  an envelope one, and is checked a stage later at `validateStructure`.

  The payload bytes must themselves be canonical: `decode/1` re-encodes
  the parsed object and refuses anything that does not round-trip. A
  non-canonical encoding of the same eight keys would hash differently
  while claiming the same content, and the record's job is to be one
  thing.

  `sign/3` is the writer's side, shared by bootstrap, the retention
  sweeper, the conformance-vector runner and (later) the fold — one
  implementation, so nothing in this repository can sign a shape the gate
  would refuse.
  """

  @payload_type "application/vnd.r5e.admission-request+json;v=1"

  @envelope_keys ~w(payloadType payload signatures publicKeys)
  @request_keys ~w(origin actor target specAddress derivedFrom authority nonce expires)
  @target_keys ~w(group version kind name)

  @max_authority 16
  @nonce_bytes 16

  @doc "The DSSE payload type every admission request is signed under."
  def payload_type, do: @payload_type

  @doc "The eight request-object keys, in the contract's order."
  def request_keys, do: @request_keys

  # -- reading -----------------------------------------------------------

  @doc """
  Check an inbound envelope's form and decode it (§1). `{:ok, decoded}`
  where `decoded` carries

      %{envelope:, request:, payload_bytes:, signers: [key id],
        public_keys: %{key id => %{algorithm:, bytes:, base64:}}}

  or `{:error, reason}` — every one of which is
  `authenticate: malformed envelope`. Signatures are *not* verified here;
  that is `verify/1`, because the contract orders the two refusals and
  gives them different names.
  """
  @spec decode(term()) :: {:ok, map()} | {:error, String.t()}
  def decode(envelope) when is_map(envelope) do
    with :ok <- exact_keys(envelope, @envelope_keys, "envelope"),
         :ok <- payload_type(envelope["payloadType"]),
         {:ok, payload_bytes} <- base64(envelope["payload"], "payload"),
         {:ok, public_keys} <- public_keys(envelope["publicKeys"]),
         {:ok, signers} <- signatures(envelope["signatures"], public_keys),
         {:ok, request} <- request_object(payload_bytes) do
      {:ok,
       %{
         envelope: envelope,
         request: request,
         payload_bytes: payload_bytes,
         signers: signers,
         public_keys: public_keys
       }}
    end
  end

  def decode(_envelope), do: {:error, "the envelope must be a JSON object"}

  @doc """
  Verify every signature on a decoded envelope under §7's ed25519
  profile. `:ok`, or `{:error, reason}` — `authenticate: signature
  invalid`, which is also unattributable and also not recorded.
  """
  @spec verify(map()) :: :ok | {:error, String.t()}
  def verify(%{envelope: envelope, payload_bytes: payload_bytes, public_keys: public_keys}) do
    message = R5e.DSSE.pae(@payload_type, payload_bytes)

    envelope["signatures"]
    |> Enum.with_index(1)
    |> Enum.reduce_while(:ok, fn {%{"keyid" => keyid, "sig" => sig}, position}, _ ->
      {:ok, signature} = RecurseVerify.DSSE.decode64(sig)
      %{bytes: key} = Map.fetch!(public_keys, keyid)

      if RecurseVerify.DSSE.verify_ed25519(message, signature, key),
        do: {:cont, :ok},
        else: {:halt, {:error, "signature #{position} (#{keyid}) does not verify"}}
    end)
  end

  # -- envelope form -----------------------------------------------------

  defp payload_type(@payload_type), do: :ok

  defp payload_type(other),
    do: {:error, "payloadType must be #{inspect(@payload_type)}, got #{inspect(other)}"}

  defp public_keys(list) when is_list(list) and list != [] do
    Enum.reduce_while(list, {:ok, %{}}, fn entry, {:ok, acc} ->
      case public_key(entry, acc) do
        {:ok, keyid, value} -> {:cont, {:ok, Map.put(acc, keyid, value)}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp public_keys(other),
    do: {:error, "publicKeys must be a non-empty array, got #{inspect(other)}"}

  defp public_key(entry, seen) when is_map(entry) do
    with :ok <- exact_keys(entry, ~w(keyid algorithm bytes), "a publicKeys entry"),
         {:ok, spec} <- registry(entry["algorithm"]),
         {:ok, bytes} <- base64(entry["bytes"], "a publicKeys entry's bytes"),
         :ok <- key_length(bytes, spec, entry["algorithm"]),
         {:ok, derived} <- RecurseVerify.DSSE.key_id(entry["algorithm"], bytes),
         :ok <- same_keyid(entry["keyid"], derived),
         :ok <- unseen(seen, entry["keyid"]) do
      {:ok, derived, %{algorithm: entry["algorithm"], bytes: bytes, base64: entry["bytes"]}}
    end
  end

  defp public_key(other, _seen),
    do: {:error, "each publicKeys entry must be an object, got #{inspect(other)}"}

  defp registry(algorithm) do
    case RecurseVerify.DSSE.algorithm(algorithm) do
      {:ok, spec} -> {:ok, spec}
      :error -> {:error, "unknown algorithm #{inspect(algorithm)} (§0 registry v1: ed25519)"}
    end
  end

  defp key_length(bytes, %{public_key_bytes: size}, algorithm) do
    if byte_size(bytes) == size,
      do: :ok,
      else: {:error, "an #{algorithm} public key is #{size} bytes, got #{byte_size(bytes)}"}
  end

  defp same_keyid(keyid, derived) when keyid == derived, do: :ok

  defp same_keyid(keyid, derived),
    do:
      {:error,
       "keyid #{inspect(keyid)} is not the key id of the bytes beside it (#{inspect(derived)})"}

  defp unseen(seen, keyid) do
    if Map.has_key?(seen, keyid),
      do: {:error, "publicKeys carries #{inspect(keyid)} twice"},
      else: :ok
  end

  defp signatures(list, public_keys) when is_list(list) and length(list) in 1..2 do
    Enum.reduce_while(list, {:ok, []}, fn entry, {:ok, acc} ->
      case signature(entry, public_keys) do
        {:ok, keyid} -> {:cont, {:ok, acc ++ [keyid]}}
        {:error, _} = error -> {:halt, error}
      end
    end)
  end

  defp signatures(list, _public_keys) when is_list(list),
    do: {:error, "an envelope carries 1 or 2 signatures, got #{length(list)}"}

  defp signatures(other, _public_keys),
    do: {:error, "signatures must be an array, got #{inspect(other)}"}

  defp signature(entry, public_keys) when is_map(entry) do
    with :ok <- exact_keys(entry, ~w(keyid sig), "a signatures entry"),
         {:ok, sig} <- base64(entry["sig"], "a signature"),
         :ok <- signature_length(sig),
         :ok <- known_key(public_keys, entry["keyid"]) do
      {:ok, entry["keyid"]}
    end
  end

  defp signature(other, _public_keys),
    do: {:error, "each signatures entry must be an object, got #{inspect(other)}"}

  defp signature_length(sig) when byte_size(sig) == 64, do: :ok

  defp signature_length(sig),
    do: {:error, "an ed25519 signature is 64 bytes, got #{byte_size(sig)}"}

  defp known_key(public_keys, keyid) do
    if is_binary(keyid) and Map.has_key?(public_keys, keyid),
      do: :ok,
      else: {:error, "no publicKeys entry for signature keyid #{inspect(keyid)}"}
  end

  # -- request-object form -----------------------------------------------

  defp request_object(payload_bytes) do
    with {:ok, decoded} <- decode_canonical(payload_bytes),
         :ok <- must_be_object(decoded),
         :ok <- exact_keys(decoded, @request_keys, "the request object"),
         :ok <- address(decoded["origin"], "sha256:", "origin"),
         :ok <- actor(decoded["actor"]),
         :ok <- target(decoded["target"]),
         :ok <- address(decoded["specAddress"], "sha256:", "specAddress"),
         :ok <- derived_from(decoded["derivedFrom"]),
         :ok <- authority(decoded["authority"]),
         :ok <- nonce(decoded["nonce"]),
         :ok <- expires(decoded["expires"]) do
      {:ok, decoded}
    end
  end

  # §8 both ways: the bytes must parse *and* be what this encoder would
  # have written. A signature over a non-canonical encoding of the same
  # eight keys is a signature over a second spelling of the record.
  defp decode_canonical(bytes) do
    case R5e.Canonical.decode_json(bytes) do
      {:ok, decoded} ->
        if R5e.Canonical.encode(decoded) == bytes,
          do: {:ok, decoded},
          else: {:error, "the payload bytes are not the canonical encoding (§8) of their content"}

      {:error, reason} ->
        {:error, "the payload is not canonical JSON: #{reason}"}
    end
  end

  defp must_be_object(decoded) when is_map(decoded), do: :ok
  defp must_be_object(_decoded), do: {:error, "the request object must be a JSON object"}

  defp actor(id) do
    if RecurseVerify.DSSE.key_id?(id),
      do: :ok,
      else: {:error, "actor must be a key id, got #{inspect(id)}"}
  end

  defp target(t) when is_map(t) do
    with :ok <- exact_keys(t, @target_keys, "target") do
      cond do
        not Enum.all?(~w(group version kind), &non_empty_string?(t[&1])) ->
          {:error, "target group, version and kind must be non-empty strings"}

        not (is_nil(t["name"]) or non_empty_string?(t["name"])) ->
          {:error, "target name must be a string or null, got #{inspect(t["name"])}"}

        true ->
          :ok
      end
    end
  end

  defp target(other), do: {:error, "target must be an object, got #{inspect(other)}"}

  defp derived_from(nil), do: :ok
  defp derived_from(value), do: address(value, "bytes:sha256:", "derivedFrom")

  defp authority(list) when is_list(list) do
    cond do
      length(list) > @max_authority ->
        {:error, "authority carries #{length(list)} entries; the limit is #{@max_authority}"}

      Enum.uniq(list) != list ->
        {:error, "authority carries a duplicate entry"}

      not Enum.all?(list, &event_ref?/1) ->
        {:error, "every authority entry must be event:sha256:<64 lowercase hex>"}

      true ->
        :ok
    end
  end

  defp authority(other), do: {:error, "authority must be an array, got #{inspect(other)}"}

  defp nonce(value) do
    case RecurseVerify.DSSE.decode64(value) do
      {:ok, bytes} when byte_size(bytes) == @nonce_bytes -> :ok
      _ -> {:error, "nonce must be canonical base64 of #{@nonce_bytes} bytes"}
    end
  end

  defp expires(value) do
    case RecurseVerify.Instant.parse(value) do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, "expires: #{reason}"}
    end
  end

  defp event_ref?(value),
    do: is_binary(value) and String.match?(value, ~r/\Aevent:sha256:[0-9a-f]{64}\z/)

  defp address(value, prefix, where) do
    if is_binary(value) and
         String.match?(value, ~r/\A#{Regex.escape(prefix)}[0-9a-f]{64}\z/) do
      :ok
    else
      {:error, "#{where} must be #{prefix}<64 lowercase hex>, got #{inspect(value)}"}
    end
  end

  defp non_empty_string?(value), do: is_binary(value) and value != ""

  defp base64(value, where) do
    case RecurseVerify.DSSE.decode64(value) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> {:error, "#{where} must be canonical padded base64, got #{inspect(value)}"}
    end
  end

  defp exact_keys(map, keys, where) when is_map(map) do
    present = MapSet.new(Map.keys(map))
    wanted = MapSet.new(keys)

    cond do
      extra = Enum.find(Enum.sort(present), &(&1 not in wanted)) ->
        {:error, "#{where} carries the undeclared key #{inspect(extra)}"}

      missing = Enum.find(Enum.sort(keys), &(not MapSet.member?(present, &1))) ->
        {:error, "#{where} is missing the key #{inspect(missing)}"}

      true ->
        :ok
    end
  end

  defp exact_keys(other, _keys, where),
    do: {:error, "#{where} must be a JSON object, got #{inspect(other)}"}

  # -- writing -----------------------------------------------------------

  @doc """
  Build and sign an admission request (§1). `fields` names the act:

      %{target: %{"group" =>, "version" =>, "kind" =>, "name" =>},
        spec: map(),                       # or spec_address:
        derived_from: nil | address,
        authority: [event ref]}

  `keys` is the signers, in order — `:node` for this node's own signing
  key, or `%{public:, private:, algorithm:}` for a keypair held in
  memory. `opts` overrides `:origin`, `:nonce` and `:expires`, which
  otherwise come from this chain's origin, 16 fresh random bytes, and the
  clock plus one hour.

  Returns the envelope map, ready to hand to `R5e.Admission.admit/1`
  beside the spec.
  """
  @spec sign(map(), [term()], keyword()) :: map()
  def sign(fields, keys, opts \\ []) do
    request = build(fields, Keyword.put_new(opts, :actor, key_id(hd(keys))))
    envelope(request, keys)
  end

  @doc "The request object `sign/3` would sign, without signing it."
  @spec build(map(), keyword()) :: map()
  def build(fields, opts \\ []) do
    %{
      "origin" => Keyword.get_lazy(opts, :origin, &R5e.Origin.current/0),
      "actor" => Keyword.fetch!(opts, :actor),
      "target" => Map.take(fields[:target] || %{}, @target_keys),
      "specAddress" =>
        Keyword.get_lazy(opts, :spec_address, fn -> R5e.CAS.spec_address(fields[:spec]) end),
      "derivedFrom" => fields[:derived_from],
      "authority" => fields[:authority] || [],
      "nonce" => Keyword.get_lazy(opts, :nonce, &fresh_nonce/0),
      "expires" => Keyword.get_lazy(opts, :expires, fn -> R5e.Clock.in_seconds(3600) end)
    }
  end

  @doc "Sixteen fresh random bytes, base64 — a nonce (§1)."
  @spec fresh_nonce() :: String.t()
  def fresh_nonce, do: Base.encode64(:crypto.strong_rand_bytes(@nonce_bytes))

  @doc """
  Wrap an already-built request object in a signed envelope. Separate
  from `build/2` so a conformance vector can substitute the payload bytes
  after signing and watch the gate refuse them.
  """
  @spec envelope(map(), [term()]) :: map()
  def envelope(request, keys) do
    payload = R5e.Canonical.encode(request)
    message = R5e.DSSE.pae(@payload_type, payload)

    %{
      "payloadType" => @payload_type,
      "payload" => Base.encode64(payload),
      "signatures" =>
        for key <- keys do
          %{"keyid" => key_id(key), "sig" => Base.encode64(sign_bytes(key, message))}
        end,
      "publicKeys" =>
        keys
        |> Enum.uniq_by(&key_id/1)
        |> Enum.map(fn key ->
          %{
            "keyid" => key_id(key),
            "algorithm" => algorithm(key),
            "bytes" => Base.encode64(public_key(key))
          }
        end)
    }
  end

  @doc "The §0 key id of a signer spec (`:node` or a keypair map)."
  @spec key_id(term()) :: String.t()
  def key_id(key), do: RecurseVerify.DSSE.key_id!(algorithm(key), public_key(key))

  @doc "The raw public key bytes of a signer spec."
  @spec public_key(term()) :: binary()
  def public_key(:node), do: R5e.SignerProvider.public_key()
  def public_key(%{public: public}), do: public

  defp algorithm(:node), do: "ed25519"
  defp algorithm(%{} = key), do: Map.get(key, :algorithm, "ed25519")

  defp sign_bytes(:node, message), do: R5e.SignerProvider.sign(message)

  defp sign_bytes(%{private: private}, message),
    do: :crypto.sign(:eddsa, :none, message, [private, :ed25519])

  @doc "Generate a keypair in the shape `sign/3` takes. Bootstrap and tests use it."
  @spec generate_key() :: %{public: binary(), private: binary(), algorithm: String.t()}
  def generate_key do
    {public, private} = :crypto.generate_key(:eddsa, :ed25519)
    %{public: public, private: private, algorithm: "ed25519"}
  end
end
