defmodule R5e.HTTP.Router do
  @moduledoc """
  The meta-API over HTTP (Plug + Bandit, JSON only).

      POST /apis/:group/:version/:kind           admit an instance
      GET  /apis                                 list admitted Kinds
      GET  /apis/:group/:version/:kind           list instances
      GET  /apis/:group/:version/:kind/*name     fetch (?resolution=refs|deep)
      GET  /events                               the chain
      POST /export                               write an offline bundle
      PUT  /cas                                  admit raw bytes (§5)
      GET  /cas/*address                         fetch an admitted object

  A name may contain `/` (schema-lite v2 §2), so the single-instance route
  takes a **glob tail**: everything after `group/version/Kind` is the name.
  `/apis/core.r5e.io/v1/KindDefinition/gateway.r5e.io/v1alpha1/ToolCall`
  works unencoded, and the percent-encoded form works exactly as before.

  The admission body is `{"envelope": {...}, "spec": {...}, "name"?: ...}`
  (spec 011 §1). `envelope` is the DSSE envelope over the signed request
  object; `spec` is the bytes the signature's `specAddress` covers; `name`
  is how the caller addresses the instance and must equal the signed
  `target.name` (absent ⇔ null). The route must equal the signed
  `target.{group,version,kind}`. `derivedFrom` moved **inside** the signed
  request — it is a claim about the act, so it is signed like the rest of
  it, and a body key would be an unsigned one.

  There are no actor headers. Identity is the signature or it is nothing.

  ## `PUT /cas` (spec/05 §5, spec 011 §1)

  `PUT /cas` is **an admission of a `core.r5e.io/v1/CasObject`**, not a
  file upload that happens to be logged: `R5e.CAS.admit/3` builds the spec
  from the bytes and runs the whole pipeline. The envelope arrives
  base64-encoded in the `x-r5e-request` header (at most 8 KiB), because
  the body is the object and cannot also carry the request. On a grant,
  `201` with the receipt plus `{"address", "size"}`; on a denial, `403`
  and nothing was written.

  The JSON parser is skipped on this route: a body that must be hashed
  exactly as sent cannot be parsed and re-encoded first, and a `PUT /cas`
  of JSON is a normal thing to do.

  **Over the ceiling → `413`, with an error and no receipt.** The body is
  measured while it is read and the read is abandoned at
  `config :r5e, cas_max_bytes` (default 16 MiB), so an oversized request
  never reaches the gate. There is no receipt because there was no
  admission — nothing was submitted, decided or recorded, and a receipt
  for an act that did not happen would be worse than none. The response
  says the limit and the route it applies to, so a caller can tell a
  rejected act from an unsent one.

  ## `GET /cas/*address`

  Returns the object at `bytes:sha256:<hex>` (the bare `sha256:<hex>` form
  is accepted too — §6 says both name the same tree) with the `mediaType`
  the `CasObject` admission recorded, or `application/octet-stream` when
  none did: an object put before §5, or a kernel-derived one, has no
  recorded label and is not given an invented one. `404` when the
  deployment holds no such object.
  """

  use Plug.Router

  @default_cas_max_bytes 16 * 1024 * 1024
  @request_header "x-r5e-request"
  @request_header_max 8 * 1024

  @parsers Plug.Parsers.init(
             parsers: [:json],
             json_decoder: Jason,
             pass: ["application/json"]
           )

  plug(:parse_unless_cas)
  plug(:match)
  plug(:dispatch)

  # `PUT /cas` reads its own body, raw and unparsed, so the bytes admitted
  # are the bytes sent. Every other route parses JSON exactly as before.
  defp parse_unless_cas(%Plug.Conn{method: "PUT", path_info: ["cas"]} = conn, _opts), do: conn
  defp parse_unless_cas(conn, _opts), do: Plug.Parsers.call(conn, @parsers)

  put "/cas" do
    limit = Application.get_env(:r5e, :cas_max_bytes, @default_cas_max_bytes)

    case read_body_within(conn, limit) do
      {:ok, body, conn} ->
        case request_header(conn) do
          {:ok, envelope} ->
            case R5e.CAS.admit(envelope, body, header(conn, "content-type")) do
              {:ok, receipt, address, size} ->
                json(conn, 201, Map.merge(receipt, %{"address" => address, "size" => size}))

              {:denied, receipt} ->
                json(conn, 403, receipt)
            end

          {:error, message} ->
            json(conn, 400, %{"error" => message})
        end

      {:too_large, conn} ->
        json(conn, 413, %{
          "error" =>
            "body exceeds this deployment's PUT /cas ceiling of #{limit} bytes; nothing was " <>
              "submitted to the admission gate, so there is no receipt and no record of an act",
          "limit" => limit
        })

      {:error, reason, conn} ->
        json(conn, 400, %{"error" => "could not read the request body: #{inspect(reason)}"})
    end
  end

  get "/cas/*address" do
    address = Enum.join(address, "/")

    case R5e.CAS.get(address) do
      {:ok, bytes} ->
        conn
        # No charset appended: the label is served exactly as the
        # `CasObject` admission recorded it, because that is the label
        # somebody put on the record and this route is not entitled to
        # refine it.
        |> put_resp_content_type(media_type(address), nil)
        |> send_resp(200, bytes)

      {:error, _} ->
        json(conn, 404, %{"error" => "no object at #{address} in this deployment's CAS"})
    end
  end

  post "/apis/:group/:version/:kind" do
    body = conn.body_params

    request = %{
      envelope: body["envelope"],
      group: group,
      version: version,
      kind: kind,
      name: body["name"],
      spec: body["spec"] || %{}
    }

    case R5e.Admission.admit(request) do
      {:ok, receipt} -> json(conn, 201, receipt)
      {:denied, receipt} -> json(conn, 403, receipt)
    end
  end

  get "/apis" do
    kinds =
      for kind <- R5e.KindRegistry.list() do
        kind
        |> R5e.Kind.to_map()
        |> Map.put("specAddress", kind_spec_address(kind))
      end

    json(conn, 200, %{"kinds" => kinds})
  end

  get "/apis/:group/:version/:kind" do
    instances = R5e.ResourceStore.list(group, version, kind)
    json(conn, 200, %{"items" => instances})
  end

  get "/apis/:group/:version/:kind/*name" do
    name = Enum.join(name, "/")

    resolution =
      case conn.query_params["resolution"] do
        "deep" -> :deep
        _ -> :refs
      end

    case R5e.ResourceStore.get(group, version, kind, name, resolution) do
      {:ok, entry, lineage} when resolution == :deep ->
        json(conn, 200, Map.merge(entry, %{"resolution" => "deep", "lineage" => lineage}))

      {:ok, entry, _} ->
        json(conn, 200, Map.put(entry, "resolution", "refs"))

      {:error, :not_found} ->
        json(conn, 404, %{"error" => "no admitted instance #{group}/#{version}/#{kind}/#{name}"})
    end
  end

  get "/events" do
    json(conn, 200, %{"events" => R5e.Log.events()})
  end

  get "/proof/inclusion" do
    with {:ok, seq} <- int_param(conn, "seq"),
         leaves = R5e.Log.leaves(),
         {:ok, tree_size} <- int_param(conn, "treeSize", length(leaves)),
         :ok <- bounds(seq >= 1 and seq <= tree_size and tree_size <= length(leaves)),
         prefix = Enum.take(leaves, tree_size),
         {:ok, proof} <- RecurseVerify.Merkle.inclusion_proof(prefix, seq - 1) do
      json(conn, 200, %{
        "seq" => seq,
        "treeSize" => tree_size,
        "leaf" => Enum.at(leaves, seq - 1),
        "proof" => Enum.map(proof, &RecurseVerify.Merkle.hex/1),
        "root" => RecurseVerify.Merkle.hex(RecurseVerify.Merkle.root(prefix))
      })
    else
      _ ->
        json(conn, 400, %{
          "error" =>
            "usage: /proof/inclusion?seq=N[&treeSize=M], 1 <= N <= M <= current tree size"
        })
    end
  end

  get "/proof/consistency" do
    leaves = R5e.Log.leaves()

    with {:ok, from} <- int_param(conn, "from"),
         {:ok, to} <- int_param(conn, "to", length(leaves)),
         :ok <- bounds(from >= 1 and from <= to and to <= length(leaves)),
         {:ok, proof} <- RecurseVerify.Merkle.consistency_proof(leaves, from, to) do
      json(conn, 200, %{
        "from" => from,
        "to" => to,
        "proof" => Enum.map(proof, &RecurseVerify.Merkle.hex/1),
        "fromRoot" =>
          RecurseVerify.Merkle.hex(RecurseVerify.Merkle.root(Enum.take(leaves, from))),
        "toRoot" => RecurseVerify.Merkle.hex(RecurseVerify.Merkle.root(Enum.take(leaves, to)))
      })
    else
      _ ->
        json(conn, 400, %{
          "error" => "usage: /proof/consistency?from=N[&to=M], 1 <= N <= M <= current tree size"
        })
    end
  end

  post "/export" do
    case R5e.Export.run(conn.body_params["path"]) do
      {:ok, dest, manifest} ->
        json(conn, 201, %{"bundle" => Path.expand(dest), "manifest" => manifest})

      {:error, reason} ->
        json(conn, 500, %{"error" => inspect(reason)})
    end
  end

  match _ do
    json(conn, 404, %{"error" => "no such route"})
  end

  defp json(conn, status, body) do
    conn
    |> put_resp_content_type("application/json")
    |> send_resp(status, Jason.encode!(body))
  end

  # The address of the admitted KindDefinition that put this Kind in the
  # registry, so a consumer of `GET /apis` can pin the definition it read.
  # `to_map/1` itself stays untouched: it is also the export's `kinds/*.json`
  # and the verifier reads that file.
  defp kind_spec_address(kind) do
    case R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", R5e.Kind.name(kind)) do
      # nil during the bootstrap pre-registration window, before the
      # meta-Kind's own admission.
      {:ok, entry, _lineage} -> entry["specAddress"]
      {:error, :not_found} -> nil
    end
  end

  # Read the body in chunks, stopping the moment the accumulated size
  # passes the ceiling: an oversized request is refused without ever
  # buffering all of it, and without reaching the gate.
  defp read_body_within(conn, limit, acc \\ "") do
    case Plug.Conn.read_body(conn, length: 1_000_000) do
      {:ok, chunk, conn} ->
        acc = acc <> chunk
        if byte_size(acc) > limit, do: {:too_large, conn}, else: {:ok, acc, conn}

      {:more, chunk, conn} ->
        acc = acc <> chunk

        if byte_size(acc) > limit,
          do: {:too_large, conn},
          else: read_body_within(conn, limit, acc)

      {:error, reason} ->
        {:error, reason, conn}
    end
  end

  # The label a `CasObject` admission recorded, or none. `content-type`
  # arrives with parameters (`application/json; charset=utf-8`) and is
  # recorded verbatim, so it is served back verbatim.
  defp media_type(address) do
    case R5e.RefIndex.cas_object(address) do
      {:ok, %{"mediaType" => type}} when is_binary(type) and type != "" -> type
      _ -> "application/octet-stream"
    end
  end

  # The envelope rides in a header because the body is the object. The
  # ceiling is the contract's 8 KiB, and it is refused *here* rather than
  # at the gate: an oversized header is a transport error, not an act.
  defp request_header(conn) do
    case header(conn, @request_header) do
      nil ->
        {:error, "PUT /cas requires the signed request envelope in #{@request_header}"}

      value when byte_size(value) > @request_header_max ->
        {:error, "#{@request_header} exceeds #{@request_header_max} bytes"}

      value ->
        with {:ok, bytes} <- decode_header(value),
             {:ok, envelope} <- Jason.decode(bytes) do
          {:ok, envelope}
        else
          _ -> {:error, "#{@request_header} must be base64 of the envelope JSON"}
        end
    end
  end

  defp decode_header(value) do
    case Base.decode64(value) do
      {:ok, bytes} -> {:ok, bytes}
      :error -> :error
    end
  end

  defp header(conn, name) do
    case get_req_header(conn, name) do
      [value | _] -> value
      [] -> nil
    end
  end

  defp int_param(conn, name, default \\ nil) do
    case conn.query_params[name] do
      nil when default != nil -> {:ok, default}
      value when is_binary(value) -> parse_int(value)
      _ -> :error
    end
  end

  defp parse_int(value) do
    case Integer.parse(value) do
      {n, ""} -> {:ok, n}
      _ -> :error
    end
  end

  defp bounds(true), do: :ok
  defp bounds(false), do: :error
end
