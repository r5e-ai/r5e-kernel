defmodule R5e.HTTP.RouterTest do
  use ExUnit.Case, async: false

  import Plug.Test
  import Plug.Conn
  import R5e.TestHelpers

  @opts R5e.HTTP.Router.init([])

  defp request(method, path) do
    method |> conn(path) |> R5e.HTTP.Router.call(@opts)
  end

  defp body(conn), do: Jason.decode!(conn.resp_body)

  test "GET /apis carries each Kind's specAddress, matching the admitted KindDefinition" do
    spec = kind_spec(%{"kind" => "RouterProbe"})
    {:ok, receipt} = admit_kind(spec)

    kinds = request(:get, "/apis") |> body() |> Map.fetch!("kinds")
    entry = Enum.find(kinds, &(&1["kind"] == "RouterProbe"))

    name = "#{spec["group"]}/#{spec["version"]}/RouterProbe"
    {:ok, stored, _} = R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", name)

    assert entry["specAddress"] == stored["specAddress"]
    assert entry["specAddress"] == receipt["specAddress"]

    # Every registered Kind answers, and the meta-Kind is admitted too.
    meta = Enum.find(kinds, &(&1["kind"] == "KindDefinition"))
    assert meta["specAddress"] =~ ~r/^sha256:/
  end

  test "a slash-bearing KindDefinition name is reachable percent-encoded" do
    {:ok, _} =
      admit_kind(
        kind_spec(%{"group" => "gateway.r5e.io", "version" => "v1alpha1", "kind" => "ToolCall"})
      )

    name = "gateway.r5e.io/v1alpha1/ToolCall"

    conn =
      request(:get, "/apis/core.r5e.io/v1/KindDefinition/gateway.r5e.io%2Fv1alpha1%2FToolCall")

    assert conn.status == 200
    entry = body(conn)

    assert entry["name"] == name
    assert entry["spec"]["kind"] == "ToolCall"
    assert entry["resolution"] == "refs"
  end

  test "a slash-bearing name is reachable unencoded, as a glob tail" do
    {:ok, _} =
      admit_kind(
        kind_spec(%{"group" => "gateway.r5e.io", "version" => "v1alpha1", "kind" => "LlmCall"})
      )

    conn =
      request(:get, "/apis/core.r5e.io/v1/KindDefinition/gateway.r5e.io/v1alpha1/LlmCall")

    assert conn.status == 200
    entry = body(conn)
    assert entry["name"] == "gateway.r5e.io/v1alpha1/LlmCall"
    assert entry["spec"]["kind"] == "LlmCall"
  end

  test "GET /apis shows the v2 meta-Kind's naming mode and description" do
    kinds = request(:get, "/apis") |> body() |> Map.fetch!("kinds")
    meta = Enum.find(kinds, &(&1["kind"] == "KindDefinition"))

    assert meta["naming"] == %{"mode" => "path"}
    assert meta["substrate"] == "resource"
    assert meta["description"] =~ "meta-Kind"
    assert meta["schema"]["properties"]["naming"]["required"] == ["mode"]
  end

  test "POST carries the signed derivedFrom through to the receipt" do
    # C8: the envelope address must be backed by a CasObject admission.
    # Spec 011 §1: `derivedFrom` is inside the signed request now, so the
    # body carries only the envelope, the spec, and (here, none) a name.
    address = put_object("the document RouterEnvelope was derived from")
    spec = kind_spec(%{"kind" => "RouterEnvelope"})

    envelope =
      R5e.Request.sign(
        %{
          target: %{
            "group" => "core.r5e.io",
            "version" => "v1",
            "kind" => "KindDefinition",
            "name" => nil
          },
          spec: spec,
          derived_from: address
        },
        [key_for("person:you")]
      )

    conn =
      :post
      |> conn(
        "/apis/core.r5e.io/v1/KindDefinition",
        Jason.encode!(%{"envelope" => envelope, "spec" => spec})
      )
      |> put_req_header("content-type", "application/json")
      |> R5e.HTTP.Router.call(@opts)

    assert conn.status == 201
    receipt = body(conn)
    assert receipt["derivedFrom"] == address
    assert receipt["identity"] == "signed"
    assert receipt["signers"] == [key_id_for("person:you")]
    assert receipt["eventRef"] =~ ~r/^event:sha256:[0-9a-f]{64}$/
  end

  test "POST with a route that is not the signed target is a target mismatch" do
    spec = kind_spec(%{"kind" => "RouterMisrouted"})

    envelope =
      R5e.Request.sign(
        %{
          target: %{
            "group" => "core.r5e.io",
            "version" => "v1",
            "kind" => "KindDefinition",
            "name" => nil
          },
          spec: spec
        },
        [key_for("person:you")]
      )

    conn =
      :post
      |> conn(
        "/apis/core.r5e.io/v1/CasObject",
        Jason.encode!(%{"envelope" => envelope, "spec" => spec})
      )
      |> put_req_header("content-type", "application/json")
      |> R5e.HTTP.Router.call(@opts)

    assert conn.status == 403
    assert body(conn)["reason"] =~ "validateStructure: target mismatch"
  end

  # -- PUT/GET /cas (spec/05 §5) -----------------------------------------

  # Spec 011 §1: the envelope rides in `x-r5e-request` because the body is
  # the object. `sign_body` is the bytes whose spec was signed, so a test
  # can sign one body and submit another.
  defp put_cas(body, headers \\ [], opts \\ []) do
    media_type = headers[:"content-type"]
    signed_body = Keyword.get(opts, :sign_body, body)

    request_header =
      Keyword.get_lazy(opts, :request_header, fn ->
        spec = R5e.CAS.object_spec(signed_body, media_type)

        envelope =
          R5e.Request.sign(
            %{
              target: %{
                "group" => "core.r5e.io",
                "version" => "v1",
                "kind" => "CasObject",
                "name" => nil
              },
              spec: spec
            },
            [key_for("person:you")]
          )

        Base.encode64(Jason.encode!(envelope))
      end)

    headers =
      if request_header == nil,
        do: headers,
        else: Keyword.put(headers, :"x-r5e-request", request_header)

    Enum.reduce(headers, conn(:put, "/cas", body), fn {name, value}, conn ->
      put_req_header(conn, to_string(name), value)
    end)
    |> R5e.HTTP.Router.call(@opts)
  end

  test "PUT /cas is an admission: 201 with the receipt plus the address and size" do
    bytes = "raw bytes over HTTP #{System.unique_integer([:positive])}"
    conn = put_cas(bytes, [{:"content-type", "text/plain"}])

    assert conn.status == 201
    receipt = body(conn)

    assert receipt["outcome"] == "admitted"
    assert receipt["address"] == "bytes:" <> R5e.Canonical.hash_bytes(bytes)
    assert receipt["size"] == byte_size(bytes)
    assert receipt["eventRef"] =~ ~r/^event:sha256:[0-9a-f]{64}$/

    # The bytes are the admit step: they are on disk because the
    # admission was granted, and the CasObject spec the kernel built
    # records what it hashed rather than what the caller claimed.
    assert R5e.CAS.exists?(receipt["address"])
    payload = payload_of(receipt)
    assert payload["target"]["kind"] == "CasObject"
    assert payload["spec"]["class"] == "raw"
    assert payload["spec"]["size"] == byte_size(bytes)
    assert payload["spec"]["mediaType"] == "text/plain"

    # GET returns the bytes under the recorded label.
    get = request(:get, "/cas/" <> receipt["address"])
    assert get.status == 200
    assert get.resp_body == bytes
    assert get_resp_header(get, "content-type") == ["text/plain"]
  end

  test "PUT /cas of a JSON body admits the bytes as sent, unparsed" do
    bytes = ~s({"n":#{System.unique_integer([:positive])},"note":"not re-encoded"})
    conn = put_cas(bytes, [{:"content-type", "application/json"}])

    assert conn.status == 201
    assert body(conn)["address"] == "bytes:" <> R5e.Canonical.hash_bytes(bytes)
    assert {:ok, ^bytes} = R5e.CAS.get(body(conn)["address"])
  end

  test "PUT /cas with no signed request never reaches the gate, and writes nothing" do
    bytes = "unattributed #{System.unique_integer([:positive])}"
    before = length(R5e.Log.events())

    conn = conn(:put, "/cas", bytes) |> R5e.HTTP.Router.call(@opts)

    # A missing envelope is a transport error, not an act: 400, no
    # receipt, and nothing on the chain to say somebody asked.
    assert conn.status == 400
    assert body(conn)["error"] =~ "x-r5e-request"
    assert length(R5e.Log.events()) == before
    refute R5e.CAS.exists?("bytes:" <> R5e.Canonical.hash_bytes(bytes))
  end

  test "PUT /cas whose body is not the bytes the request signed is a spec address mismatch" do
    bytes = "submitted #{System.unique_integer([:positive])}"
    conn = put_cas(bytes, [], sign_body: "signed something else")

    assert conn.status == 403
    assert body(conn)["reason"] =~ "validateStructure: spec address mismatch"
    refute R5e.CAS.exists?("bytes:" <> R5e.Canonical.hash_bytes(bytes))
  end

  test "PUT /cas records the trimmed content-type as the mediaType" do
    bytes = "trimmed #{System.unique_integer([:positive])}"
    conn = put_cas(bytes, [{:"content-type", "text/plain "}])

    assert conn.status == 201
    assert payload_of(body(conn))["spec"]["mediaType"] == "text/plain"
  end

  test "PUT /cas refuses a request header over the 8 KiB ceiling" do
    bytes = "oversized header #{System.unique_integer([:positive])}"
    conn = put_cas(bytes, [], request_header: String.duplicate("A", 8 * 1024 + 4))

    assert conn.status == 400
    assert body(conn)["error"] =~ "exceeds 8192 bytes"
  end

  test "PUT /cas of bytes already present is a new admission and no rewrite" do
    bytes = "twice #{System.unique_integer([:positive])}"

    first = put_cas(bytes) |> body()
    second = put_cas(bytes) |> body()

    assert first["address"] == second["address"]
    assert first["name"] == second["name"], "content naming: the same spec, the same name"
    refute first["eventRef"] == second["eventRef"], "a second put is a second act"

    # What a citation names is the admission that put the object there.
    assert {:ok, %{"eventRef" => ref, "admissions" => 2}} =
             R5e.RefIndex.cas_object(first["address"])

    assert ref == first["eventRef"]
  end

  test "PUT /cas over the ceiling is 413 with no receipt: nothing was submitted" do
    previous = Application.get_env(:r5e, :cas_max_bytes)
    Application.put_env(:r5e, :cas_max_bytes, 16)
    on_exit(fn -> Application.put_env(:r5e, :cas_max_bytes, previous) end)

    bytes = String.duplicate("x", 17)
    before = length(R5e.Log.events())
    conn = put_cas(bytes)

    assert conn.status == 413
    response = body(conn)
    assert response["limit"] == 16
    assert response["error"] =~ "there is no receipt"
    refute Map.has_key?(response, "outcome")

    # No act, so no record of one — not even a denial.
    assert length(R5e.Log.events()) == before
    refute R5e.CAS.exists?("bytes:" <> R5e.Canonical.hash_bytes(bytes))
  end

  test "PUT /cas exactly at the ceiling is admitted" do
    previous = Application.get_env(:r5e, :cas_max_bytes)
    Application.put_env(:r5e, :cas_max_bytes, 16)
    on_exit(fn -> Application.put_env(:r5e, :cas_max_bytes, previous) end)

    assert put_cas(String.duplicate("y", 16)).status == 201
  end

  test "GET /cas of an object with no recorded mediaType falls back, and 404s otherwise" do
    address = "bytes:" <> R5e.CAS.put("no label #{System.unique_integer([:positive])}")

    conn = request(:get, "/cas/" <> address)
    assert conn.status == 200
    assert get_resp_header(conn, "content-type") == ["application/octet-stream"]

    missing = request(:get, "/cas/bytes:sha256:" <> String.duplicate("ab", 32))
    assert missing.status == 404
    assert body(missing)["error"] =~ "no object at"
  end
end
