defmodule R5e.RetentionTest do
  @moduledoc """
  The retention sweeper (spec/05 §5) against a fresh kernel, with
  `cas_ttl_seconds: 0` so every admitted object is immediately old enough
  and what is left to decide is only the question the slice is about:
  does anything cite it.
  """

  use ExUnit.Case, async: false

  @actor %{"id" => "test:alice", "keyFingerprint" => "sha256:test-alice"}

  @cites %{
    "group" => "retention.r5e.io",
    "kind" => "Cites",
    "version" => "v1alpha1",
    "substrate" => "resource",
    "naming" => %{"mode" => "caller"},
    "schema" => %{
      "required" => [],
      "properties" => %{
        "blob" => %{"type" => "ref", "ref" => %{"bytes" => true}},
        "archived" => %{
          "type" => "ref",
          "ref" => %{"bytes" => true, "retention" => "public-record"}
        }
      },
      "additionalProperties" => false
    },
    "predicates" => []
  }

  defp with_ttl(seconds, fun) do
    R5e.Vectors.with_fresh_kernel(fn ->
      previous = Application.get_env(:r5e, :cas_ttl_seconds)
      Application.put_env(:r5e, :cas_ttl_seconds, seconds)

      try do
        fun.()
      after
        Application.put_env(:r5e, :cas_ttl_seconds, previous)
      end
    end)
  end

  defp put(bytes) do
    {:ok, _receipt, address, _size} = R5e.TestHelpers.cas_admit(@actor, bytes)
    address
  end

  defp cite(name, spec) do
    {:ok, _} = R5e.Vectors.admit_definition(@cites)

    {:ok, receipt} =
      R5e.TestHelpers.admit_request(%{
        actor: @actor,
        group: "retention.r5e.io",
        version: "v1alpha1",
        kind: "Cites",
        name: name,
        spec: spec
      })

    receipt
  end

  test "off by default: no TTL configured means the sweeper removes nothing" do
    with_ttl(nil, fn ->
      address = put("kept because nobody said otherwise")

      assert R5e.Retention.sweep() == %{
               ttl: nil,
               scanned: 0,
               expired: [],
               denied: [],
               retained: []
             }

      assert R5e.CAS.exists?(address)
    end)
  end

  test "an uncited object is expired: one CasExpired admission, then the bytes go" do
    with_ttl(0, fn ->
      address = put("nothing cites me")
      assert R5e.CAS.exists?(address)

      result = R5e.Retention.sweep()

      assert [{^address, event_ref}] = result.expired
      assert result.denied == []
      refute R5e.CAS.exists?(address), "the bytes are the admit step of the CasExpired"

      # The removal is on the chain, by the retention principal, and says
      # what it removed. An object that is gone can be asked who took it.
      payload = payload_of(event_ref)
      assert payload["target"]["kind"] == "CasExpired"
      assert payload["actor"]["id"] == R5e.Retention.actor()["id"]
      assert payload["spec"] == %{"address" => address}
      assert payload["outcome"] == "admitted"
    end)
  end

  test "a cited object is retained, and a direct CasExpired for it is denied" do
    with_ttl(0, fn ->
      address = put("something cites me")
      cite("c", %{"blob" => %{"$ref" => address}})

      result = R5e.Retention.sweep()

      assert result.expired == []
      assert result.retained == [address]
      assert R5e.CAS.exists?(address)

      # The sweeper declined to ask. Asking anyway is refused at
      # validateConstraints, and the refusal names the citing seq.
      {:denied, receipt} = expire(address)

      assert receipt["reason"] =~
               "validateConstraints: the object at #{address} is still cited by"

      assert receipt["reason"] =~ "(manifest at /blob)"
      assert R5e.CAS.exists?(address)
    end)
  end

  test "a public-record citation is refused as the stronger of the two refusals" do
    with_ttl(0, fn ->
      address = put("the public record")
      receipt = cite("c", %{"archived" => %{"$ref" => address}})

      assert R5e.Retention.sweep().expired == []

      {:denied, denial} = expire(address)

      assert denial["reason"] =~ "cited with retention \"public-record\""
      assert denial["reason"] =~ "seq #{receipt["seq"]}"
      assert denial["reason"] =~ "a public-record object is never expired"
      assert R5e.CAS.exists?(address)
    end)
  end

  test "a swept object is swept once: the index remembers it was expired" do
    with_ttl(0, fn ->
      address = put("transient")
      assert [{^address, _}] = R5e.Retention.sweep().expired

      second = R5e.Retention.sweep()
      assert second.expired == []
      assert R5e.RefIndex.expired?(address)
    end)
  end

  test "a denial's manifest counts as a citation: the record of an asking is a record" do
    with_ttl(0, fn ->
      address = put("cited only by a refusal")
      {:ok, _} = R5e.Vectors.admit_definition(@cites)

      previous = Application.get_env(:r5e, :policy)
      Application.put_env(:r5e, :policy, __MODULE__.DenyAll)
      on_exit(fn -> Application.put_env(:r5e, :policy, previous) end)

      {:denied, receipt} =
        R5e.TestHelpers.admit_request(%{
          actor: @actor,
          group: "retention.r5e.io",
          version: "v1alpha1",
          kind: "Cites",
          name: "d",
          spec: %{"blob" => %{"$ref" => address}}
        })

      Application.put_env(:r5e, :policy, previous)

      # The refusal resolved the ref before policy saw it, so the denial's
      # manifest names the object. §5 qualifies "admitted spec" and
      # "admitted specAddress" and does not qualify "resolution manifest":
      # expiring these bytes would leave the record of the asking citing
      # something that is gone.
      assert [%{"class" => "bytes", "value" => ^address}] = receipt["resolvedRefs"]
      assert R5e.Retention.sweep().retained == [address]
      assert R5e.CAS.exists?(address)
    end)
  end

  defmodule DenyAll do
    @moduledoc false
    @behaviour R5e.Policy

    @impl true
    def authorize(_request), do: {:deny, "nothing is permitted here", %{"engine" => "deny-all"}}
  end

  defp expire(address) do
    R5e.TestHelpers.admit_request(%{
      actor: R5e.Retention.actor(),
      authority: R5e.Retention.authority(),
      group: "core.r5e.io",
      version: "v1",
      kind: "CasExpired",
      name: nil,
      spec: %{"address" => address}
    })
  end

  defp payload_of("event:" <> hash) do
    event = Enum.find(R5e.Log.events(), &(&1["hash"] == hash))
    {:ok, bytes} = R5e.CAS.get(event["payload"])
    Jason.decode!(bytes)
  end
end
