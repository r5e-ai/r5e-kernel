defmodule R5e.MetaKindTransitionTest do
  @moduledoc """
  Schema-lite v2 §11 / spec 011 §10: a log that already carries the v1
  meta-Kind is transitioned to v3 by exactly one supersession act at boot,
  signed by the node key and declared `transition: "spec-011"` on the
  payload.
  """

  use ExUnit.Case, async: false

  @v1_fixture Path.expand("fixtures/kind-definition.v1.json", __DIR__)
  @external_resource @v1_fixture

  @meta_name "core.r5e.io/v1/KindDefinition"

  setup do
    previous = Application.fetch_env!(:r5e, :data_dir)
    dir = Path.join(System.tmp_dir!(), "r5e-transition-#{System.unique_integer([:positive])}")

    stop_r5e()
    Application.put_env(:r5e, :data_dir, dir)

    on_exit(fn ->
      stop_r5e()
      Application.put_env(:r5e, :data_dir, previous)
      {:ok, _} = Application.ensure_all_started(:r5e)
      File.rm_rf(dir)
    end)

    write_v1_log(dir)
    {:ok, _} = Application.ensure_all_started(:r5e)

    {:ok, dir: dir, v1: v1_spec()}
  end

  test "the registry ends at v3, and the transition is one recorded act", %{v1: v1} do
    {:ok, meta} = R5e.KindRegistry.get("core.r5e.io", "v1", "KindDefinition")

    assert meta.naming == %{"mode" => "path"}
    assert meta.substrate == "resource"
    refute meta.legacy
    assert meta.description =~ "v3 (spec 011)"

    transitions = transition_events()
    assert length(transitions) == 1
    [{event, payload}] = transitions

    assert payload["transition"] == R5e.Bootstrap.transition_reason()
    # §10: bootstrap signs. The transition's actor of record is the node key.
    assert payload["actor"]["id"] == R5e.DSSE.node_key_id()
    assert payload["identity"] == "signed"
    assert payload["outcome"] == "admitted"
    assert payload["target"]["name"] == @meta_name
    assert payload["spec"]["naming"] == %{"mode" => "path"}

    # The v1 definition it displaced is still on the chain, at seq 1.
    assert [v1_event] = Enum.filter(R5e.Log.events(), &(&1["seq"] == 1))
    assert payload_of(v1_event)["spec"] == v1

    # The store entry is the v2 definition, and it says what it superseded.
    {:ok, entry, _} = R5e.ResourceStore.get("core.r5e.io", "v1", "KindDefinition", @meta_name)
    assert entry["spec"]["naming"] == %{"mode" => "path"}
    assert entry["admissionEvent"] == R5e.Admission.event_ref(event)
    assert entry["supersedes"] == R5e.Admission.event_ref(v1_event)

    # ...and the displaced entry records supersededBy.
    [displaced] = R5e.ResourceStore.superseded("core.r5e.io", "v1", "KindDefinition", @meta_name)
    assert displaced["spec"] == v1
    assert displaced["supersededBy"] == R5e.Admission.event_ref(event)
  end

  test "a second boot on the same log transitions nothing", %{dir: dir} do
    before = length(R5e.Log.events())

    :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :data_dir, dir)
    {:ok, _} = Application.ensure_all_started(:r5e)

    assert length(R5e.Log.events()) == before
    assert length(transition_events()) == 1

    {:ok, meta} = R5e.KindRegistry.get("core.r5e.io", "v1", "KindDefinition")
    assert meta.naming == %{"mode" => "path"}
  end

  test "the v1 definition is replayed as legacy, never denied", %{v1: v1} do
    assert {:error, reason} = R5e.Kind.from_map(v1)
    assert reason =~ "naming is required"

    assert {:ok, legacy} = R5e.Kind.from_map(v1, replay: true)
    assert legacy.legacy
    assert legacy.naming == %{"mode" => "caller"}

    # ...and it serializes exactly as it did under v1: no invented keys.
    map = R5e.Kind.to_map(legacy)
    refute Map.has_key?(map, "naming")
    refute Map.has_key?(map, "description")
  end

  # -- fixture -----------------------------------------------------------
  # The log line the v1 kernel would have written, built with the same
  # canonical/chain code it used: a granted admission of the v1 meta-Kind,
  # with the v1 payload shape (no resolvedRefs, no derivedFrom). That kernel's
  # checkpoint key already existed; the fixture keeps it beside the history.
  defp write_v1_log(dir) do
    File.mkdir_p!(dir)
    R5e.Signer.Local.ensure_keys!(key_dir: Path.join(dir, "keys"))

    payload = %{
      "actor" => %{
        "id" => "system:bootstrap",
        "keyFingerprint" => "sha256:0000-bootstrap-placeholder"
      },
      "target" => %{
        "group" => "core.r5e.io",
        "version" => "v1",
        "kind" => "KindDefinition",
        "name" => @meta_name
      },
      "outcome" => "admitted",
      "assurance" => "observed",
      "spec" => v1_spec(),
      "scopeDefaulted" => false
    }

    addr = R5e.CAS.put(R5e.Canonical.encode(payload))
    event = R5e.Chain.build_event(1, R5e.Chain.genesis(), "admission.granted", addr)
    File.write!(Path.join(dir, "log.jsonl"), Jason.encode!(event) <> "\n")
  end

  defp v1_spec, do: @v1_fixture |> File.read!() |> Jason.decode!()

  defp stop_r5e do
    case Application.stop(:r5e) do
      :ok -> :ok
      {:error, {:not_started, :r5e}} -> :ok
    end
  end

  defp transition_events do
    for event <- R5e.Log.events(),
        payload = payload_of(event),
        payload["transition"] != nil,
        do: {event, payload}
  end

  defp payload_of(event) do
    {:ok, bytes} = R5e.CAS.get(event["payload"])
    Jason.decode!(bytes)
  end
end
