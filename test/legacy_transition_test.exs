defmodule R5e.LegacyTransitionTest do
  @moduledoc """
  Spec 011 §10, the legacy chain: a log written before this contract is
  brought forward at its next boot, and **every step of that is on the
  record**.

  The fixture is the chain a pre-011 kernel wrote: the schema-lite v2
  meta-Kind and the v1 `CasExpired`, admitted by `system:bootstrap` with
  an asserted key fingerprint and no signature. Nothing about it is
  rewritten. What the contract asks is that the next boot

    * generates `random` and the origin (they were not on that chain);
    * admits the v3 meta-Kind as the same-identity transition, signed by
      the node key, with `transition: "spec-011"` on the payload;
    * does the same for **every core seed whose bytes changed** — here
      `CasExpired`, which gains `requiresAuthority`;
    * admits the seeds that chain never had, in manifest order;
    * endorses the retention key.

  and that the earlier events keep carrying **no `identity` field at all**.
  The absence is the legacy marker: a defaulted `"unsigned"` would erase
  the difference between a chain that predates signatures and one that
  stopped using them.
  """

  use ExUnit.Case, async: false

  setup do
    previous = Application.fetch_env!(:r5e, :data_dir)
    dir = Path.join(System.tmp_dir!(), "r5e-legacy-#{System.unique_integer([:positive])}")

    stop_r5e()
    Application.put_env(:r5e, :data_dir, dir)

    on_exit(fn ->
      stop_r5e()
      Application.put_env(:r5e, :data_dir, previous)
      {:ok, _} = Application.ensure_all_started(:r5e)
      File.rm_rf(dir)
    end)

    write_legacy_log(dir)
    {:ok, _} = Application.ensure_all_started(:r5e)

    :ok
  end

  test "the two pre-011 events are untouched and carry no identity field" do
    [first, second | _] = chain()

    for {event, payload} <- [first, second] do
      assert payload["actor"]["id"] == "system:bootstrap"
      refute Map.has_key?(payload, "identity")
      refute Map.has_key?(payload, "signed")
      refute Map.has_key?(payload, "nonce")
      assert event["seq"] in [1, 2]
    end
  end

  test "the changed seeds are transitioned, signed by the node key, declared on the payload" do
    transitions =
      for {_event, payload} <- chain(), payload["transition"] != nil, do: payload

    names = Enum.map(transitions, & &1["target"]["name"])
    assert names == ["core.r5e.io/v1/KindDefinition", "core.r5e.io/v1/CasExpired"]

    for payload <- transitions do
      assert payload["transition"] == "spec-011"
      assert payload["identity"] == "signed"
      assert payload["actor"]["id"] == R5e.DSSE.node_key_id()
      assert payload["authority"] == []
    end

    # §10: the chain had no origin — its two events predate origins
    # entirely — so the **first act this contract causes** carries the
    # `random` the origin was derived from, exactly as event 1 does on a
    # fresh chain. Exactly one act carries it.
    [meta, cas_expired] = transitions
    assert meta["random"] == R5e.Origin.random()
    refute Map.has_key?(cas_expired, "random")

    assert 1 ==
             Enum.count(chain(), fn {_event, payload} -> Map.has_key?(payload, "random") end)

    # ...and it is the origin every later request on this chain is
    # addressed to, re-derivable by anyone holding the node public key.
    {:ok, random} = Base.decode64(meta["random"])
    assert R5e.Origin.derive(random, R5e.SignerProvider.public_key()) == meta["origin"]
    assert meta["origin"] == R5e.Origin.current()

    # ...and the transitioned CasExpired is the one that requires authority.
    {:ok, kind} = R5e.KindRegistry.get("core.r5e.io", "v1", "CasExpired")
    assert kind.requires_authority
  end

  test "the missing seeds arrive in manifest order, then the retention Endorsement" do
    after_transition =
      chain()
      |> Enum.drop(4)
      |> Enum.map(fn {_event, payload} -> R5e.Admission.target_path(payload) end)

    assert after_transition == [
             "core.r5e.io/v1/KindDefinition",
             "core.r5e.io/v1/KindDefinition",
             "core.r5e.io/v1/KindDefinition",
             "core.r5e.io/v1/KindDefinition",
             "core.r5e.io/v1/KindDefinition",
             "core.r5e.io/v1/KindDefinition",
             "core.r5e.io/v1/KindDefinition",
             # ...and the last act of the transition is the grant of authority
             "core.r5e.io/v1/Endorsement"
           ]

    seeded =
      chain()
      |> Enum.drop(4)
      |> Enum.take(7)
      |> Enum.map(fn {_event, payload} -> payload["target"]["name"] end)

    assert seeded == [
             "core.r5e.io/v1/CasObject",
             "core.r5e.io/v1/Principal",
             "core.r5e.io/v1/Endorsement",
             "core.r5e.io/v1/Badge",
             "core.r5e.io/v1/Succession",
             "core.r5e.io/v1/Revocation",
             "core.r5e.io/v1/Deployment"
           ]

    assert R5e.Retention.authority() != []
  end

  test "an unsigned request on a transitioned chain is refused" do
    {:denied, receipt} =
      R5e.Admission.admit(%{
        envelope: nil,
        group: "core.r5e.io",
        version: "v1",
        kind: "KindDefinition",
        name: nil,
        spec: R5e.TestHelpers.kind_spec()
      })

    assert receipt["reason"] =~ "authenticate: malformed envelope"
    assert receipt["recorded"] == false
  end

  test "a second boot on the transitioned log transitions nothing further" do
    before = length(R5e.Log.events())
    origin = R5e.Origin.current()
    dir = Application.fetch_env!(:r5e, :data_dir)

    :ok = Application.stop(:r5e)
    Application.put_env(:r5e, :data_dir, dir)
    {:ok, _} = Application.ensure_all_started(:r5e)

    assert length(R5e.Log.events()) == before

    # The origin is adopted from the transition payload, not only from
    # seq 1 — so the second boot writes no second `random` and the chain
    # keeps the origin it already had.
    assert R5e.Origin.current() == origin
    assert R5e.Origin.adopted?()

    assert 1 ==
             Enum.count(chain(), fn {_event, payload} -> Map.has_key?(payload, "random") end)
  end

  test "replay adopts the origin from the transition payload, not from seq 1" do
    # Seq 1 predates origins; the fact is on the chain regardless, and a
    # replay from the log alone finds it.
    [{_event, first} | _] = chain()
    refute Map.has_key?(first, "origin")

    origin = R5e.Origin.current()
    :ok = R5e.Bootstrap.replay()

    assert R5e.Origin.current() == origin
    assert R5e.Origin.adopted?()
  end

  # -- the fixture -------------------------------------------------------
  # Two log lines a pre-011 kernel would have written, built with the same
  # canonical and chain code it used: unsigned, `assurance: "observed"`,
  # no identity block anywhere.
  defp write_legacy_log(dir), do: R5e.TestHelpers.write_legacy_log(dir)

  defp stop_r5e do
    case Application.stop(:r5e) do
      :ok -> :ok
      {:error, {:not_started, :r5e}} -> :ok
    end
  end

  defp chain do
    for event <- R5e.Log.events(),
        {:ok, payload} <- [R5e.Log.payload(event)],
        do: {event, payload}
  end
end
