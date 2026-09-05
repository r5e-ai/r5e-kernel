defmodule R5e.CheckpointSigningTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  setup do
    dest = Path.join(System.tmp_dir!(), "r5e-ckpt-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, dest: dest}
  end

  test "checkpoint sign/verify roundtrip against the node public key" do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "CkptProbe"}))

    signed = R5e.Log.checkpoint()
    pub = R5e.SignerProvider.public_key()

    assert {:ok, payload, key_id} = R5e.DSSE.verify(signed["envelope"], pub)
    assert key_id == R5e.SignerProvider.key_id()
    assert key_id == R5e.Signer.Local.fingerprint(pub)

    claim = Jason.decode!(payload)
    assert claim == signed["checkpoint"]
    assert claim["chainHead"] == List.last(R5e.Log.events())["hash"]

    # The STH is a true tree head: size + Merkle root over the event hashes.
    leaves = R5e.Log.leaves()
    assert claim["treeSize"] == length(leaves)
    assert claim["merkleRoot"] == RecurseVerify.Merkle.hex(RecurseVerify.Merkle.root(leaves))

    # A different keypair must NOT verify.
    {other_pub, _priv} = :crypto.generate_key(:eddsa, :ed25519)
    assert {:error, :signature_mismatch} = R5e.DSSE.verify(signed["envelope"], other_pub)
  end

  test "verifier reports a tampered signed root as a failed signature", %{dest: dest} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "CkptTamper"}))
    {:ok, ^dest, _} = R5e.Export.run(dest)

    manifest_path = Path.join(dest, "manifest.json")
    manifest = manifest_path |> File.read!() |> Jason.decode!()

    tampered_claim =
      manifest["checkpoint"]["checkpoint"]
      |> Map.put("merkleRoot", String.duplicate("f", 64))

    tampered =
      manifest
      |> put_in(["checkpoint", "checkpoint"], tampered_claim)
      |> put_in(
        ["checkpoint", "envelope", "payload"],
        Base.encode64(R5e.Canonical.encode(tampered_claim))
      )

    File.write!(manifest_path, Jason.encode!(tampered))

    {:ok, report} = RecurseVerify.run(dest)

    assert Enum.any?(report.findings, &(&1 =~ "checkpoint signature FAILED"))
    refute Enum.any?(report.checked, &(&1 =~ "checkpoint signature: verified"))
    # The chain itself is untouched; the verifier still says so.
    assert Enum.any?(report.checked, &(&1 =~ "chain: intact"))
  end

  test "verifier flags an unsigned/legacy checkpoint as a finding, not a crash", %{dest: dest} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "CkptLegacy"}))
    {:ok, ^dest, _} = R5e.Export.run(dest)

    manifest_path = Path.join(dest, "manifest.json")
    manifest = manifest_path |> File.read!() |> Jason.decode!()

    legacy =
      Map.put(manifest, "checkpoint", %{
        "root" => manifest["checkpoint"]["checkpoint"]["chainHead"],
        "seq" => manifest["checkpoint"]["checkpoint"]["treeSize"],
        "signature" => nil
      })

    File.write!(manifest_path, Jason.encode!(legacy))

    {:ok, report} = RecurseVerify.run(dest)
    assert Enum.any?(report.findings, &(&1 =~ "unsigned checkpoint"))
  end

  test "private key file is created with owner-only permissions" do
    key_path =
      Path.join([Application.fetch_env!(:r5e, :data_dir), "keys", "node_ed25519.key"])

    # Force provisioning (idempotent), then check the mode.
    _ = R5e.SignerProvider.public_key()
    %File.Stat{mode: mode} = File.stat!(key_path)
    assert Bitwise.band(mode, 0o077) == 0
  end
end
