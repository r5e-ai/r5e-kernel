defmodule R5e.BootstrapTest do
  @moduledoc """
  Spec 011 §10: the seed manifest, the retention key, and `endorse_role/3`
  — the function the contract names so a co-located extension gets its
  authority from an Endorsement on the chain rather than from a constant
  in someone's source.
  """

  use ExUnit.Case, async: false

  test "the manifest is the seeding order, and every file in it exists" do
    files = R5e.Bootstrap.manifest_files()

    assert files == [
             "kind-definition.v3.json",
             "cas-expired.v2.json",
             "cas-object.v1.json",
             "principal.json",
             "endorsement.json",
             "badge.json",
             "succession.json",
             "revocation.json",
             "deployment.json"
           ]

    for file <- files do
      assert File.exists?(Path.join(:code.priv_dir(:r5e), "kinds/#{file}"))
    end

    # ...and nothing in `priv/kinds/` is seeded by accident: the manifest
    # names every Kind file there except itself. `LICENSE` sits beside them
    # because the schemas are Apache-2.0 protocol surface inside an AGPL
    # repository; it is not JSON and is not a Kind, so it is not seeded.
    on_disk =
      :code.priv_dir(:r5e)
      |> Path.join("kinds")
      |> File.ls!()
      |> Enum.filter(&String.ends_with?(&1, ".json"))
      |> Enum.sort()

    assert on_disk == Enum.sort(["order.json" | files])
    assert File.exists?(Path.join(:code.priv_dir(:r5e), "kinds/LICENSE"))
  end

  test "the retention key is a second local key, endorsed by the node key for CasExpired" do
    R5e.Vectors.with_fresh_kernel(fn ->
      retention = R5e.Request.key_id(R5e.Bootstrap.retention_key())
      refute retention == R5e.DSSE.node_key_id()

      ref = R5e.Bootstrap.role_endorsement("retention", retention)
      assert ref =~ ~r/^event:sha256:[0-9a-f]{64}$/

      payload = payload_at(ref)
      assert payload["actor"]["id"] == R5e.DSSE.node_key_id()
      assert payload["spec"]["subject"] == retention
      assert payload["spec"]["role"] == "retention"
      assert payload["spec"]["kinds"] == ["core.r5e.io/v1/CasExpired"]
      assert payload["spec"]["mayIssue"] == false
      assert R5e.Retention.authority() == [ref]

      # The subject and the key material beside it agree, because
      # `Endorsement.subject` carries `derives.keyIdOf: subjectKey` — the
      # gate derived it rather than taking the issuer's word.
      {:ok, bytes} = Base.decode64(payload["spec"]["subjectKey"]["bytes"])
      assert R5e.DSSE.key_id("ed25519", bytes) == {:ok, retention}
    end)
  end

  test "endorse_role/3 grants a co-located extension its authority, on the record" do
    R5e.Vectors.with_fresh_kernel(fn ->
      fold = R5e.Request.generate_key()

      {:ok, receipt} =
        R5e.Bootstrap.endorse_role(fold.public, "fold", kinds: ["*"], may_issue: true)

      subject = R5e.Request.key_id(fold)
      assert R5e.Bootstrap.role_endorsement("fold", subject) == receipt["eventRef"]

      payload = R5e.TestHelpers.payload_of(receipt)
      assert payload["spec"]["kinds"] == ["*"]
      assert payload["spec"]["mayIssue"] == true
      assert payload["actor"]["id"] == R5e.DSSE.node_key_id()

      # Ten years by default, and the term is ordered — the `ordered`
      # keyword on the Endorsement Kind is what proves that rather than
      # this test's arithmetic.
      {:ok, from} = RecurseVerify.Instant.parse(payload["spec"]["notBefore"])
      {:ok, to} = RecurseVerify.Instant.parse(payload["spec"]["notAfter"])
      assert DateTime.diff(to, from, :second) == 10 * 365 * 24 * 60 * 60
    end)
  end

  test "a renewal is a new Endorsement, and the newest is the one cited" do
    R5e.Vectors.with_fresh_kernel(fn ->
      retention = R5e.Request.key_id(R5e.Bootstrap.retention_key())
      first = R5e.Bootstrap.role_endorsement("retention", retention)

      {:ok, renewal} =
        R5e.Bootstrap.endorse_role(R5e.Bootstrap.retention_key().public, "retention",
          kinds: ["core.r5e.io/v1/CasExpired"]
        )

      refute renewal["eventRef"] == first
      assert R5e.Bootstrap.role_endorsement("retention", retention) == renewal["eventRef"]
      assert R5e.Retention.authority() == [renewal["eventRef"]]
    end)
  end

  defp payload_at("event:" <> hash) do
    R5e.Log.events()
    |> Enum.find(&(&1["hash"] == hash))
    |> R5e.Log.payload()
    |> elem(1)
  end
end
