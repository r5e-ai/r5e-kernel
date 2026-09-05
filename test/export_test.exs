defmodule R5e.ExportTest do
  use ExUnit.Case, async: false

  import R5e.TestHelpers

  setup do
    dest = Path.join(System.tmp_dir!(), "r5e-export-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)
    {:ok, dest: dest}
  end

  test "an export writes into an empty directory", %{dest: dest} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "ExportOk"}))
    assert {:ok, ^dest, manifest} = R5e.Export.run(dest)
    assert manifest["events"] > 0
    assert File.exists?(Path.join(dest, "log.jsonl"))
  end

  # A bundle is a whole claim: the manifest counts the objects beside it
  # and the verifier reads everything in `cas/` as something the chain
  # must account for. A second export into the same directory would leave
  # one run's log beside another run's objects, and the verifier would
  # report those objects as ones nothing on the chain put there — it would
  # be right, and the bundle would be the lie.
  test "a second export into the same directory is refused, and writes nothing",
       %{dest: dest} do
    {:ok, _} = admit_kind(kind_spec(%{"kind" => "ExportOnce"}))
    {:ok, ^dest, _} = R5e.Export.run(dest)

    before = snapshot(dest)

    assert {:error, {:non_empty, ^dest}} = R5e.Export.run(dest)
    assert snapshot(dest) == before
  end

  test "a directory holding anything at all is non-empty", %{dest: dest} do
    File.mkdir_p!(dest)
    File.write!(Path.join(dest, "README"), "not a bundle")

    assert {:error, {:non_empty, ^dest}} = R5e.Export.run(dest)
    assert File.ls!(dest) == ["README"]
  end

  # Debt #17: the address of a spec has one derivation. The `admit` step
  # writes it and `R5e.Bootstrap` replays it, so the write path and the
  # pure path have to agree on every spec, not merely usually.
  test "put_spec/1 returns spec_address/1" do
    for spec <- [
          %{},
          %{"title" => "hello"},
          %{"b" => [1, 2, %{"c" => nil}], "a" => "ünïcode"},
          kind_spec()
        ] do
      assert R5e.CAS.put_spec(spec) == R5e.CAS.spec_address(spec)
    end
  end

  defp snapshot(dir) do
    dir
    |> Path.join("**")
    |> Path.wildcard()
    |> Enum.filter(&File.regular?/1)
    |> Map.new(&{Path.relative_to(&1, dir), File.read!(&1)})
  end
end
