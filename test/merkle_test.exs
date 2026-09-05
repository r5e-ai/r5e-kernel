defmodule R5e.MerkleTest do
  use ExUnit.Case, async: true

  alias RecurseVerify.Merkle

  defp leaves(n), do: Enum.map(1..n, &"leaf-data-#{&1}")

  test "inclusion proof roundtrip: every index of every tree size up to 17" do
    for n <- 1..17, leaves = leaves(n), root = Merkle.root(leaves), index <- 0..(n - 1) do
      {:ok, proof} = Merkle.inclusion_proof(leaves, index)

      assert Merkle.verify_inclusion(Enum.at(leaves, index), index, n, proof, root),
             "inclusion failed for index #{index} in tree of #{n}"
    end
  end

  test "consistency proof roundtrip: every (m, n) pair up to 17" do
    for n <- 1..17, leaves = leaves(n), root_n = Merkle.root(leaves), m <- 1..n do
      root_m = Merkle.root(Enum.take(leaves, m))
      {:ok, proof} = Merkle.consistency_proof(leaves, m, n)

      assert Merkle.verify_consistency(m, n, root_m, root_n, proof),
             "consistency failed for m=#{m}, n=#{n}"
    end
  end

  test "a tampered leaf is detected by inclusion verification and by the root" do
    original = leaves(9)
    root = Merkle.root(original)
    {:ok, proof} = Merkle.inclusion_proof(original, 4)

    # Same proof, different leaf data: must not verify.
    refute Merkle.verify_inclusion("leaf-data-tampered", 4, 9, proof, root)

    # A tree with the tampered leaf has a different root, categorically.
    tampered = List.replace_at(original, 4, "leaf-data-tampered")
    assert Merkle.root(tampered) != root

    # And a consistency check between the honest prefix and the tampered
    # tree fails: the tampered tree is not an append-only extension.
    root_m = Merkle.root(Enum.take(original, 5))
    {:ok, cproof} = Merkle.consistency_proof(tampered, 5, 9)
    refute Merkle.verify_consistency(5, 9, root_m, Merkle.root(tampered), cproof)
  end

  test "proofs do not verify against the wrong size, index, or root" do
    l = leaves(11)
    root = Merkle.root(l)
    {:ok, proof} = Merkle.inclusion_proof(l, 3)

    refute Merkle.verify_inclusion(Enum.at(l, 3), 2, 11, proof, root)
    # A size whose fold path genuinely differs (proof length can't match).
    refute Merkle.verify_inclusion(Enum.at(l, 3), 3, 4, proof, root)
    refute Merkle.verify_inclusion(Enum.at(l, 3), 3, 11, proof, Merkle.root(leaves(10)))
    assert {:error, :index_out_of_range} = Merkle.inclusion_proof(l, 11)
    assert {:error, :bad_sizes} = Merkle.consistency_proof(l, 5, 12)
  end
end
