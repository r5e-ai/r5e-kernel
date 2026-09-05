defmodule R5e.CASTest do
  use ExUnit.Case, async: true

  test "put/get/exists roundtrip, address is sha256 of the bytes" do
    bytes = "the payload bytes #{System.unique_integer()}"
    addr = R5e.CAS.put(bytes)

    assert "sha256:" <> hex = addr
    assert hex == Base.encode16(:crypto.hash(:sha256, bytes), case: :lower)
    assert R5e.CAS.exists?(addr)
    assert {:ok, ^bytes} = R5e.CAS.get(addr)

    # idempotent: same bytes, same address
    assert R5e.CAS.put(bytes) == addr
  end

  test "get of an absent or malformed address reports honestly" do
    assert {:error, :not_found} = R5e.CAS.get("sha256:" <> String.duplicate("a", 64))
    assert {:error, :bad_address} = R5e.CAS.get("not-an-address")
    refute R5e.CAS.exists?("sha256:zz")
  end
end
