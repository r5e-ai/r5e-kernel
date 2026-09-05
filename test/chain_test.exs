defmodule R5e.ChainTest do
  use ExUnit.Case, async: true

  defp build_chain(n) do
    Enum.reduce(1..n, {[], R5e.Chain.genesis()}, fn seq, {events, prev} ->
      event = R5e.Chain.build_event(seq, prev, "test.event", R5e.Canonical.hash(%{"n" => seq}))
      {events ++ [event], event["hash"]}
    end)
    |> elem(0)
  end

  test "an untampered chain verifies" do
    assert {:ok, 5} = R5e.Chain.verify_events(build_chain(5))
  end

  test "tampering with a middle event is detected as a finding, not silence" do
    events = build_chain(5)

    tampered =
      List.update_at(events, 2, fn event ->
        Map.put(event, "payload", R5e.Canonical.hash(%{"n" => "altered"}))
      end)

    assert {:error, findings} = R5e.Chain.verify_events(tampered)
    assert Enum.any?(findings, fn f -> f.seq == 3 and f.problem =~ "recomputed" end)
  end

  test "canonical encoding is key-order independent" do
    a = %{"b" => 1, "a" => [%{"y" => true, "x" => nil}]}
    b = %{"a" => [%{"x" => nil, "y" => true}], "b" => 1}
    assert R5e.Canonical.encode(a) == R5e.Canonical.encode(b)
    assert R5e.Canonical.encode(a) == ~s({"a":[{"x":null,"y":true}],"b":1})
  end
end
