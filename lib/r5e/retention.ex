defmodule R5e.Retention do
  @moduledoc """
  The retention sweeper (spec/05 §5): the only thing on this node that
  asks for an object to be removed, and it asks the same way everything
  else asks — by submitting an admission.

  ## Opt-in, and off by default

      config :r5e, cas_ttl_seconds: 86_400   # a day
      config :r5e, cas_ttl_seconds: nil      # never expire (the default)

  `nil` means the sweeper does nothing at all: a deployment that has not
  said how long it keeps raw objects keeps them. There is no implicit
  default lifetime, because "the operator never configured retention" and
  "the operator chose one day" are different states and only one of them
  should delete anything.

  ## What it sweeps

  Every address a granted `CasObject` put on the record, whose object is
  still on disk, that no granted `CasExpired` has already removed, and
  whose admission is older than the TTL — then `R5e.RefIndex` is asked
  §5's "unreferenced" question, and if nothing cites it the sweeper
  submits one `CasExpired` for it, signed by the retention key and citing
  the Endorsement that key holds.

  One admission per address, and no batching: an expiry is a claim about
  one object at one position on the chain, and a claim about seventeen
  objects at once could not be read back as seventeen separate facts.

  ## Why it submits rather than deletes

  The sweeper has no privileged path. It builds a request and hands it to
  the gate, and the gate can refuse it — and does, at
  `validateConstraints`, when a citation landed between the scan and the
  submission, or when one declared `retention: "public-record"`. The bytes
  are removed by the `admit` step of a granted admission and by nothing
  else, so an object that is gone has an event on the chain saying who
  removed it, when, and on what claim.

  ## Not scheduled here

  `sweep/0` is called; nothing calls it on a timer yet. A deployment that
  wants a periodic sweep runs it from its own scheduler, and this slice
  ships the act rather than a policy about when to perform it — the
  timing of deletion is an operational decision, and inventing one would
  put it out of the operator's sight.
  """

  @doc """
  The actor of record on every `CasExpired` this sweeper submits: the
  **retention key** (spec 011 §10), a locally held keypair distinct from
  the node key, endorsed by the node key at event 10 for
  `core.r5e.io/v1/CasExpired` and nothing else.

  That separation is the point, and it is now what the kernel proves.
  `CasExpired` declares `requiresAuthority: true`, so an expiry citing
  nothing is refused; the citation is resolved at `resolve` (§5), so the
  Endorsement must be admitted, unrevoked, in term, held by this key, and
  cover `core.r5e.io/v1/CasExpired`; and §6 re-checks the revocation state
  and the term under the append lock, so a grant cannot say an authority
  was effective at a seq where the chain says it was not. A reader of the
  chain can therefore say that the acts which delete bytes were done under
  an authority scoped to deleting bytes — not by whoever holds the node
  key, which cannot expire anything without an endorsement of its own.
  """
  def actor, do: %{"id" => R5e.Request.key_id(R5e.Bootstrap.retention_key())}

  @doc "The Endorsement ref every sweep cites (§10, event 10)."
  @spec authority() :: [String.t()]
  def authority do
    case R5e.Bootstrap.role_endorsement("retention", actor()["id"]) do
      nil -> []
      ref -> [ref]
    end
  end

  @doc "The configured TTL in seconds, or `nil` when retention is off."
  @spec ttl_seconds() :: non_neg_integer() | nil
  def ttl_seconds, do: Application.get_env(:r5e, :cas_ttl_seconds)

  @doc """
  Run one sweep. Returns

      %{ttl: ttl | nil, scanned: n, expired: [address], denied: [{address, reason}],
        retained: [address]}

  `retained` is the addresses that were still cited (or too young), and it
  is returned rather than discarded so a caller can say what it left
  alone as well as what it removed.
  """
  @spec sweep() :: map()
  def sweep do
    case ttl_seconds() do
      nil ->
        %{ttl: nil, scanned: 0, expired: [], denied: [], retained: []}

      ttl ->
        now = R5e.Clock.now()

        R5e.RefIndex.cas_objects()
        |> Enum.sort_by(fn {address, _info} -> address end)
        |> Enum.reduce(%{ttl: ttl, scanned: 0, expired: [], denied: [], retained: []}, fn entry,
                                                                                          acc ->
          consider(entry, ttl, now, acc)
        end)
    end
  end

  defp consider({address, info}, ttl, now, acc) do
    acc = %{acc | scanned: acc.scanned + 1}

    cond do
      R5e.RefIndex.expired?(address) -> acc
      not R5e.CAS.exists?(address) -> acc
      not old_enough?(info, ttl, now) -> retain(acc, address)
      not R5e.RefIndex.unreferenced?(address) -> retain(acc, address)
      true -> expire(acc, address)
    end
  end

  # The clock is the chain's: the `ts` of the event that admitted the
  # object, not the file's mtime. An object's age is a fact about when it
  # was put on the record, and the record is what carries it.
  defp old_enough?(%{"ts" => ts}, ttl, now) when is_binary(ts) do
    case DateTime.from_iso8601(ts) do
      {:ok, admitted_at, _offset} -> DateTime.diff(now, admitted_at, :second) >= ttl
      _ -> false
    end
  end

  defp old_enough?(_info, _ttl, _now), do: false

  defp retain(acc, address), do: %{acc | retained: acc.retained ++ ["bytes:" <> address]}

  defp expire(acc, address) do
    case authority() do
      [] -> %{acc | denied: acc.denied ++ [{"bytes:" <> address, no_authority_reason()}]}
      cited -> expire_under(acc, address, cited)
    end
  end

  # §10: role Endorsements are minted at boot only, and only when none was
  # ever recorded. A sweeper whose Endorsement has been revoked refuses
  # locally and says why — it does not submit an admission it knows
  # carries no authority, it does not re-endorse itself, and the next boot
  # does not re-endorse it either. A revocation a restart reverses is a
  # suspension.
  defp no_authority_reason do
    base =
      "the retention role has no effective Endorsement on this chain, so this sweep cites none " <>
        "and CasExpired is admitted only under cited authority (§4)."

    case R5e.Bootstrap.role_status("retention")["reason"] do
      nil -> base
      reason -> base <> " " <> reason
    end
  end

  defp expire_under(acc, address, cited) do
    spec = %{"address" => "bytes:" <> address}

    target = %{
      "group" => "core.r5e.io",
      "version" => "v1",
      "kind" => "CasExpired",
      "name" => nil
    }

    envelope =
      R5e.Request.sign(
        %{target: target, spec: spec, authority: cited},
        [R5e.Bootstrap.retention_key()]
      )

    case R5e.Admission.admit(%{
           envelope: envelope,
           group: "core.r5e.io",
           version: "v1",
           kind: "CasExpired",
           name: nil,
           spec: spec
         }) do
      {:ok, receipt} ->
        %{acc | expired: acc.expired ++ [{"bytes:" <> address, receipt["eventRef"]}]}

      {:denied, receipt} ->
        %{acc | denied: acc.denied ++ [{"bytes:" <> address, receipt["reason"]}]}
    end
  end
end
