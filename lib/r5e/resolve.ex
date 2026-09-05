defmodule R5e.Resolve do
  @moduledoc """
  The `resolve` stage (spec/05 §4): pure lookups, no writes, between
  `validateStructure` and `authorize`.

  Every ref value in the submitted spec is looked up by its declaration's
  class, and the result is the **resolution manifest** — an array sorted
  by JSON pointer, one entry per ref value (array members individually,
  duplicates kept), recorded beside `spec` on the event payload and the
  store entry, returned on the receipt, and handed to the policy engine as
  `resolved` on the request. What each class checks and what its entry
  adds is §4's table; a failure denies at stage `resolve` with a reason
  naming the pointer, the declared target, and what was found — the three
  things a reader needs to tell a typo from a race from a lie.

  A **site** is `{pointer, refdecl, value}`, the triple `R5e.Refs.sites/2`
  yields, and it is carried whole through the per-class helpers because
  every denial needs all three of it.

  ## The bytes arm asks three questions, in order (§5)

  Presence says only that the deployment holds those bytes; what §4 asks
  for is that somebody put them on the record. So each denial says which
  of the three failed: **presence** (the object is in this deployment's
  CAS), **the partition** (the address coincides with no event payload
  address and no admitted `specAddress`, answered in one `R5e.RefIndex`
  lookup — amendment B6), and **backing** (a `CasObject` admission carries
  the address, and its `event:` ref becomes `casObjectEvent` — amendment
  B7; *or* the object is a kernel-derived one, whose entry records
  `casObjectEvent: null` with `derived: true` beside it, so the null is a
  stated class rather than a gap). Present, partitioned and backed by
  neither is refused: bytes in a directory are not a citation.

  ## What is *not* established here, and is said rather than implied

    * **This is a snapshot, and the commit is what makes it true.** The
      head and every `kind`-ref `generation` are read here without a lock,
      and re-read under the append lock at `record` (§7, `R5e.Commit`). A
      mismatch is not a denial: the admission retries from this stage, so
      what the manifest records is what was true at the seq the event
      landed at, not merely at the moment the request arrived. What
      `resolve` alone establishes is therefore "this was true when I
      looked", and that is why the manifest records the observation
      (`generation`, `head`) rather than only the conclusion.
    * **Cost.** Resolving an `event` ref still reads the whole log once
      per admission and decodes every payload. `bytes` refs no longer do:
      the index answers both of their chain questions in constant time.
  """

  @doc """
  Resolve every ref in `spec` against the live kernel. Returns the
  manifest, sorted by pointer, or a denial reason for stage `resolve`.
  """
  @spec run(R5e.Kind.t(), map(), map()) :: {:ok, [map()]} | {:error, String.t()}
  def run(%R5e.Kind{schema: schema}, spec, request) do
    case R5e.Refs.sites(schema, spec) do
      [] ->
        {:ok, []}

      sites ->
        sites
        |> Enum.sort_by(fn {pointer, _decl, _value} -> pointer end)
        |> reduce_manifest(spec, request, chain(sites))
    end
  end

  defp reduce_manifest(sites, spec, request, chain) do
    Enum.reduce_while(sites, {:ok, []}, fn site, {:ok, acc} ->
      case resolve_site(site, spec, request, chain) do
        {:ok, entry} -> {:cont, {:ok, acc ++ [entry]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  # -- the chain view ----------------------------------------------------
  # Read once per admission, and only when something needs it: `kind` refs
  # are answered by the in-memory store alone.

  defp chain(sites) do
    if Enum.any?(sites, fn {_p, decl, _v} -> R5e.Refs.class(decl) == :event end) do
      events = R5e.Log.events()

      %{
        events: events,
        by_hash: Map.new(events, &{&1["hash"], &1}),
        payloads: payloads(events)
      }
    else
      %{events: [], by_hash: %{}, payloads: %{}}
    end
  end

  defp payloads(events) do
    for event <- events,
        {:ok, decoded} <- [R5e.Log.payload(event)],
        into: %{},
        do: {event["hash"], decoded}
  end

  # -- kind (§4) ---------------------------------------------------------

  defp resolve_site({pointer, %{"kind" => declared}, value} = site, _spec, _request, _chain) do
    with {:ok, group, version, kind, name} <- split(site),
         :ok <- same_path(site, declared, "#{group}/#{version}/#{kind}"),
         {:ok, entry} <- entry(site, group, version, kind, name) do
      {:ok,
       %{
         "path" => pointer,
         "class" => "kind",
         "value" => value,
         "specAddress" => entry["specAddress"],
         "admissionEvent" => entry["admissionEvent"],
         "generation" => entry["admissionSeq"]
       }}
    end
  end

  # -- event (§4) --------------------------------------------------------

  defp resolve_site({pointer, %{"event" => declared} = _decl, value} = site, spec, request, chain) do
    with {:ok, event} <- event(site, chain),
         {:ok, payload} <- payload(site, event, chain),
         :ok <- target_kind(site, event, payload, declared),
         :ok <- outcome_facet(site, event, payload),
         :ok <- same_actor(site, payload, request),
         {:ok, anchor} <- same_anchor(site, event, payload, spec, request, chain) do
      {:ok,
       Map.merge(
         %{
           "path" => pointer,
           "class" => "event",
           "value" => value,
           "seq" => event["seq"],
           "outcome" => payload["outcome"],
           "targetKind" => R5e.Admission.target_path(payload)
         },
         anchor
       )}
    end
  end

  # -- bytes (§4, §5) ----------------------------------------------------

  defp resolve_site({pointer, %{"bytes" => _} = decl, value} = site, _spec, _request, _chain) do
    address = R5e.Refs.object_address(value)

    with {:ok, bytes} <- object(site, address),
         :ok <- partition(site, address),
         {:ok, backing} <- backing(site, address) do
      {:ok,
       %{
         "path" => pointer,
         "class" => "bytes",
         "value" => value,
         "size" => byte_size(bytes),
         "casObjectEvent" => backing["casObjectEvent"]
       }
       |> put_if(backing["derived"], "derived", true)
       |> put_if(decl["retention"] != nil, "retention", decl["retention"])}
    end
  end

  defp resolve_site(site, _spec, _request, _chain),
    do: deny(site, "the declaration names no known ref class")

  @doc """
  The envelope `derivedFrom` (§1) as a bytes citation (§5, amendment C8).

  It is not in the spec, so `R5e.Refs` never sees it and it gets no
  manifest entry — but it is a `bytes:` address that a reader will follow,
  and §5 says a `bytes:` citation is backed or it is nothing. So the same
  question the `bytes` arm asks is asked of it here, at the same stage.
  Its `@` pointer says where it was read from: the envelope, not the spec.

  What it deliberately does **not** do is make the object unexpirable.
  §5's four citation sources are the admitted spec, the resolution
  manifest, event payload addresses and admitted `specAddress`es;
  `derivedFrom` is none of them, so the retention sweeper may still expire
  an object whose only citation is an envelope. Backing is checked at the
  moment of admission and is not a promise about later, and that is a gap
  this slice names rather than closes.
  """
  @spec derived_from(nil | String.t()) :: :ok | {:error, String.t()}
  def derived_from(nil), do: :ok

  def derived_from(address) when is_binary(address) do
    if backed?(address) do
      :ok
    else
      {:error,
       "@derivedFrom → bytes: #{inspect(address)} — no core.r5e.io/v1/CasObject admission on " <>
         "this chain put those bytes on the record and they are not a kernel-derived object; " <>
         "a derivedFrom is a bytes: citation and must be backed like any other (§5)"}
    end
  end

  @doc """
  §4's head over admitted events for `(kind, anchor)`: the latest granted
  admission of `kind` whose spec's `field` canonically encodes to `anchor`,
  or `nil`. `pairs` is `[{event, payload}]` of granted admissions.

  `resolve` reads it here as a snapshot and records it on the manifest
  entry; `R5e.Commit` re-reads it under the append lock (§7) and compares.
  One function, because two answers to "which is the head" is exactly the
  disagreement the re-check exists to catch.
  """
  @spec head([{map(), map()}], String.t(), String.t(), String.t()) :: map() | nil
  def head(pairs, kind, field, anchor) do
    pairs
    |> Enum.filter(fn {_event, payload} ->
      R5e.Admission.target_path(payload) == kind and
        R5e.Kind.exists?(payload["spec"] || %{}, field) and
        R5e.Canonical.encode(payload["spec"][field]) == anchor
    end)
    |> List.last()
    |> case do
      nil -> nil
      {event, _payload} -> event
    end
  end

  # -- kind helpers ------------------------------------------------------

  defp split({_pointer, _decl, value} = site) do
    case R5e.Refs.split_kind_ref(value) do
      {:ok, g, v, k, name} -> {:ok, g, v, k, name}
      :error -> deny(site, "not a group/version/Kind/name path")
    end
  end

  defp same_path(_site, declared, declared), do: :ok
  defp same_path(site, _declared, found), do: deny(site, "the value names Kind #{found}")

  defp entry(site, group, version, kind, name) do
    case R5e.ResourceStore.get(group, version, kind, name) do
      {:error, :not_found} ->
        deny(site, "no admitted instance of that name is on the store")

      # The live entry is never a displaced one — supersession moves the
      # old entry into the superseded index — but a ref must not resolve
      # to something that has been replaced, so the rule is stated where
      # it is relied on rather than left to the store's shape.
      {:ok, %{"supersededBy" => by}, _lineage} when by != nil ->
        deny(site, "that entry has been displaced (supersededBy #{by})")

      {:ok, entry, _lineage} ->
        {:ok, entry}
    end
  end

  # -- event helpers -----------------------------------------------------

  defp event({_pointer, _decl, value} = site, chain) do
    case Map.fetch(chain.by_hash, R5e.Refs.object_address(value)) do
      :error ->
        deny(site, "no event with that hash is on this chain")

      {:ok, %{"kind" => kind} = event} when kind in ~w(admission.granted admission.denied) ->
        {:ok, event}

      {:ok, event} ->
        deny(site, "the event at seq #{event["seq"]} is a #{event["kind"]}, not an admission")
    end
  end

  defp payload(site, event, chain) do
    case Map.fetch(chain.payloads, event["hash"]) do
      {:ok, payload} ->
        {:ok, payload}

      :error ->
        deny(
          site,
          "targetPayload: missing — the payload of the event at seq #{event["seq"]} " <>
            "(#{event["payload"]}) is not in this deployment's CAS"
        )
    end
  end

  # §5/KS-5: a declaration may name one Kind or a list of them — a
  # Revocation cites an Endorsement, a Badge or a Succession, and three
  # properties for one citation would be three ways to say one thing.
  defp target_kind(site, event, payload, declared) do
    found = R5e.Admission.target_path(payload)

    if found in List.wrap(declared),
      do: :ok,
      else: deny(site, "the event at seq #{event["seq"]} admitted #{found}")
  end

  defp outcome_facet({_pointer, decl, _value} = site, event, payload) do
    case {R5e.Refs.outcome(decl), payload["outcome"]} do
      {"any", _} -> :ok
      {"admitted", "admitted"} -> :ok
      {_, found} -> deny(site, "the event at seq #{event["seq"]} is a #{found} one")
    end
  end

  # -- sameActor (§5) ----------------------------------------------------

  # KS-5: only the actor of record — or a key that actor succeeded — may
  # cite this event. It is what makes a Revocation a *withdrawal* rather
  # than a claim: anyone may say an endorsement should not stand, and only
  # the endorser can make that so.
  defp same_actor({_pointer, %{"sameActor" => true}, _value} = site, payload, request) do
    target_actor = get_in(payload, ["actor", "id"])
    submitter = request[:actor]["id"]

    if R5e.Succession.matches(target_actor, submitter, R5e.Succession.next_seq()) do
      :ok
    else
      # §5 (r4.3): the reason string **begins** `resolve: sameActor`, and
      # the site detail follows it. The rule's name comes first because
      # that is what a reader greps a chain for — refused withdrawals —
      # and the pointer is the detail, not the headline.
      deny_as(
        "sameActor",
        site,
        "the target's actor of record is #{inspect(target_actor)}, " <>
          "and #{inspect(submitter)} is neither that key nor its successor"
      )
    end
  end

  defp same_actor(_site, _payload, _request), do: :ok

  # -- sameAnchor (§4) ---------------------------------------------------

  defp same_anchor(
         {_pointer, %{"sameAnchor" => field}, _value} = site,
         event,
         payload,
         spec,
         request,
         chain
       )
       when is_binary(field) do
    target_spec = payload["spec"] || %{}
    target_actor = get_in(payload, ["actor", "id"])

    cond do
      not R5e.Kind.exists?(spec, field) ->
        deny(site, "the anchor field #{inspect(field)} does not exist on this spec")

      not R5e.Kind.exists?(target_spec, field) ->
        deny(site, "the anchor field #{inspect(field)} does not exist on the target's spec")

      R5e.Canonical.encode(spec[field]) != R5e.Canonical.encode(target_spec[field]) ->
        deny(
          site,
          "the anchor field #{inspect(field)} differs: this spec anchors on " <>
            "#{R5e.Canonical.encode(spec[field])}, the target on " <>
            "#{R5e.Canonical.encode(target_spec[field])}"
        )

      target_actor != request.actor["id"] ->
        deny(
          site,
          "the target's actor of record is #{inspect(target_actor)}, " <>
            "not the submitting actor #{inspect(request.actor["id"])}"
        )

      true ->
        head_check(site, event, field, spec, chain)
    end
  end

  defp same_anchor(_site, _event, _payload, _spec, _request, _chain), do: {:ok, %{}}

  # The snapshot half of §7's head check: `record` re-reads this under the
  # append lock, and the manifest records which snapshot it was.
  defp head_check({_pointer, decl, _value} = site, event, field, spec, chain) do
    declared = decl["event"]
    anchor = R5e.Canonical.encode(spec[field])
    head = head(granted_pairs(chain), declared, field, anchor)

    cond do
      head == nil ->
        deny(site, "no admitted #{declared} anchors on that value")

      head["hash"] == event["hash"] ->
        {:ok, %{"anchorField" => field, "head" => "event:" <> head["hash"]}}

      true ->
        deny(
          site,
          "the event at seq #{event["seq"]} is not the current head for that anchor — " <>
            "seq #{head["seq"]} (event:#{head["hash"]}) is"
        )
    end
  end

  defp granted_pairs(chain) do
    for event <- chain.events,
        event["kind"] == "admission.granted",
        payload = Map.get(chain.payloads, event["hash"]),
        do: {event, payload}
  end

  # -- bytes helpers -----------------------------------------------------

  defp object(site, address) do
    case R5e.CAS.get(address) do
      {:ok, bytes} -> {:ok, bytes}
      {:error, _} -> deny(site, "no object at that address in this deployment's CAS")
    end
  end

  # §4: the partition between kernel-written objects (event payloads,
  # admitted specs) and admitted raw bytes is a property of the *act*, not
  # of the address. An address on both sides means someone tried to pass
  # one off as the other, and it is refused here and by the verifier.
  # O(1) since §5's index (amendment B6); it was a full log scan before.
  defp partition(site, address) do
    case R5e.RefIndex.partition(address) do
      :ok ->
        :ok

      {:error, :payload} ->
        deny(site, "that address is an event payload, not admitted raw bytes (§4)")

      {:error, :spec} ->
        deny(site, "that address is an admitted spec, not admitted raw bytes (§4)")
    end
  end

  # §5: presence is not admission. The object must have entered through
  # the door — a granted `CasObject` — or be one the kernel derived inside
  # an admission, which is the one class that legitimately has no
  # admission of its own.
  defp backing(site, address) do
    case R5e.RefIndex.cas_object(address) do
      {:ok, %{"eventRef" => ref}} ->
        {:ok, %{"casObjectEvent" => ref, "derived" => false}}

      :error ->
        if R5e.RefIndex.derived?(address) do
          {:ok, %{"casObjectEvent" => nil, "derived" => true}}
        else
          deny(
            site,
            "the object at #{address} is in this deployment's CAS, but no " <>
              "core.r5e.io/v1/CasObject admission on this chain put it there and it is not a " <>
              "kernel-derived object — bytes present is not bytes admitted (§5)"
          )
        end
    end
  end

  # The one question `derived_from/1` and the `bytes` arm share: did an
  # act put these bytes on the record?
  defp backed?(address) do
    match?({:ok, _}, R5e.RefIndex.cas_object(address)) or R5e.RefIndex.derived?(address)
  end

  defp put_if(map, true, key, value), do: Map.put(map, key, value)
  defp put_if(map, _false, _key, _value), do: map

  # -- denial ------------------------------------------------------------

  defp deny({pointer, decl, value}, found),
    do: {:error, "#{pointer} → #{R5e.Refs.declared_target(decl)}: #{inspect(value)} — #{found}"}

  # The same site detail, behind a named rule. Used where the contract
  # fixes the *prefix* of the reason rather than leaving it to the site.
  defp deny_as(rule, site, found) do
    {:error, detail} = deny(site, found)
    {:error, "#{rule}: #{detail}"}
  end
end
