# SPDX-License-Identifier: AGPL-3.0-only
defmodule R5e.Policy.Facts do
  @moduledoc """
  Optimistic, tracked resource and latest-event reads for policy adapters.

  Call `resolve/1` with the admitting request to present its actor, resolved
  authority chains, cited resource entries (`resources`, keyed by ref), and
  immutable admission events (`events`, keyed by ref, with `event` and `payload`).
  Consumers must inspect the event outcome: grants and denials with a recorded
  spec are supported; redacted denials with nil spec are refused. Event payloads
  retain the recorded actor and spec; they have no mutable
  resource generation. Bytes-class citations are not hydrated. Call `fetch/1` for each further
  resource hop. Entries retain their admitted `spec` and `admissionSeq`; no
  recursive hydration or application-specific interpretation is performed.

  These calls must run synchronously in the process executing `R5e.Policy.decide/1`.
  The kernel adds every served generation to the decision metadata and Commit
  rechecks it under the append lock, even if the adapter reports none. Missing,
  malformed or conflicting reads invalidate the decision even if their error
  return is ignored. Authority chains are the gate's already resolved records;
  their existing `authority_visited` commit checks remain authoritative.

  Event reads validate the log framing and hash chain and verify each returned
  payload against its recorded address using the same bytes that are decoded.
  Head reads scan and verify every granted payload; cited event reads verify
  their selected payload. Each call scans history; no cross-call cache is used.
  This integrity contract does not extend to unrelated kernel CAS readers.

  Tracking is scoped to one decision, restored on nested decisions, and cleaned
  up on exceptions and retries. Direct ResourceStore reads and child processes
  are outside this contract; adapters must use `fetch/1` for every resource hop.
  """
  @key {__MODULE__, :reads}

  @doc false
  def run(fun, finalize) do
    previous = Process.get(@key)
    Process.put(@key, %{generations: %{}, heads: %{}, error: nil})

    try do
      answer = fun.()
      finalize.(answer, Process.get(@key))
    after
      if previous == nil,
        do: Process.delete(@key),
        else: Process.put(@key, merge_capture(previous, Process.get(@key)))
    end
  end

  @doc false
  def invalidate(reason), do: fail(reason)

  defp merge_capture(parent, child) do
    parent = %{parent | error: parent.error || child.error}

    Enum.reduce([:generations, :heads], parent, fn field, merged ->
      Enum.reduce(child[field], merged, fn {key, value}, acc ->
        case Map.fetch(acc[field], key) do
          {:ok, other} when other != value ->
            %{acc | error: acc.error || "conflicting nested #{field} for #{inspect(key)}"}

          _ ->
            Map.put(acc, field, Map.put(acc[field], key, value))
        end
      end)
    end)
  end

  @doc """
  Read the latest granted admission of an exact `group/version/Kind` whose
  literal top-level spec field canonically equals `anchor`. Returns `{:ok, nil}`
  for absence, otherwise `{:ok, %{event: event, payload: payload}}`.

  The head, including absence, is captured by the kernel and rechecked under the
  append lock. This uses Resolve.head/4's present/non-null field semantics; nil
  anchors are invalid. Anchors must be canonical JSON values (no floats).
  Non-granted events never move this head. No application state machine or
  authority rule is implied by reading it.
  """
  @spec head(String.t(), String.t(), term()) :: {:ok, map() | nil} | {:error, String.t()}
  def head(kind, field, anchor) do
    with :ok <- active(),
         true <- valid_head_query?(kind, field, anchor),
         bytes = R5e.Canonical.encode(anchor),
         {:ok, ^anchor} <- R5e.Canonical.decode_json(bytes),
         {:ok, pairs} <- granted_pairs(),
         event = R5e.Resolve.head(pairs, kind, field, bytes),
         ref = if(event, do: "event:" <> event["hash"]),
         :ok <- track_head({kind, field, bytes}, ref) do
      if event do
        {^event, payload} = Enum.find(pairs, fn {candidate, _} -> candidate == event end)
        {:ok, %{event: event, payload: payload}}
      else
        {:ok, nil}
      end
    else
      {:error, reason} -> fail(reason)
      _ -> fail("malformed policy head query")
    end
  rescue
    error ->
      fail("policy head read raised")
      reraise error, __STACKTRACE__
  catch
    kind, reason ->
      fail("policy head read interrupted")
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp valid_head_query?(kind, field, anchor) do
    is_binary(kind) and String.valid?(kind) and
      match?([_, _, _], String.split(kind, "/")) and
      Enum.all?(String.split(kind, "/"), &(&1 != "")) and
      is_binary(field) and String.valid?(field) and field != "" and anchor != nil and
      json_value?(anchor)
  end

  defp json_value?(value) when is_map(value),
    do:
      Enum.all?(value, fn {key, item} ->
        is_binary(key) and String.valid?(key) and json_value?(item)
      end)

  defp json_value?(value) when is_list(value), do: Enum.all?(value, &json_value?/1)
  defp json_value?(value) when is_binary(value), do: String.valid?(value)
  defp json_value?(value), do: is_integer(value) or value in [true, false, nil]

  defp granted_pairs do
    with {:ok, events} <- R5e.Log.strict_events() do
      Enum.reduce_while(events, {:ok, []}, fn event, {:ok, pairs} ->
        if event["kind"] == "admission.granted" do
          case R5e.Log.strict_payload(event) do
            {:ok, %{"target" => target, "spec" => spec} = payload}
            when is_map(target) and is_map(spec) ->
              {:cont, {:ok, [{event, payload} | pairs]}}

            _ ->
              {:halt, {:error, "missing or malformed granted policy head payload"}}
          end
        else
          {:cont, {:ok, pairs}}
        end
      end)
      |> case do
        {:ok, pairs} -> {:ok, Enum.reverse(pairs)}
        error -> error
      end
    end
  end

  defp track_head(query, head) do
    state = Process.get(@key)

    case Map.fetch(state.heads, query) do
      {:ok, other} when other != head ->
        fail("conflicting policy event heads for #{inspect(query)}")

      _ ->
        Process.put(@key, %{state | heads: Map.put(state.heads, query, head)})
        :ok
    end
  end

  @doc false
  def head_metadata(heads) do
    heads
    |> Enum.sort()
    |> Enum.map(fn {{kind, field, anchor}, head} ->
      %{"kind" => kind, "field" => field, "anchor" => anchor, "head" => head}
    end)
  end

  @doc "Present the gate-resolved request and fetch every kind-class citation."
  @spec resolve(map()) :: {:ok, map()} | {:error, String.t()}
  def resolve(request) when is_map(request) do
    with :ok <- active(),
         %{actor: actor, resolved: manifest, resolved_authority: authority} <- request,
         true <- valid_actor?(actor) and is_list(manifest) and valid_authority?(authority),
         {:ok, resources, events} <- citations(manifest) do
      {:ok,
       %{
         actor: actor,
         resolved_authority: authority,
         resources: resources,
         events: events,
         generations: Process.get(@key).generations
       }}
    else
      {:error, reason} -> fail(reason)
      _ -> fail("malformed resolved request")
    end
  rescue
    error ->
      fail("policy fact resolution raised")
      reraise error, __STACKTRACE__
  catch
    kind, reason ->
      fail("policy fact resolution interrupted")
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  def resolve(_), do: fail("malformed resolved request")

  @doc "Fetch an admitted resource by group/version/Kind/name, tracking its generation."
  @spec fetch(String.t()) :: {:ok, map()} | {:error, String.t()}
  def fetch(ref) do
    with :ok <- active(),
         {:ok, g, v, k, n} <- R5e.Refs.split_kind_ref(ref),
         {:ok, entry, _} <- R5e.ResourceStore.get(g, v, k, n),
         %{"spec" => spec, "admissionSeq" => seq} <- entry,
         true <- is_map(spec) and is_integer(seq) and seq >= 0,
         true <- is_binary(entry["actor"]) and entry["actor"] != "",
         true <- R5e.Refs.valid_value?(%{"event" => ""}, entry["admissionEvent"]),
         :ok <- track(ref, seq) do
      {:ok, entry}
    else
      {:error, reason} -> fail("#{inspect(ref)}: #{inspect(reason)}")
      _ -> fail("malformed policy fact #{inspect(ref)}")
    end
  rescue
    error ->
      fail("policy fact read raised")
      reraise error, __STACKTRACE__
  catch
    kind, reason ->
      fail("policy fact read interrupted")
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  @doc "Read an immutable admission event and its decoded payload from this chain."
  @spec event(String.t()) :: {:ok, map()} | {:error, String.t()}
  def event(ref) do
    with :ok <- active(),
         true <- R5e.Refs.valid_value?(%{"event" => ""}, ref),
         "event:" <> hash <- ref,
         {:ok, history} <- R5e.Log.strict_events(),
         %{"kind" => kind} = event <- Enum.find(history, &(&1["hash"] == hash)),
         true <- kind in ["admission.granted", "admission.denied"],
         {:ok, payload} when is_map(payload) <- R5e.Log.strict_payload(event),
         true <-
           is_map(payload["spec"]) and is_map(payload["target"]) and
             valid_actor?(payload["actor"]) do
      {:ok, %{event: event, payload: payload}}
    else
      _ -> fail("missing or malformed admission event #{inspect(ref)}")
    end
  rescue
    error ->
      fail("policy fact read raised")
      reraise error, __STACKTRACE__
  catch
    kind, reason ->
      fail("policy fact read interrupted")
      :erlang.raise(kind, reason, __STACKTRACE__)
  end

  defp citations(manifest) do
    Enum.reduce_while(manifest, {:ok, %{}, %{}}, fn
      %{"class" => "kind", "value" => ref}, {:ok, resources, events} ->
        case fetch(ref) do
          {:ok, entry} -> {:cont, {:ok, Map.put(resources, ref, entry), events}}
          error -> {:halt, error}
        end

      %{"class" => "event", "value" => ref}, {:ok, resources, events} ->
        case event(ref) do
          {:ok, fact} -> {:cont, {:ok, resources, Map.put(events, ref, fact)}}
          error -> {:halt, error}
        end

      %{"class" => "bytes"}, acc ->
        {:cont, acc}

      _, _ ->
        {:halt, fail("malformed resolution manifest")}
    end)
  end

  defp valid_actor?(%{"id" => id}), do: is_binary(id) and id != ""
  defp valid_actor?(_), do: false

  defp valid_authority?(authority) when is_list(authority) do
    Enum.all?(authority, fn
      %{"index" => i, "value" => ref, "chain" => [_ | _] = chain} ->
        is_integer(i) and i >= 0 and R5e.Refs.valid_value?(%{"event" => ""}, ref) and
          Enum.all?(chain, &valid_link?/1)

      _ ->
        false
    end)
  end

  defp valid_authority?(_), do: false

  defp valid_link?(%{"seq" => seq, "actor" => actor, "value" => ref, "kind" => kind}) do
    is_integer(seq) and seq >= 0 and is_binary(actor) and actor != "" and
      is_binary(kind) and R5e.Refs.valid_value?(%{"event" => ""}, ref)
  end

  defp valid_link?(_), do: false

  defp active do
    if Process.get(@key), do: :ok, else: {:error, "policy facts require an active decision"}
  end

  defp track(ref, seq) do
    state = Process.get(@key)

    case Map.fetch(state.generations, ref) do
      {:ok, other} when other != seq ->
        fail("conflicting generations for #{ref}")

      _ ->
        Process.put(@key, %{state | generations: Map.put(state.generations, ref, seq)})
        :ok
    end
  end

  defp fail(reason) do
    if state = Process.get(@key), do: Process.put(@key, %{state | error: state.error || reason})
    {:error, reason}
  end
end

