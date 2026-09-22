# SPDX-License-Identifier: AGPL-3.0-only
defmodule R5e.Policy.Facts do
  @moduledoc """
  Optimistic, tracked resource reads for policy adapters.

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

  Tracking is scoped to one decision, restored on nested decisions, and cleaned
  up on exceptions and retries. Direct ResourceStore reads and child processes
  are outside this contract; adapters must use `fetch/1` for every resource hop.
  """
  @key {__MODULE__, :reads}

  @doc false
  def run(fun, finalize) do
    previous = Process.get(@key)
    Process.put(@key, %{generations: %{}, error: nil})

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
    Enum.reduce(child.generations, %{parent | error: parent.error || child.error}, fn {ref, seq},
                                                                                      acc ->
      case Map.fetch(acc.generations, ref) do
        {:ok, other} when other != seq ->
          %{acc | error: acc.error || "conflicting nested generations for #{ref}"}

        _ ->
          %{acc | generations: Map.put(acc.generations, ref, seq)}
      end
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
         %{"kind" => kind} = event <- Enum.find(R5e.Log.events(), &(&1["hash"] == hash)),
         true <- kind in ["admission.granted", "admission.denied"],
         {:ok, payload} when is_map(payload) <- R5e.Log.payload(event),
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
