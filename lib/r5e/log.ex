defmodule R5e.Log do
  @moduledoc """
  The event log substrate: append-only, hash-chained JSONL at
  `<data_dir>/log.jsonl`, with an RFC 9162 Merkle tree maintained over
  the event hashes alongside the linear chain. A single GenServer
  serializes appends; chain and tree math live in the standalone
  verifier package (`RecurseVerify.Chain` / `RecurseVerify.Merkle`), so
  the writer and any checker share the same code.

  The linear chain orders and links events; the Merkle tree is what makes
  the log *provable*: inclusion proofs (this event is in the attested
  tree) and consistency proofs (that older checkpoint's tree is a prefix
  of this one — append-only, nothing rewritten).

  ## The append lock is the commit lock (spec/05 §7)

  This GenServer is the kernel's one lock, and §7's commit protocol is
  built on that and on nothing else — no second lock, no distributed
  anything, all of it per node.

  `commit/4` is what a **granted** admission calls. Under the one lock,
  in this order:

  1. if the node is `halted`, nothing is appended and the caller is told
     to deny at stage `record`;
  2. `R5e.Commit.terminal/1` re-checks the facts a retry could not fix —
     spec 011 §6's `expires`, and later its authority terms and
     revocations; a mismatch appends nothing and the caller denies at
     `record`, terminally;
  3. `R5e.Commit.stale/1` re-checks every generation the admission
     captured; a mismatch appends nothing and the caller retries from
     `resolve`;
  3. the event payload is durably stored in the CAS, then the complete
     event line is appended and synced to the log;
  4. the substrate write runs — inside the same call, so no other
     admission can observe the store between the two.

  Step 3 before step 4 is the legible-gap rule and is unchanged. The
  caller receives no event or grant until the relevant file and directory
  syncs have completed. What §7
  adds is that the window is closed to *other admissions*: a reader of the
  store under this lock sees every earlier granted admission's effect, so
  "the generation this admission read has not moved" means what it says.

  A substrate failure in step 4 does not crash the log — the event is
  already on the chain and the state advances — it sets `halted` on this
  node. Every later granted admission is then refused at step 1 until
  `resume/0` (which `R5e.Bootstrap.replay/0` calls) or a restart, whose
  `init/1` starts clean because the log on disk is the record and the
  halt is not on it.

  `append/2` is the unconditional path and is what a **denial** record
  uses. A denial carries no capture, so it can be neither contended nor
  halted: the record of a refusal must land, including the record of a
  refusal caused by contention or by a halt.
  """

  use GenServer

  @history_marker "history.initialized"
  @history_marker_bytes "r5e-event-log/v1\n"

  @checkpoint_payload_type "application/vnd.r5e.checkpoint+json"

  def checkpoint_payload_type, do: @checkpoint_payload_type

  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, name: __MODULE__)

  @doc """
  Store `payload` (a map) in the CAS and append a chained event referencing
  it. Returns the appended event map (including its hash).
  """
  @spec append(String.t(), map()) :: map()
  def append(event_kind, payload) when is_map(payload) do
    case GenServer.call(__MODULE__, {:append, event_kind, payload}) do
      {:persistence_failed, _reason, error, stacktrace} -> reraise error, stacktrace
      event -> event
    end
  end

  @doc """
  Append a **granted** admission's event and perform its substrate write,
  under one lock, having first re-checked `capture` (spec/05 §7). See the
  moduledoc for the order and why it is that order.

  `admit_fun` is the substrate write, called with the appended event and
  returning whatever the caller wants back (the kernel passes the
  admitted spec's CAS address). It runs inside this GenServer, so it must
  not call back into `R5e.Log`.

  Returns

    * `{:ok, event, result}` — appended and written;
    * `{:retry, moved}` — nothing appended; a captured generation moved,
      and `moved` says which;
    * `{:refused, reason}` — nothing appended; a §6 terminal fact moved
      (`expires`, a cited authority revoked, or a visited term ended),
      and retrying cannot make it true again;
    * `{:halted, reason}` — nothing appended; this node halted earlier;
    * `{:failed, event, reason, error, stacktrace}` — appended, the
      substrate write raised, the node is now halted. The caller re-raises:
      the act is on the chain and the caller is owed the failure, not a
      denial receipt that would contradict the record.
  """
  @spec commit(String.t(), map(), map(), (map() -> term())) ::
          {:ok, map(), term()}
          | {:retry, String.t()}
          | {:refused, String.t()}
          | {:halted, String.t()}
          | {:persistence_failed, String.t(), Exception.t(), Exception.stacktrace()}
          | {:failed, map(), String.t(), Exception.t(), Exception.stacktrace()}
  def commit(event_kind, payload, capture, admit_fun)
      when is_map(payload) and is_map(capture) and is_function(admit_fun, 1) do
    GenServer.call(__MODULE__, {:commit, event_kind, payload, capture, admit_fun})
  end

  @doc "The halt reason on this node (spec/05 §7), or `nil`."
  @spec halted() :: nil | String.t()
  def halted, do: GenServer.call(__MODULE__, :halted)

  @doc """
  Clear the halt. Called by `R5e.Bootstrap.replay/0` — the halt says the
  derived views may be behind the chain, and a replay is exactly what
  makes them agree again. A restart clears it too, by starting clean.
  """
  @spec resume() :: :ok
  def resume, do: GenServer.call(__MODULE__, :resume)

  @doc "All events, oldest first."
  @spec events() :: [map()]
  def events, do: GenServer.call(__MODULE__, :events)

  @doc """
  All events, oldest first, read straight from the log on disk — the same
  answer `events/0` gives, for callers that must not go through this
  GenServer: `R5e.Commit`'s re-check runs *inside* it, and
  `R5e.Bootstrap.replay/0` runs before it is asked anything. An unreadable
  or absent log is `[]`; `verify/0` is where its unreadability is a finding.
  """
  @spec read_events(Path.t() | nil) :: [map()]
  def read_events(path \\ nil) do
    case R5e.Chain.read_log(path || log_path()) do
      {:ok, events} -> events
      _ -> []
    end
  end

  @doc """
  The decoded payload of an event, or `:error` when this deployment no
  longer holds it (§6: the payload is swept with the event). Four readers
  of the chain asked this question three ways before.
  """
  @spec payload(map()) :: {:ok, map()} | :error
  def payload(event) do
    with {:ok, bytes} <- R5e.CAS.get(event["payload"] || ""),
         {:ok, decoded} <- Jason.decode(bytes) do
      {:ok, decoded}
    else
      _ -> :error
    end
  end

  @doc "Merkle leaves: the event hashes, oldest first."
  @spec leaves() :: [String.t()]
  def leaves, do: GenServer.call(__MODULE__, :leaves)

  @doc "Verify the whole chain on disk. See `RecurseVerify.Chain.verify_events/1`."
  def verify do
    case R5e.Chain.read_log(log_path()) do
      {:ok, events} -> R5e.Chain.verify_events(events)
      {:error, :enoent} -> {:ok, 0}
      {:error, reason} -> {:error, [%{seq: nil, problem: "log unreadable: #{inspect(reason)}"}]}
    end
  end

  @doc """
  A signed tree head (STH): the claim

      %{"treeSize" => n, "merkleRoot" => <hex of RFC 9162 MTH over the
        n event hashes>, "chainHead" => <last event hash>, "ts" => ...}

  canonically encoded, DSSE-enveloped, signed by the node key.

  What the signature attests: log integrity as claimed by the holder of
  this key at this moment — nothing about who holds the key
  (key-to-identity binding awaits endorsement chains, spec/03). Given two
  STHs, a consistency proof shows the later tree extends the earlier one
  append-only. SLICE: detecting equivocation (different STHs served to
  different audiences) requires independent witnesses gossiping STHs —
  out of scope here and named in the verifier's not-checked list.
  """
  @spec checkpoint() :: map()
  def checkpoint, do: GenServer.call(__MODULE__, :checkpoint)

  def log_path, do: Path.join(Application.fetch_env!(:r5e, :data_dir), "log.jsonl")

  @doc "The durable marker that distinguishes a used data directory from first boot."
  def history_marker_path,
    do: Path.join(Application.fetch_env!(:r5e, :data_dir), @history_marker)

  @doc "Refuse missing acknowledged history before startup can create new identity files."
  def validate_storage_presence! do
    case File.stat(log_path()) do
      {:ok, %{size: 0}} -> fresh_presence_or_raise!("zero-length")
      {:ok, _stat} -> :ok
      {:error, :enoent} -> fresh_presence_or_raise!("missing")
      {:error, reason} -> raise File.Error, reason: reason, action: "inspect", path: log_path()
    end
  end

  # -- GenServer ---------------------------------------------------------

  @impl true
  def init(_opts) do
    path = log_path()
    R5e.Persistence.ensure_dir!(Path.dirname(path))

    case load(path) do
      {:ok, {seq, prev, leaves}} ->
        {:ok, %{path: path, seq: seq, prev: prev, leaves: leaves, halted: nil}}

      {:error, reason} ->
        {:stop, {:invalid_event_log, reason}}
    end
  end

  @impl true
  def handle_call({:append, event_kind, payload}, _from, state) do
    try do
      {event, state} = do_append(event_kind, payload, state)
      {:reply, event, state}
    rescue
      error -> persistence_failure(error, __STACKTRACE__, state)
    end
  end

  # §7's commit. The three refusals come first and append nothing; only
  # then is the event written, and only then the substrate.
  def handle_call({:commit, event_kind, payload, capture, admit_fun}, _from, state) do
    # §5/§6: `ts(s)` is read **once** here and used twice — by the terminal
    # re-check, which compares every visited authority term against it, and
    # by the event this call is about to write. Two reads could land on
    # either side of a second boundary and put a `ts` on the record that
    # the term check never saw.
    ts = R5e.Clock.ts()

    cond do
      state.halted != nil ->
        {:reply, {:halted, state.halted}, state}

      (reason = R5e.Commit.terminal(capture, ts)) != nil ->
        {:reply, {:refused, reason}, state}

      (moved = R5e.Commit.stale(capture)) != nil ->
        {:reply, {:retry, moved}, state}

      true ->
        try do
          {event, state} = do_append(event_kind, payload, state, ts)
          substrate(event, payload, admit_fun, state)
        rescue
          error -> persistence_failure(error, __STACKTRACE__, state)
        end
    end
  end

  def handle_call(:halted, _from, state), do: {:reply, state.halted, state}
  def handle_call(:resume, _from, state), do: {:reply, :ok, %{state | halted: nil}}

  def handle_call(:events, _from, state), do: {:reply, read_events(state.path), state}

  def handle_call(:leaves, _from, state), do: {:reply, state.leaves, state}

  def handle_call(:checkpoint, _from, state) do
    claim = %{
      "treeSize" => state.seq,
      "merkleRoot" => RecurseVerify.Merkle.hex(RecurseVerify.Merkle.root(state.leaves)),
      "chainHead" => state.prev,
      "ts" => R5e.Clock.ts()
    }

    signed = %{
      "checkpoint" => claim,
      "envelope" => R5e.DSSE.envelope(@checkpoint_payload_type, R5e.Canonical.encode(claim)),
      "keyId" => R5e.SignerProvider.key_id()
    }

    {:reply, signed, state}
  end

  # -- internals ---------------------------------------------------------

  defp do_append(event_kind, payload, state, ts \\ nil) do
    payload_addr = R5e.CAS.put(R5e.Canonical.encode(payload))
    event = R5e.Chain.build_event(state.seq + 1, state.prev, event_kind, payload_addr, ts)
    R5e.Persistence.append!(state.path, Jason.encode!(event) <> "\n")
    if state.seq == 0, do: ensure_history_marker!()

    {event,
     %{
       state
       | seq: event["seq"],
         prev: event["hash"],
         leaves: state.leaves ++ [event["hash"]]
     }}
  end

  defp load(path) do
    case File.read(path) do
      {:error, :enoent} ->
        fresh_log_or_refusal("missing")

      {:error, reason} ->
        {:error, "cannot read #{path}: #{inspect(reason)}"}

      {:ok, bytes} ->
        if bytes == "" do
          fresh_log_or_refusal("zero-length")
        else
          with :ok <- valid_framing(bytes),
               {:ok, events} <- R5e.Chain.read_log(path),
               :ok <- valid_chain(events),
               :ok <- valid_payloads(events) do
            last = List.last(events)
            ensure_history_marker!()
            {:ok, {last["seq"], last["hash"], Enum.map(events, & &1["hash"])}}
          else
            {:error, reason} -> {:error, reason}
          end
        end
    end
  end

  defp fresh_log_or_refusal(state) do
    evidence = persistent_history_evidence()

    if evidence == [] do
      {:ok, {0, R5e.Chain.genesis(), []}}
    else
      {:error,
       "refusing writable startup: event log is #{state} while persistent history evidence " <>
         "remains (#{Enum.join(evidence, ", ")}); restore the acknowledged log or recover into " <>
         "a new data directory"}
    end
  end

  defp fresh_presence_or_raise!(state) do
    case fresh_log_or_refusal(state) do
      {:ok, _fresh} -> :ok
      {:error, reason} -> raise reason
    end
  end

  defp persistent_history_evidence do
    data_dir = Application.fetch_env!(:r5e, :data_dir)

    [
      {"history marker", history_marker_path()},
      {"persisted origin", Path.join([data_dir, "keys", "origin.json"])},
      {"CAS entries", R5e.CAS.root()}
    ]
    |> Enum.flat_map(fn
      {"CAS entries" = label, path} -> if directory_populated!(path), do: [label], else: []
      {label, path} -> if file_present!(path), do: [label], else: []
    end)
  end

  defp ensure_history_marker! do
    path = history_marker_path()

    case File.read(path) do
      {:ok, @history_marker_bytes} ->
        R5e.Persistence.sync_existing!(path, @history_marker_bytes)

      {:ok, _other} ->
        raise "invalid event-log history marker at #{path}"

      {:error, :enoent} ->
        R5e.Persistence.write_atomic!(path, @history_marker_bytes, replace: false)

      {:error, reason} ->
        raise File.Error, reason: reason, action: "read", path: path
    end
  end

  defp directory_populated!(path) do
    case File.ls(path) do
      {:ok, entries} -> entries != []
      {:error, :enoent} -> false
      {:error, reason} -> raise File.Error, reason: reason, action: "list directory", path: path
    end
  end

  defp file_present!(path) do
    case File.stat(path) do
      {:ok, _stat} -> true
      {:error, :enoent} -> false
      {:error, reason} -> raise File.Error, reason: reason, action: "inspect", path: path
    end
  end

  defp valid_framing(""), do: :ok

  defp valid_framing(bytes) do
    if :binary.last(bytes) != ?\n do
      {:error, "refusing to modify a log whose final record is not newline-terminated"}
    else
      records = bytes |> :binary.split("\n", [:global]) |> Enum.drop(-1)

      case Enum.find_index(records, &(&1 == "")) do
        nil ->
          :ok

        index ->
          {:error, "refusing to modify a log containing an empty record at line #{index + 1}"}
      end
    end
  end

  defp valid_chain(events) do
    case R5e.Chain.verify_events(events) do
      {:ok, _count} ->
        :ok

      {:error, findings} ->
        details =
          Enum.map_join(findings, "; ", fn finding ->
            "seq #{inspect(finding.seq)}: #{finding.problem}"
          end)

        {:error, "refusing to modify a malformed or corrupt log: " <> details}
    end
  end

  # An exported chain remains inspectable when a detached payload was erased:
  # the offline verifier reports a disclosed gap. A writable kernel has a
  # stricter obligation. Bootstrap rebuilds policy, authority, revocation,
  # nonce, and resource views from these payloads; silently skipping one could
  # remove a restriction and then admit new work under incomplete state.
  defp valid_payloads(events) do
    Enum.find_value(events, :ok, fn event ->
      address = event["payload"]

      cond do
        not R5e.CAS.object_address?(address) ->
          {:error,
           "refusing writable startup: event at seq #{inspect(event["seq"])} has invalid " <>
             "payload address #{inspect(address)}"}

        not RecurseVerify.CAS.intact?(R5e.CAS.root(), address) ->
          {:error,
           "refusing writable startup: event payload #{address} at seq #{event["seq"]} is " <>
             "missing or does not hash to its address; replay cannot reconstruct admission state"}

        true ->
          false
      end
    end)
  end

  defp persistence_failure(error, stacktrace, state) do
    reason =
      "event persistence failed before acknowledgement at seq #{state.seq + 1}: " <>
        Exception.message(error)

    {:stop, {:persistence_failure, reason}, {:persistence_failed, reason, error, stacktrace},
     state}
  end

  # The substrate write of a granted admission, inside the lock and after
  # the append. A failure here is the one §7 calls post-record: the act is
  # on the chain, the deployment's derived state is not, and the honest
  # response is to stop admitting rather than to keep going on views that
  # no longer match the record.
  defp substrate(event, payload, admit_fun, state) do
    case admit_fun.(event) do
      # A write that reports failure rather than raising is the same
      # failure and is turned into one, so there is a single halt path.
      {:error, reason} -> raise "the substrate write reported #{inspect(reason)}"
      result -> {:reply, {:ok, event, result}, state}
    end
  rescue
    error ->
      reason =
        "halted: the substrate write for the granted admission at seq #{event["seq"]} " <>
          "(#{R5e.Admission.target_path(payload)}) failed — " <>
          "#{Exception.message(error)}; this node denies every admission at record until replay"

      {:reply, {:failed, event, reason, error, __STACKTRACE__}, %{state | halted: reason}}
  end
end
