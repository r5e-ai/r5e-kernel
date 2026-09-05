defmodule R5e.StoryOneTest do
  @moduledoc """
  Story 1, end to end, with **real refs**: a fresh kernel admits the nine
  gateway seeds, then records one turn of agent work —

      AgentSession → Prompt → LlmCall → ToolCall ×2 (the second denied by
      the policy in force) → Completion → LlmResponse{toolCalls: [both]}
      → ToolResult

  — each step citing the previous receipts' returned names and event refs,
  and each citation resolved at admission (spec/05 §4). The chain is then
  exported and verified offline: findings none, and the verifier's `refs:`
  line re-derives every entry of every manifest from the bundle alone.

  This is the claim the sub-slice is for. A ref that resolves at admission
  and cannot be re-derived from the export would mean the kernel knew
  something the record does not carry, which is the failure mode the whole
  design exists to refuse.
  """

  use ExUnit.Case, async: false

  @seeds "test/vectors/gateway/*.json" |> Path.wildcard() |> Enum.sort()
  @actor %{"id" => "agent:claude-code", "keyFingerprint" => "sha256:test-agent"}

  defmodule Policy do
    @moduledoc false
    # A policy with something to say: it denies one tool by name, and
    # every receipt it writes cites the admitted bundle it decided under,
    # so a reader of the export can fetch the rule that denied.
    @behaviour R5e.Policy

    @impl true
    def authorize(request) do
      bundle = Application.get_env(:r5e, :story_bundle)

      # The manifest is on the request as `resolved` (§4): a policy sees
      # what the kernel already looked up rather than looking it up again.
      cited = Enum.map(request[:resolved] || [], & &1["path"])

      case {request.kind, request.spec["tool"]} do
        {"ToolCall", "rm"} ->
          {:deny, "tool \"rm\" is not permitted for this session",
           meta(bundle, "deny", ["no-destructive-tools"], cited)}

        _ ->
          {:ok, meta(bundle, "allow", [], cited)}
      end
    end

    defp meta(bundle, decision, matched, cited) do
      %{
        "engine" => "story-policy",
        "decision" => decision,
        "bundle" => bundle && bundle["address"],
        "bundleRef" => bundle && bundle["ref"],
        "matched" => matched,
        "resolvedPaths" => cited
      }
    end
  end

  test "one turn of agent work, recorded with real refs, exported and re-derived offline" do
    dest = Path.join(System.tmp_dir!(), "r5e-story-#{System.unique_integer([:positive])}")
    on_exit(fn -> File.rm_rf(dest) end)

    R5e.Vectors.with_fresh_kernel(fn ->
      for path <- @seeds do
        {:ok, _} = R5e.Vectors.admit_definition(path |> File.read!() |> Jason.decode!())
      end

      # Four raw objects, each put on the record the way `PUT /cas` puts
      # one (§5): `R5e.CAS.admit/3` is the function the router calls, so
      # every `bytes:` ref below cites bytes a granted `CasObject`
      # admission wrote, and every such manifest entry names that
      # admission rather than recording a null.
      policy_source = "permit(principal, action, resource) unless { resource.tool == \"rm\" };"
      prompt_bytes = "list the files, then remove the temp directory"
      completion_bytes = ~s({"content":"I'll list the files first."})
      args_bytes = ~s({"command":"ls -la"})

      policy_ref = put_object(policy_source, "text/plain")
      prompt_ref = put_object(prompt_bytes, "text/plain")
      completion_ref = put_object(completion_bytes, "application/json")
      args_ref = put_object(args_bytes, "application/json")

      # The bundle is admitted before it can govern anything: the
      # bootstrap fixpoint, and the verifier counts it as one.
      {:ok, bundle} =
        admit("PolicyBundle", "active", %{
          "engine" => "cedar",
          "sourceRef" => %{"$ref" => policy_ref},
          "description" => "no destructive tools"
        })

      {:ok, %{"eventRef" => policy_object_event}} = R5e.RefIndex.cas_object(policy_ref)

      # The bundle's `sourceRef` declares `retention: "public-record"`
      # (§4), and the manifest carries the declaration onto the record —
      # which is what makes the rule answerable later from the chain
      # alone: no `CasExpired` for these bytes can ever be admitted, and
      # the denial can name this seq without re-reading the Kind.
      assert bundle["resolvedRefs"] == [
               %{
                 "path" => "/sourceRef",
                 "class" => "bytes",
                 "value" => policy_ref,
                 "size" => byte_size(policy_source),
                 "casObjectEvent" => policy_object_event,
                 "retention" => "public-record"
               }
             ]

      assert [%{"retention" => "public-record"}] =
               R5e.RefIndex.public_record_citations(policy_ref)

      Application.put_env(:r5e, :story_bundle, %{
        "address" => bundle["specAddress"],
        "ref" => "gateway.r5e.io/v1alpha1/PolicyBundle/active"
      })

      previous_policy = Application.get_env(:r5e, :policy)
      Application.put_env(:r5e, :policy, Policy)

      on_exit(fn ->
        Application.put_env(:r5e, :policy, previous_policy || R5e.Policy.AllowAll)
        Application.delete_env(:r5e, :story_bundle)
      end)

      # 1. the session: server-named, so its name *is* its admission event
      {:ok, session} = admit("AgentSession", nil, %{"harness" => "claude-code"})
      session_path = "gateway.r5e.io/v1alpha1/AgentSession/" <> session["name"]

      # 2. the prompt: detached bytes plus the session it belongs to
      {:ok, prompt} =
        admit("Prompt", nil, %{
          "contentRef" => %{"$ref" => prompt_ref},
          "role" => "user",
          "session" => %{"$ref" => session_path}
        })

      assert manifest(prompt) == [
               {"/contentRef", "bytes", prompt_ref},
               {"/session", "kind", session_path}
             ]

      assert entry_of(prompt, "/session")["generation"] == session["seq"]

      # 3. the call: a kind ref to the prompt artifact, by its content name
      prompt_path = "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]

      {:ok, call} =
        admit("LlmCall", nil, %{
          "model" => "claude-sonnet-4",
          "prompt" => %{"$ref" => prompt_path},
          "session" => %{"$ref" => session_path},
          "transport" => "https"
        })

      assert manifest(call) == [
               {"/prompt", "kind", prompt_path},
               {"/session", "kind", session_path}
             ]

      # 4. two tool calls extracted from the response, in the model's
      #    order. The second asks for a tool the bundle refuses.
      {:ok, ls} =
        admit("ToolCall", nil, %{
          "tool" => "bash",
          "argsRef" => %{"$ref" => args_ref},
          "argsMediaType" => "application/json",
          "llmCall" => %{"$ref" => call["eventRef"]},
          "index" => 0,
          "session" => %{"$ref" => session_path}
        })

      {:denied, rm} =
        admit("ToolCall", nil, %{
          "tool" => "rm",
          "args" => %{"path" => "/tmp"},
          "llmCall" => %{"$ref" => call["eventRef"]},
          "index" => 1,
          "session" => %{"$ref" => session_path}
        })

      assert rm["reason"] == "authorize: tool \"rm\" is not permitted for this session"
      assert rm["policy"]["bundle"] == bundle["specAddress"]

      # A denial resolved its refs before policy saw it — the manifest is
      # on the denial's record too, because asking is itself an act.
      assert manifest(rm) == [
               {"/llmCall", "event", call["eventRef"]},
               {"/session", "kind", session_path}
             ]

      assert rm["policy"]["resolvedPaths"] == ["/llmCall", "/session"]

      # 5. the completion, and the response citing both tool calls
      {:ok, completion} =
        admit("Completion", nil, %{
          "contentRef" => %{"$ref" => completion_ref},
          "mediaType" => "application/json"
        })

      completion_path = "gateway.r5e.io/v1alpha1/Completion/" <> completion["name"]

      {:ok, response} =
        admit("LlmResponse", nil, %{
          "llmCall" => %{"$ref" => call["eventRef"]},
          "outcome" => "ok",
          "completion" => %{"$ref" => completion_path},
          "toolCalls" => [
            %{"$ref" => ls["eventRef"]},
            %{"$ref" => rm["eventRef"]}
          ],
          "upstreamStatus" => 200
        })

      # Sorted by pointer, array members individually, and the denied tool
      # call cited as what it is: `outcome: any` is what makes a refused
      # act citable at all.
      assert manifest(response) == [
               {"/completion", "kind", completion_path},
               {"/llmCall", "event", call["eventRef"]},
               {"/toolCalls/0", "event", ls["eventRef"]},
               {"/toolCalls/1", "event", rm["eventRef"]}
             ]

      assert entry_of(response, "/toolCalls/0")["outcome"] == "admitted"
      assert entry_of(response, "/toolCalls/1")["outcome"] == "denied"

      # 6. the result of the tool call that was allowed
      {:ok, result} =
        admit("ToolResult", nil, %{
          "toolCall" => %{"$ref" => ls["eventRef"]},
          "outcome" => "ok",
          "result" => %{"stdout" => "total 0\n"},
          "durationMs" => 12
        })

      assert manifest(result) == [{"/toolCall", "event", ls["eventRef"]}]

      # -- offline ------------------------------------------------------

      {:ok, ^dest, export} = R5e.Export.run(dest)
      {:ok, report} = RecurseVerify.run(dest)

      assert report.findings == [], Enum.join(report.findings, "\n")

      # 16 refs across the eight receipts that cite anything: six kind
      # refs, six event refs (one of them naming the denial), four
      # objects.
      refs_line = Enum.find(report.checked, &String.starts_with?(&1, "refs:"))
      assert refs_line =~ "16 typed refs recorded across 8/"
      assert refs_line =~ "(bytes 4, event 6, kind 6)"
      assert refs_line =~ "every one re-derived from this bundle"
      assert refs_line =~ "backed by the CasObject admission the entry names"

      # Every `bytes:` ref is backed: the four objects were admitted, and
      # the verifier found each admission on the chain rather than taking
      # the manifest's word for it.
      assert Enum.all?(
               [prompt_ref, completion_ref, args_ref, policy_ref],
               fn address ->
                 match?({:ok, %{"eventRef" => _}}, R5e.RefIndex.cas_object(address))
               end
             )

      cas_line = Enum.find(report.checked, &String.starts_with?(&1, "cas:"))
      assert cas_line =~ "4 object(s) admitted, 0 expired, 0 kernel-derived"
      assert cas_line =~ "every object in this bundle's CAS is accounted for"

      # Every object the refs cite was swept, including the `bytes:` ones
      # (§6) — the export matches `sha256:` and `bytes:` alike.
      assert export["missingObjects"] == []

      for object <- [policy_ref, prompt_ref, completion_ref, args_ref] do
        assert RecurseVerify.CAS.intact?(Path.join(dest, "cas"), object),
               "#{object} was not swept into the bundle"
      end

      # The kinds block carries what the seeds declare (§10).
      output = RecurseVerify.format(report)
      assert output =~ "naming: content"
      assert output =~ "naming: server"
      assert output =~ "description: A span of work by one actor"
    end)
  end

  defp put_object(bytes, media_type) do
    {:ok, _receipt, address, _size} = R5e.TestHelpers.cas_admit(@actor, bytes, media_type)
    address
  end

  defp admit(kind, name, spec) do
    R5e.TestHelpers.admit_request(%{
      actor: @actor,
      group: "gateway.r5e.io",
      version: "v1alpha1",
      kind: kind,
      name: name,
      spec: spec
    })
  end

  defp manifest(receipt) do
    assert receipt["resolvedRefs"] == R5e.TestHelpers.payload_of(receipt)["resolvedRefs"],
           "the receipt's manifest and the recorded one differ"

    for entry <- receipt["resolvedRefs"], do: {entry["path"], entry["class"], entry["value"]}
  end

  defp entry_of(receipt, path),
    do: Enum.find(receipt["resolvedRefs"], &(&1["path"] == path))
end
