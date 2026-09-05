defmodule R5e.GatewaySeedsTest do
  @moduledoc """
  The nine `gateway.r5e.io/v1alpha1` seeds are the shapes schema-lite v2 was
  written for. They live here verbatim, as fixtures — the kernel does not
  ship them (they belong to the gateway group, not to core) — and this test
  is the claim that the validator accepts them and the Story-1 instance
  shapes they describe.
  """

  use ExUnit.Case, async: false

  @seeds "test/vectors/gateway/*.json" |> Path.wildcard() |> Enum.sort()
  @event_ref "event:sha256:" <> String.duplicate("ab", 32)

  for seed <- @seeds do
    @external_resource seed
  end

  test "all nine seeds are admitted as KindDefinitions against the v2 meta-Kind" do
    R5e.Vectors.with_fresh_kernel(fn ->
      assert length(@seeds) == 9

      for path <- @seeds do
        spec = path |> File.read!() |> Jason.decode!()

        case R5e.Vectors.admit_definition(spec) do
          {:ok, receipt} ->
            assert receipt["name"] ==
                     "#{spec["group"]}/#{spec["version"]}/#{spec["kind"]}"

            assert receipt["specAddress"] == R5e.Canonical.hash(spec)

          {:denied, receipt} ->
            flunk("#{Path.basename(path)} was denied: #{receipt["reason"]}")
        end
      end

      # GET /apis carries what the definitions declare: naming and description.
      {:ok, tool_call} = R5e.KindRegistry.get("gateway.r5e.io", "v1alpha1", "ToolCall")
      map = R5e.Kind.to_map(tool_call)

      assert map["naming"] == %{"mode" => "content"}
      assert map["description"] =~ "invoke a tool"
      refute Map.has_key?(map, "derivedFrom")

      {:ok, shape} = R5e.KindRegistry.get("gateway.r5e.io", "v1alpha1", "PolicyShape")

      assert R5e.Kind.to_map(shape)["naming"] == %{
               "mode" => "derived",
               "derive" => "{engine}.{kind}"
             }
    end)
  end

  test "the Story-1 shapes A1 named are admitted: toolCalls: [], args: {}, result: \"\"" do
    R5e.Vectors.with_fresh_kernel(fn ->
      for path <- @seeds do
        {:ok, _} = R5e.Vectors.admit_definition(path |> File.read!() |> Jason.decode!())
      end

      # Every ref here is real: `resolve` (§4) looks each one up, so the
      # empty-shaped cases A1 named — `toolCalls: []`, `args: {}`,
      # `result: ""` — can only be shown against targets that exist.
      # SLICE (CS-1c): the prompt's bytes are put in the CAS directly;
      # `PUT /cas` admits a CasObject instead once §5 lands.
      content = R5e.TestHelpers.put_object("write me a haiku")

      {:ok, prompt} = admit("Prompt", %{"contentRef" => %{"$ref" => content}, "role" => "user"})

      {:ok, call} =
        admit("LlmCall", %{
          "model" => "claude-sonnet-4",
          "prompt" => %{"$ref" => "gateway.r5e.io/v1alpha1/Prompt/" <> prompt["name"]}
        })

      # An error response cites the call, extracted no tool calls, and
      # carries no completion — `requires` only asks for one when the
      # outcome is `ok`.
      {:ok, response} =
        admit("LlmResponse", %{
          "llmCall" => %{"$ref" => call["eventRef"]},
          "outcome" => "error",
          "toolCalls" => [],
          "upstreamStatus" => 502,
          "errorKind" => "upstream_5xx"
        })

      assert response["name"] =~ ~r/^sha256:[0-9a-f]{64}$/

      assert response["resolvedRefs"] == [
               %{
                 "path" => "/llmCall",
                 "class" => "event",
                 "value" => call["eventRef"],
                 "seq" => seq_of(call),
                 "outcome" => "admitted",
                 "targetKind" => "gateway.r5e.io/v1alpha1/LlmCall"
               }
             ]

      {:ok, tool_call} = admit("ToolCall", %{"tool" => "bash", "args" => %{}})
      assert tool_call["outcome"] == "admitted"
      assert tool_call["resolvedRefs"] == []

      {:ok, result} =
        admit("ToolResult", %{
          "toolCall" => %{"$ref" => tool_call["eventRef"]},
          "outcome" => "ok",
          "result" => ""
        })

      assert result["outcome"] == "admitted"

      # An AgentSession is server-named: the kernel assigns it.
      {:ok, session} = admit("AgentSession", %{"harness" => "claude-code"})
      assert session["name"] == session["eventRef"]
      assert session["name"] =~ ~r/^event:sha256:[0-9a-f]{64}$/
    end)
  end

  test "a Prompt with a caller-supplied name is denied — content naming is the kernel's" do
    R5e.Vectors.with_fresh_kernel(fn ->
      for path <- @seeds do
        {:ok, _} = R5e.Vectors.admit_definition(path |> File.read!() |> Jason.decode!())
      end

      # Naming is settled at validateStructure, one stage before resolve,
      # so the caller-name denial fires whether or not the bytes exist.
      {:denied, receipt} =
        R5e.TestHelpers.admit("gateway.r5e.io", "v1alpha1", "Prompt", "my-prompt", %{
          "contentRef" => %{"$ref" => "bytes:sha256:" <> String.duplicate("cd", 32)}
        })

      assert String.starts_with?(receipt["reason"], "validateStructure: ")
      assert receipt["reason"] =~ "a caller-supplied name is not admissible"
    end)
  end

  test "a ToolResult may not cite a ToolCall that was never admitted" do
    R5e.Vectors.with_fresh_kernel(fn ->
      for path <- @seeds do
        {:ok, _} = R5e.Vectors.admit_definition(path |> File.read!() |> Jason.decode!())
      end

      {:denied, receipt} =
        admit("ToolResult", %{
          "toolCall" => %{"$ref" => @event_ref},
          "outcome" => "ok",
          "result" => ""
        })

      assert String.starts_with?(receipt["reason"], "resolve: ")
      assert receipt["reason"] =~ "/toolCall"
      assert receipt["reason"] =~ "no event with that hash is on this chain"
      assert receipt["resolvedRefs"] == []
    end)
  end

  defp admit(kind, spec) do
    R5e.TestHelpers.admit("gateway.r5e.io", "v1alpha1", kind, nil, spec)
  end

  defp seq_of(receipt), do: receipt["seq"]
end
