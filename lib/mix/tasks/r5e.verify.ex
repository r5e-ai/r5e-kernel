defmodule Mix.Tasks.R5e.Verify do
  @shortdoc "Verify an exported r5e bundle offline (delegates to recurse_verify)"

  @moduledoc """
  Thin delegate over the standalone verifier (`recurse_verify`, the
  Apache Tier 1 project at r5e-core/verifier — also buildable as an
  escript there):

      mix r5e.verify PATH_TO_BUNDLE [--prior PATH_TO_EARLIER_BUNDLE]

  Prints what was checked and what was not — never a bare pass/fail — per
  the output doctrine in r5e-core/verifier/README.md. Exit status is 1
  when findings (tampering, gaps) are present, 0 otherwise; the text, not
  the exit code, is the verdict.
  """

  use Mix.Task

  @impl true
  def run(args) do
    # Deliberately no application start: the verifier reads the bundle
    # directory (and optionally a prior one) and nothing else.
    {opts, positional, invalid} = OptionParser.parse(args, strict: [prior: :string])

    case {positional, invalid} do
      {[bundle], []} ->
        case RecurseVerify.run(bundle, prior: opts[:prior]) do
          {:ok, report} ->
            Mix.shell().info(RecurseVerify.format(report))
            if report.findings != [], do: exit({:shutdown, 1})

          {:error, message} ->
            Mix.raise(message)
        end

      _ ->
        Mix.raise("usage: mix r5e.verify PATH_TO_BUNDLE [--prior PATH_TO_EARLIER_BUNDLE]")
    end
  end
end
