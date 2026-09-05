defmodule R5e.MixProject do
  use Mix.Project

  def project do
    [
      app: :r5e,
      version: "0.1.0",
      elixir: "~> 1.19",
      start_permanent: Mix.env() == :prod,
      package: package(),
      deps: deps()
    ]
  end

  # The licence, stated where a scanner looks for it. AGPL-3.0-only is the
  # decision recorded in `LICENSE.md`: `-only`, not `-or-later`.
  defp package do
    [
      licenses: ["AGPL-3.0-only"],
      links: %{"Source" => "https://gitlab.com/r5e-group/r5e-kernel"}
    ]
  end

  def application do
    [
      extra_applications: [:logger, :crypto],
      mod: {R5e.Application, []}
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:plug, "~> 1.20.3"},
      {:bandit, "~> 1.12.5"},
      # Cedar is kernel infrastructure: core admission must not depend on
      # an enterprise application being present in the release.
      {:rustler, "~> 0.37.3"},
      # Single source of verification truth (Apache Tier 1, standalone
      # escript project). The kernel consumes it; it never depends back.
      {:recurse_verify, path: "../r5e-core/verifier"}
    ]
  end
end
