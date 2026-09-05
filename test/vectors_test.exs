defmodule R5e.ConformanceVectorsTest do
  @moduledoc """
  The schema-lite v2 §12 discriminator: every file under `test/vectors/`
  is admitted against a fresh kernel and its outcome, stage and reason are
  asserted. An implementer of another kernel agrees with this one iff every
  vector passes.
  """

  use ExUnit.Case, async: false

  for path <- R5e.Vectors.files() do
    @external_resource path
    @vector path

    test "vector #{R5e.Vectors.label(path)}" do
      R5e.Vectors.run(@vector)
    end
  end
end
