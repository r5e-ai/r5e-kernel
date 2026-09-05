defmodule R5e.PublicAPITest do
  @moduledoc """
  The kernel's exported surface, written down.

  The simplification pass that split `R5e.Kind` and moved shared
  derivations between modules had one hard constraint: every function a
  consumer already calls keeps its name, arity and module. `r5e-enterprise`'s
  `apps/recurse_fold` is the consumer of record; the HTTP router and the
  conformance-vector runner are the others.

  This is a **superset** assertion, not an equality one: the kernel may
  grow a function, and this test is not a reason to stop it. What it
  refuses is a function quietly leaving, or moving to another module, or
  changing arity — the three ways a refactor breaks a caller it cannot see.
  """
  use ExUnit.Case, async: true

  # Written down before the pass, from `grep -o 'R5e\.[A-Za-z.]*' ` over
  # apps/recurse_fold, the router, and the vector runner — plus everything
  # else each module documented as public at the time.
  @surface %{
    R5e.Admission => [admit: 1, commit_retries: 0, event_ref: 1, stages: 0],
    R5e.Bootstrap => [
      child_spec: 1,
      replay: 0,
      run: 0,
      seed_actor: 0,
      seed_core_kinds: 0,
      start_link: 0,
      transition_reason: 0
    ],
    R5e.CAS => [
      admit: 2,
      admit: 3,
      delete: 1,
      exists?: 1,
      exists?: 2,
      get: 1,
      get: 2,
      object_address?: 1,
      object_hash: 1,
      put: 1,
      relative_path: 1,
      root: 0,
      valid_address?: 1
    ],
    R5e.Canonical => [encode: 1, hash: 1, hash_bytes: 1],
    R5e.Chain => [
      build_event: 4,
      genesis: 0,
      read_log: 1,
      recompute_hash: 1,
      verify_events: 1
    ],
    R5e.Commit => [capture: 2, empty?: 1, stale: 1],
    R5e.DSSE => [envelope: 2, pae: 2, verify: 2],
    R5e.Export => [run: 0, run: 1],
    R5e.Kind => [
      check_definition: 1,
      compile_pattern: 1,
      exists?: 2,
      from_map: 1,
      from_map: 2,
      load_file: 1,
      name: 1,
      naming_mode: 1,
      naming_modes: 0,
      non_empty?: 1,
      parse_template: 1,
      re2_subset: 1,
      render_derived: 2,
      substrates: 0,
      to_map: 1,
      valid_name?: 1,
      validate_constraints: 2,
      validate_structure: 2
    ],
    R5e.KindRegistry => [child_spec: 1, force_put: 1, get: 3, list: 0, put: 1, start_link: 1],
    R5e.Log => [
      append: 2,
      checkpoint: 0,
      checkpoint_payload_type: 0,
      child_spec: 1,
      commit: 4,
      events: 0,
      halted: 0,
      leaves: 0,
      log_path: 0,
      resume: 0,
      start_link: 1,
      verify: 0
    ],
    R5e.Policy => [active: 0, decide: 1],
    R5e.Policy.AllowAll => [authorize: 1],
    R5e.RefIndex => [
      cas_object: 1,
      cas_objects: 0,
      child_spec: 1,
      citations: 1,
      derived?: 1,
      derived_objects: 0,
      expired?: 1,
      observe: 2,
      partition: 1,
      public_record_citations: 1,
      register_derived: 1,
      register_derived: 2,
      reset: 0,
      start_link: 1,
      unreferenced?: 1
    ],
    R5e.Refs => [
      bare_sites: 1,
      check_value: 2,
      class: 1,
      declared_target: 1,
      escape: 1,
      map_refs: 3,
      object_address: 1,
      outcome: 1,
      sites: 2,
      split_kind_ref: 1,
      valid_value?: 2,
      value_form: 1
    ],
    R5e.Resolve => [derived_from: 1, run: 3],
    R5e.ResourceStore => [
      child_spec: 1,
      get: 4,
      get: 5,
      list: 3,
      put: 5,
      start_link: 1,
      supersede: 5,
      superseded: 4
    ],
    R5e.Retention => [actor: 0, sweep: 0, ttl_seconds: 0],
    R5e.SignerProvider => [active: 0, key_id: 0, public_key: 0, sign: 1]
  }

  test "every module still exports at least what it exported before the pass" do
    for {module, expected} <- @surface do
      exported = MapSet.new(module.__info__(:functions))

      missing =
        expected
        |> Enum.reject(&MapSet.member?(exported, &1))
        |> Enum.sort()

      assert missing == [],
             "#{inspect(module)} no longer exports #{inspect(missing)} — " <>
               "a caller outside this repo is calling it"
    end
  end

  test "the pipeline stage names are the seven of spec/05 §4, in order" do
    assert R5e.Admission.stages() == [
             "authenticate",
             "validateStructure",
             "resolve",
             "authorize",
             "validateConstraints",
             "record",
             "admit"
           ]
  end

  test "R5e.Kind is still the front door for the checks that moved into submodules" do
    spec = %{
      "group" => "api.r5e.io",
      "kind" => "Thing",
      "version" => "v1",
      "substrate" => "resource",
      "naming" => %{"mode" => "caller"},
      "predicates" => [],
      "schema" => %{
        "required" => ["title"],
        "properties" => %{"title" => %{"type" => "string"}},
        "additionalProperties" => false
      }
    }

    assert R5e.Kind.check_definition(spec) == :ok
    assert {:ok, kind} = R5e.Kind.from_map(spec)
    assert R5e.Kind.validate_structure(kind, %{"title" => "x"}) == :ok
    assert R5e.Kind.validate_constraints(kind, %{"title" => "x"}) == :ok
    assert {:error, [_]} = R5e.Kind.validate_constraints(kind, %{})
    assert R5e.Kind.valid_name?("cedar.*")
    assert R5e.Kind.render_derived("{title}.x", %{"title" => "a"}) == {:ok, "a.x"}
  end
end
