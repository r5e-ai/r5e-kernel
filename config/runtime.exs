import Config

# Runtime environment overrides. When unset, the compile-time defaults in
# config.exs apply unchanged, so plain local `mix run --no-halt` behaves
# exactly as before. The Docker image sets both (state under /data/.r5e,
# port 4545).

if dir = System.get_env("R5E_DATA_DIR") do
  config :r5e, data_dir: dir
end

if port = System.get_env("R5E_PORT") do
  config :r5e, http_port: String.to_integer(port)
end

# `R5E_KERNEL_POLICY_RECOVER=1` (or `true`) asks this boot to re-admit the
# shipped default kernel policy bundle over the one in force — the named
# recovery from a bundle an operator can no longer replace by hand. It is an
# ordinary admission by the node key, decided by the bundle in force and
# recorded on the chain like any other act.
#
# Any other value is refused rather than read as "off": an operator who
# spells the flag `yes` and boots unchanged has been told nothing.
case System.get_env("R5E_KERNEL_POLICY_RECOVER") do
  nil ->
    :ok

  value when value in ~w(1 true TRUE True) ->
    config :r5e, kernel_policy_recover: true

  other ->
    raise """
    R5E_KERNEL_POLICY_RECOVER is set to #{inspect(other)}.

    The only accepted values are "1" and "true"; unset it to boot normally.
    This flag re-admits the shipped default kernel policy bundle over the one
    in force, so it is not something to leave ambiguous.
    """
end
