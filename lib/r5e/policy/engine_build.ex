defmodule R5e.Policy.EngineBuild do
  @moduledoc """
  Measures the deployed Cedar artifact files read by this kernel.

  Equal descriptor addresses mean equal measured lockfile, NIF and policy
  module bytes on the same OTP architecture. The descriptor does not prove
  that those bytes came from a published source tree or that the engine is
  correct; those require a reproducible build and an external trust decision.
  These are boot-time, process-produced file measurements, not independent
  attestation of loaded code or detection of later process compromise.
  """

  @crate "cedar-policy"
  @media_type "application/vnd.r5e.engine-build+json"
  @cargo_lock Path.expand("../../../native/r5e_cedar/Cargo.lock", __DIR__)

  @type measurement :: %{
          required(:address) => String.t(),
          required(:bytes) => binary(),
          required(:spec) => map()
        }

  @doc "Measure the deployed engine files once for one boot sequence."
  @spec measure() :: measurement()
  def measure do
    bytes = bytes()
    spec = R5e.CAS.object_spec(bytes, @media_type)
    %{address: spec["address"], bytes: bytes, spec: spec}
  end

  @spec media_type() :: String.t()
  def media_type, do: @media_type

  @spec bytes() :: binary()
  def bytes, do: R5e.Canonical.encode(descriptor())

  @spec address() :: String.t()
  def address, do: "bytes:" <> R5e.Canonical.hash_bytes(bytes())

  @spec cached_address() :: String.t() | nil
  def cached_address, do: Application.get_env(:r5e, :cedar_engine_build_address)

  @doc false
  def cache_address(address), do: Application.put_env(:r5e, :cedar_engine_build_address, address)

  @doc false
  def clear_cached_address,
    do: Application.delete_env(:r5e, :cedar_engine_build_address)

  @spec descriptor() :: map()
  def descriptor do
    %{
      "format" => "r5e.engine-build/1",
      "engine" => "cedar",
      "crate" => @crate,
      "crateVersion" => crate_version(),
      "cargoLockSha256" => sha256_file(cargo_lock_path()),
      "nifSha256" => sha256_file(nif_path()),
      "module" => inspect(R5e.Policy.KernelCedar),
      "moduleSha256" => sha256_file(:code.which(R5e.Policy.KernelCedar) |> to_string()),
      "platform" => to_string(:erlang.system_info(:system_architecture))
    }
  end

  @spec cargo_lock_path() :: Path.t()
  def cargo_lock_path, do: Application.get_env(:r5e, :cedar_cargo_lock_path, @cargo_lock)

  @spec nif_path() :: Path.t()
  def nif_path do
    :r5e
    |> :code.priv_dir()
    |> to_string()
    |> Path.join("native/r5e_cedar*")
    |> Path.wildcard()
    |> Enum.sort()
    |> List.first()
    |> case do
      nil -> Path.join([to_string(:code.priv_dir(:r5e)), "native", "r5e_cedar.so"])
      path -> path
    end
  end

  defp crate_version do
    case Regex.run(
           ~r/name\s*=\s*"#{@crate}"\s*\nversion\s*=\s*"([^"]+)"/,
           read!(cargo_lock_path())
         ) do
      [_, version] -> version
      nil -> raise "#{cargo_lock_path()} carries no #{@crate} package"
    end
  end

  defp sha256_file(path), do: :crypto.hash(:sha256, read!(path)) |> Base.encode16(case: :lower)

  defp read!(path) do
    case File.read(path) do
      {:ok, bytes} -> bytes
      {:error, reason} -> raise "cannot measure #{path}: #{:file.format_error(reason)}"
    end
  end
end
