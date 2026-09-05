defmodule R5e.Persistence do
  @moduledoc """
  The file and directory durability barriers used by the log and CAS.

  `:file.sync/1` is the contract: bytes are handed to the operating system
  for durable storage before a write is acknowledged. A newly named or
  removed file additionally requires its containing directory to be synced,
  otherwise the bytes may survive a power loss while the name does not.

  OTP opens directories with the `:directory` mode on Linux and macOS. A
  filesystem or runtime that cannot open or sync a directory is refused; this
  module never treats a successful file sync as proof that the directory entry
  is durable.

  This is an operating-system persistence contract, not a claim about storage
  hardware that lies about flush completion. A failure after a write and before
  its sync is necessarily ambiguous: the caller receives no acknowledgement,
  and startup validates whatever complete bytes remain without truncating them.
  """

  @type phase ::
          :before_file_sync
          | :after_file_sync
          | :before_directory_sync
          | :after_directory_sync
          | :before_rename
          | :atomic_replace_durable
          | :before_append
          | :append_durable
          | :delete_durable
          | :existing_file_durable

  @doc "Create a directory and durably record each newly created path component."
  @spec ensure_dir!(Path.t()) :: :ok
  def ensure_dir!(path) do
    path = Path.expand(path)

    case File.mkdir(path) do
      :ok ->
        sync_directory!(path)
        sync_directory!(Path.dirname(path))

      {:error, :eexist} ->
        unless File.dir?(path) do
          raise File.Error, reason: :enotdir, action: "create directory", path: path
        end

        :ok

      {:error, :enoent} ->
        parent = Path.dirname(path)

        if parent == path do
          raise File.Error, reason: :enoent, action: "create directory", path: path
        end

        ensure_dir!(parent)
        ensure_dir!(path)

      {:error, reason} ->
        raise File.Error, reason: reason, action: "create directory", path: path
    end
  end

  @doc "Atomically install synced bytes and sync the directory entry."
  @spec write_atomic!(Path.t(), binary(), keyword()) :: :ok
  def write_atomic!(path, bytes, opts \\ []) when is_binary(bytes) do
    ensure_dir!(Path.dirname(path))
    tmp = path <> ".tmp.#{System.unique_integer([:positive, :monotonic])}"

    try do
      with_file!(tmp, [:write, :binary, :raw, :exclusive], fn file ->
        if mode = opts[:mode], do: ok!(File.chmod(tmp, mode), "change mode of", tmp)
        ok!(:file.write(file, bytes), "write", tmp)
        sync_file!(file, tmp)
      end)

      hook(:before_rename, path)

      if Keyword.get(opts, :replace, true) do
        ok!(File.rename(tmp, path), "rename", tmp)
        sync_directory!(Path.dirname(path))
      else
        # A hard link installs the already-synced inode only when `path` is
        # still absent. Unlike POSIX rename, it cannot overwrite a key file
        # that appeared after the caller checked for an existing pair.
        ok!(File.ln(tmp, path), "install without replacing", path)
        sync_directory!(Path.dirname(path))
        ok!(File.rm(tmp), "remove temporary file", tmp)
        sync_directory!(Path.dirname(path))
      end

      hook(:atomic_replace_durable, path)
      :ok
    after
      _ = File.rm(tmp)
    end
  end

  @doc "Append bytes, sync the file, and sync its directory when newly created."
  @spec append!(Path.t(), iodata()) :: :ok
  def append!(path, bytes) do
    ensure_dir!(Path.dirname(path))
    new? = not File.exists?(path)

    with_file!(path, [:append, :binary, :raw], fn file ->
      hook(:before_append, path)
      ok!(:file.write(file, bytes), "append to", path)
      sync_file!(file, path)
    end)

    if new?, do: sync_directory!(Path.dirname(path))
    hook(:append_durable, path)
    :ok
  end

  @doc "Verify and sync an existing immutable file and its directory entry."
  @spec sync_existing!(Path.t(), binary()) :: :ok
  def sync_existing!(path, expected) when is_binary(expected) do
    case File.read(path) do
      {:ok, ^expected} -> :ok
      {:ok, _other} -> raise "immutable content-addressed object is corrupt at #{path}"
      {:error, reason} -> raise File.Error, reason: reason, action: "read", path: path
    end

    # Linux requires a descriptor opened for writing for `fsync(2)`. Pairing
    # `:read` with `:write` keeps existing contents intact on both Linux and
    # macOS; the content check above guards the immutable-object contract.
    with_file!(path, [:read, :write, :binary, :raw], &sync_file!(&1, path))
    sync_directory!(Path.dirname(path))
    hook(:existing_file_durable, path)
    :ok
  end

  @doc "Remove a file and sync the directory entry. Missing files are already removed."
  @spec delete!(Path.t()) :: :ok
  def delete!(path) do
    case File.rm(path) do
      :ok ->
        sync_directory!(Path.dirname(path))
        hook(:delete_durable, path)
        :ok

      {:error, :enoent} ->
        :ok

      {:error, reason} ->
        raise File.Error, reason: reason, action: "remove", path: path
    end
  end

  @doc "Sync a directory entry; raises when the platform or filesystem cannot do so."
  @spec sync_directory!(Path.t()) :: :ok
  def sync_directory!(path) do
    hook(:before_directory_sync, path)

    with_file!(path, [:read, :raw, :directory], fn directory ->
      ok!(:file.sync(directory), "sync directory", path)
    end)

    hook(:after_directory_sync, path)
    :ok
  end

  defp sync_file!(file, path) do
    hook(:before_file_sync, path)
    ok!(:file.sync(file), "sync", path)
    hook(:after_file_sync, path)
    :ok
  end

  defp with_file!(path, modes, fun) do
    case :file.open(String.to_charlist(path), modes) do
      {:ok, file} ->
        try do
          fun.(file)
        after
          ok!(:file.close(file), "close", path)
        end

      {:error, reason} ->
        raise File.Error, reason: reason, action: "open", path: path
    end
  end

  defp ok!(:ok, _action, _path), do: :ok

  defp ok!({:error, reason}, action, path),
    do: raise(File.Error, reason: reason, action: action, path: path)

  # Test-only failure/ordering seam. Production config never sets it.
  defp hook(phase, path) do
    case Application.get_env(:r5e, :persistence_hook) do
      fun when is_function(fun, 2) -> fun.(phase, path)
      _ -> :ok
    end
  end
end
