# r5e-kernel — stranger-proof container build.
#
# The kernel has a path dependency on ../r5e-core/verifier (the standalone
# Apache-licensed verifier; single source of verification truth — the build
# compiles that one copy, it does not vendor a fork). The build context must
# therefore be the PARENT directory that holds both repos side by side:
#
#     repos/
#       r5e-kernel/
#       r5e-core/verifier/
#
#     cd repos
#     docker build -f r5e-kernel/Dockerfile -t r5e-kernel .
#
# Requires BuildKit (default in Docker >= 23) so that
# r5e-kernel/Dockerfile.dockerignore trims the context to just the two trees.
#
# The final image is a small Alpine runtime stage: an OTP release of the
# kernel serving port 4545 with state under /data/.r5e (VOLUME /data), plus
# the recurse_verify escript on PATH so bundles can be verified in-container:
#
#     docker exec <container> recurse_verify /data/.r5e/exports/bundle-...

ARG ELIXIR_IMAGE=hexpm/elixir:1.19.5-erlang-28.5.0.4-alpine-3.22.5
ARG RUNTIME_IMAGE=alpine:3.22.5
ARG RUST_IMAGE=rust:1.92.0-alpine3.22

# ---------------------------------------------------------------- build ----
FROM ${RUST_IMAGE} AS rust-toolchain

FROM ${ELIXIR_IMAGE} AS build

ENV MIX_ENV=prod \
    CARGO_HOME=/usr/local/cargo \
    RUSTUP_HOME=/usr/local/rustup \
    PATH=/usr/local/cargo/bin:$PATH

COPY --from=rust-toolchain /usr/local/cargo /usr/local/cargo
COPY --from=rust-toolchain /usr/local/rustup /usr/local/rustup

RUN apk add --no-cache build-base \
 && mix local.hex --force \
 && mix local.rebar --force

# Mirror the on-disk layout so the `{:recurse_verify, path: "../r5e-core/verifier"}`
# dependency in mix.exs resolves as-is.
WORKDIR /src
COPY r5e-core/verifier /src/r5e-core/verifier
COPY r5e-kernel /src/r5e-kernel

# The standalone verifier escript (same copy the kernel compiles against).
WORKDIR /src/r5e-core/verifier
RUN mix deps.get && mix escript.build

# The kernel, as a self-contained OTP release (bundled ERTS, no Elixir
# install needed at runtime). no_dot_erlang.boot from the OTP root is what
# `escript` boots with; a mix release does not include it, so carry it over.
WORKDIR /src/r5e-kernel
RUN mix deps.get --only prod \
 && mix release --overwrite --path /out/r5e \
 && cp "$(erl -noshell -eval 'io:format("~s",[code:root_dir()]),halt().')/bin/no_dot_erlang.boot" /out/r5e/bin/

# -------------------------------------------------------------- runtime ----
FROM ${RUNTIME_IMAGE} AS runtime

RUN apk add --no-cache libstdc++ libgcc ncurses-libs openssl

ENV LANG=C.UTF-8 \
    R5E_DATA_DIR=/data/.r5e \
    R5E_PORT=4545

COPY --from=build /out/r5e /app
COPY --from=build /src/r5e-core/verifier/recurse_verify /opt/recurse_verify

# Put the verifier on PATH, running on the release's own ERTS (the escript's
# `#!/usr/bin/env escript` shebang has nothing to resolve to in this image).
RUN set -eu; \
    ERTS_BIN="$(ls -d /app/erts-*/bin)"; \
    printf '#!/bin/sh\nexec %s/escript /opt/recurse_verify "$@"\n' "$ERTS_BIN" \
      > /usr/local/bin/recurse_verify; \
    chmod +x /usr/local/bin/recurse_verify

# State (CAS, log, node keys, exports) lives under /data/.r5e.
VOLUME /data
EXPOSE 4545

CMD ["/app/bin/r5e", "start"]
