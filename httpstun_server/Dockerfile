# syntax=docker/dockerfile:1.4

# Use Debian base and install rustup + nightly toolchain so edition=2024 is supported
FROM debian:bookworm-slim AS builder

WORKDIR /usr/src

# Set cargo and rustup homes to paths we can cache
ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_TARGET_DIR=/usr/src/target

# Install system deps and rustup dependencies
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       build-essential curl ca-certificates pkg-config libssl-dev gnupg2 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install rustup and the nightly toolchain (non-interactive)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path && \
    /usr/local/rustup/bin/rustup default nightly || true

# Ensure cargo is on PATH
ENV PATH="/usr/local/cargo/bin:${PATH}"

# Copy workspace Cargo.lock and server manifest to take advantage of layer caching
COPY Cargo.lock ./
COPY Cargo.toml ./
COPY httpstun_server/Cargo.toml ./httpstun_server/Cargo.toml
COPY httpstun_server/src ./httpstun_server/src
COPY httpstun_client/Cargo.toml ./httpstun_client/Cargo.toml
COPY httpstun_client/src ./httpstun_client/src

RUN --mount=type=cache,id=cargo-registry-server,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git-server,target=/usr/local/cargo/git \
    cargo fetch --manifest-path Cargo.toml --locked

COPY . .
RUN --mount=type=cache,id=cargo-registry-server,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git-server,target=/usr/local/cargo/git \
    cargo build --manifest-path httpstun_server/Cargo.toml --release --locked -p httpstun_server

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/src/target/release/httpstun_server /usr/local/bin/httpstun_server

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/httpstun_server"]
