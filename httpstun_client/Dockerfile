# syntax=docker/dockerfile:1.4
FROM rust:nightly AS builder

# Build context is expected to be the repository root so we can take advantage of a workspace Cargo.lock
WORKDIR /usr/src

ENV CARGO_HOME=/usr/local/cargo
ENV RUSTUP_HOME=/usr/local/rustup
ENV CARGO_TARGET_DIR=/usr/src/target

# Use a minimal Debian base and install rustup + nightly toolchain so edition=2024 is supported
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

# Copy the workspace Cargo.lock and the client manifest to maximize layer caching
# This requires building with the repo root as the build context: `docker build -f httpstun_client/Dockerfile .`
COPY Cargo.lock ./
COPY Cargo.toml ./
COPY httpstun_client/Cargo.toml ./httpstun_client/Cargo.toml
COPY httpstun_client/src ./httpstun_client/src
COPY httpstun_server/Cargo.toml ./httpstun_server/Cargo.toml
COPY httpstun_server/src ./httpstun_server/src

# Populate the cargo registry/git cache (BuildKit cache mounts are used when available)
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-registry-client,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git-client,target=/usr/local/cargo/git \
    cargo fetch --manifest-path Cargo.toml --locked

# Copy the full source and build the client (cache target and cargo registries)
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-registry-client,target=/usr/local/cargo/registry \
    --mount=type=cache,id=cargo-git-client,target=/usr/local/cargo/git \
    cargo build --manifest-path httpstun_client/Cargo.toml --release --locked -p httpstun_client

# Final runtime image: small Debian with ca-certificates
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/target/release/httpstun_client /usr/local/bin/httpstun_client

ENV RUST_LOG=info
ENTRYPOINT ["/usr/local/bin/httpstun_client"]
