# Build stage
# Build context: the repository root. The verifier builds against the pinned, patched core in `core/`.
FROM rust:latest AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Prepare the pinned core exactly as the extension's WASM build does (checks the patch digests, clones, applies).
COPY core/prepare-core.sh core/VERSION ./core/
COPY core/patches ./core/patches
COPY core/mpz-patches ./core/mpz-patches
RUN bash core/prepare-core.sh /app/core/tlsn

WORKDIR /app/servers

# Copy workspace manifests + all member manifests so cargo can resolve the workspace
COPY servers/Cargo.toml servers/Cargo.lock ./
COPY servers/verifier/Cargo.toml ./verifier/
COPY servers/swissbank/Cargo.toml ./swissbank/

# Create dummy sources for all workspace members so deps can be fetched
RUN mkdir -p verifier/src swissbank/src && \
    echo "fn main() {}" > verifier/src/main.rs && \
    echo "fn main() {}" > swissbank/src/main.rs

# Fetch dependencies (cached if manifests/lockfile unchanged)
RUN cargo fetch --locked

# Copy real source for this crate
COPY servers/verifier/src ./verifier/src

# Invalidate the dummy build
RUN touch verifier/src/main.rs

# Build release binary
RUN cargo build --release --bin tlsn-verifier-server

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

ARG GIT_HASH=local
ENV GIT_HASH=${GIT_HASH}

RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/servers/target/release/tlsn-verifier-server /app/tlsn-verifier-server
COPY servers/verifier/config-prod.yaml /app/config.yaml

EXPOSE 7047

CMD ["/app/tlsn-verifier-server"]
