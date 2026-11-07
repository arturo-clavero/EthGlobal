# Build stage
# Build context: the repository root. The workspace's verifier member needs the pinned, patched core in `core/`.
FROM rust:latest AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

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
COPY servers/swissbank/src ./swissbank/src

# Invalidate the dummy build
RUN touch swissbank/src/main.rs

# Build release binary
RUN cargo build --release --bin swissbank

# Runtime stage
FROM debian:bookworm-slim

WORKDIR /app

COPY --from=builder /app/servers/target/release/swissbank /app/swissbank

EXPOSE 3000

CMD ["/app/swissbank"]
