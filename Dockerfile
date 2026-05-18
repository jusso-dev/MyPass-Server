# Stage 1: Build the Rust binary
FROM rust:latest AS builder

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src/ ./src/
COPY migrations/ ./migrations/

# Build in release mode. SQLX_OFFLINE enables compile without a live database.
ENV SQLX_OFFLINE=true
RUN cargo build --release

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root
RUN useradd -r -s /bin/false mypass
USER mypass

COPY --from=builder /app/target/release/mypass-server /usr/local/bin/mypass-server

EXPOSE 3000

ENTRYPOINT ["mypass-server"]
