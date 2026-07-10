# syntax=docker/dockerfile:1.6

FROM rust:1.95-slim AS builder
ARG HC_RELEASE_SHA
ARG HC_RELEASE_REF
ARG HC_RELEASE_BUILD_URL
ENV HC_RELEASE_SHA=${HC_RELEASE_SHA}
ENV HC_RELEASE_REF=${HC_RELEASE_REF}
ENV HC_RELEASE_BUILD_URL=${HC_RELEASE_BUILD_URL}
RUN apt-get update && apt-get install -y --no-install-recommends curl pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app

# Cache deps
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY docs ./docs
COPY scripts ./scripts
COPY README.md ./

RUN cargo build --locked -p hc-server -p hc-mcp --release --bins

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends curl && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 10001 hc
WORKDIR /app
COPY --from=builder /app/target/release/hc-server /app/hc-server
COPY --from=builder /app/target/release/hc-mcp-http /app/hc-mcp-http
USER hc

ENV RUST_LOG=info
EXPOSE 8080 3001

HEALTHCHECK --interval=30s --timeout=5s --retries=3 CMD curl -sf http://localhost:8080/healthz || exit 1

ENTRYPOINT ["/app/hc-server"]
