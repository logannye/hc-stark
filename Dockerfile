# syntax=docker/dockerfile:1.6

FROM rust:1.95-slim AS builder
ARG HC_RELEASE_SHA
ARG HC_RELEASE_REF
ARG HC_RELEASE_BUILD_URL
ENV HC_RELEASE_SHA=${HC_RELEASE_SHA}
ENV HC_RELEASE_REF=${HC_RELEASE_REF}
ENV HC_RELEASE_BUILD_URL=${HC_RELEASE_BUILD_URL}
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY examples/partner-adapter ./examples/partner-adapter
COPY docs ./docs
COPY scripts ./scripts
COPY README.md ./

RUN cargo build --locked -p hc-cli --release --bin hc-cli

FROM debian:bookworm-slim
ARG HC_RELEASE_SHA
ARG HC_RELEASE_REF
ARG HC_RELEASE_BUILD_URL
LABEL org.opencontainers.image.title="TinyZKP engine" \
      org.opencontainers.image.revision="${HC_RELEASE_SHA}" \
      org.opencontainers.image.version="${HC_RELEASE_REF}" \
      org.opencontainers.image.url="${HC_RELEASE_BUILD_URL}" \
      org.opencontainers.image.tinyzkp.profile="tinyzkp-p3-goldilocks-v1"
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin tinyzkp \
    && install -d -o tinyzkp -g tinyzkp -m 0700 /work /scratch
COPY --from=builder /app/target/release/hc-cli /usr/local/bin/tinyzkp-engine

USER tinyzkp
WORKDIR /work
VOLUME ["/work", "/scratch"]
STOPSIGNAL SIGTERM

ENTRYPOINT ["/usr/local/bin/tinyzkp-engine"]
CMD ["--help"]
