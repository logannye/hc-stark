FROM rust:1.95.0-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --manifest-path examples/partner-adapter/Cargo.toml --locked

FROM debian:bookworm-slim
RUN useradd --create-home --uid 10001 tinyzkp
COPY --from=build /src/target/release/tinyzkp-partner-adapter-example /usr/local/bin/partner-adapter
USER tinyzkp
ENTRYPOINT ["/usr/local/bin/partner-adapter"]
