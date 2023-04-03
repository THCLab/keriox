FROM rust:1.65.0 as build

COPY Cargo.toml ./
COPY ./src src
COPY ./components components
COPY ./keriox_core keriox_core
COPY ./support support
COPY ./keriox_tests keriox_tests
RUN cargo fetch
RUN cargo build --release --package witness

FROM debian:10-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /target/release/witness .
COPY --from=build /components/witness/witness.yml .
ENTRYPOINT ["/app/witness"]
