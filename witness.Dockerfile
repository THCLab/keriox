FROM rust:1.61 AS builder

WORKDIR app
COPY Cargo.toml ./
COPY ./src src
RUN cargo fetch
RUN cargo build --release --bin witness-binary --all-features

FROM debian:buster-slim
WORKDIR app
COPY --from=builder /app/target/release/witness-binary /usr/local/bin
COPY --from=builder /app/src/bin/configs/witness1.json /app/witness-conf.json

ENTRYPOINT ["/usr/local/bin/witness-binary"]
CMD ["-c", "/app/witness-conf.json"]
