FROM rust:1.61 AS builder

WORKDIR app
COPY Cargo.toml ./
COPY ./src src
RUN cargo fetch
RUN cargo build --release --bin watcher-binary --all-features

FROM debian:buster-slim
WORKDIR app
COPY --from=builder /app/target/release/watcher-binary /usr/local/bin
COPY --from=builder /app/src/bin/configs/watcher.json /app/watcher-conf.json

ENTRYPOINT ["/usr/local/bin/watcher-binary"]
CMD ["-c", "/app/watcher-conf.json"]
