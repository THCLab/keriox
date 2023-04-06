FROM rust:1.65.0 as build

COPY . ./
RUN cargo fetch
RUN cargo build --release --package watcher

FROM debian:10-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /target/release/watcher .
COPY --from=build /components/watcher/watcher.yml .
ENTRYPOINT ["/app/watcher"]
