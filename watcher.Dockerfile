FROM rust:1.68 as build

WORKDIR /app
RUN echo '[workspace] \n\
\n\
members = [\n\
    "keriox_core",\n\
    "components/watcher",\n\
    "components/controller",\n\
    "components/witness",\n\
    "support/teliox",\n\
]' > Cargo.toml
COPY keriox_core keriox_core
COPY components components
COPY ./support/teliox support/teliox
WORKDIR /app/components/watcher
RUN cargo fetch
RUN cargo build --release --package watcher

FROM debian:10-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /app/target/release/watcher .
COPY --from=build /app/components/watcher/watcher.yml .
ENTRYPOINT ["/app/watcher"]
