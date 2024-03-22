FROM rust:1.76 as build

WORKDIR /app
RUN echo '[workspace] \n\
\n\
resolver = "2"\n\
\n\
members = [\n\
    "keriox_core",\n\
    "components/watcher",\n\
    "components/controller",\n\
    "support/teliox",\n\
]\n\
[workspace.package]\n\
repository = "https://github.com/THCLab/keriox"\n\
authors = [\n\
    "Human Colossus Foundation <contact@humancolossus.org>",\n\
]\n\
edition = "2021"\n\
license = "EUPL-1.2"' > Cargo.toml
COPY keriox_core keriox_core
COPY components components
COPY ./support/teliox support/teliox
WORKDIR /app/components/watcher
RUN cargo fetch
RUN cargo build --release --package watcher

FROM debian:12-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /app/target/release/watcher .
COPY --from=build /app/components/watcher/watcher.yml .
ENTRYPOINT ["/app/watcher"]
