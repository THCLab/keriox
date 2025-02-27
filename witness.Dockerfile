FROM rust:1.85 as build

WORKDIR /app
RUN echo '[workspace] \n\
\n\
members = [\n\
    "keriox_core",\n\
    "components/witness",\n\
    "support/teliox",\n\
]\n\
[workspace.package]\n\
repository = "https://github.com/THCLab/keriox"\n\
authors = [\n\
    "Human Colossus Foundation <contact@humancolossus.org>",\n\
]\n\
edition = "2021"\n\
license = "EUPL-1.2"' > Cargo.toml
COPY ./components components
COPY ./keriox_core keriox_core
COPY ./support/teliox support/teliox
WORKDIR /app/components/witness
RUN cargo fetch
RUN cargo build --release --package witness

FROM debian:12-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /app/target/release/witness .
COPY --from=build /app/components/witness/witness.yml .
ENTRYPOINT ["/app/witness"]
