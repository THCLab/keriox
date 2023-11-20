FROM rust:1.74 as build

WORKDIR /app
RUN echo '[workspace] \n\
\n\
members = [\n\
    "keriox_core",\n\
    "components/witness",\n\
    "support/teliox",\n\
]' > Cargo.toml
COPY ./components components
COPY ./keriox_core keriox_core
COPY ./support/teliox support/teliox
WORKDIR /app/components/witness
RUN cargo fetch
RUN cargo build --release --package witness

FROM debian:11-slim
RUN apt update && apt install libssl-dev -y
WORKDIR /app
COPY --from=build /app/target/release/witness .
COPY --from=build /app/components/witness/witness.yml .
ENTRYPOINT ["/app/witness"]
