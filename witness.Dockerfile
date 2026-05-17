FROM rust:1.95 AS build

ARG GIT_VERSION_SUFFIX
ENV GIT_VERSION_SUFFIX=${GIT_VERSION_SUFFIX}

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
# `ca-certificates` is the trust-anchor store OpenSSL/native-tls reads
# from. debian:12-slim does not ship it, and without it any outbound
# HTTPS request from the witness fails TLS verification. Symmetric
# with the same line in watcher.Dockerfile.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/witness .
COPY --from=build /app/components/witness/witness.yml .
ENTRYPOINT ["/app/witness"]
