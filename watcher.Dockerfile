FROM rust:1.95 AS build

ARG GIT_VERSION_SUFFIX
ENV GIT_VERSION_SUFFIX=${GIT_VERSION_SUFFIX}

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
# `ca-certificates` is the trust-anchor store OpenSSL/native-tls reads
# from. debian:12-slim does not ship it, and without it every outbound
# HTTPS request from the watcher fails with
# "unable to get local issuer certificate" — the watcher then cannot
# fetch KSN / KEL events from witnesses over TLS and every signed
# query coming in bounces back as InvalidSignature / NotFound to the
# controller. Keep both packages so libssl is available for runtime
# linking and ca-certificates populates /etc/ssl/certs.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/watcher .
COPY --from=build /app/components/watcher/watcher.yml .
ENTRYPOINT ["/app/watcher"]
