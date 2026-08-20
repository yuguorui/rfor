# syntax=docker/dockerfile:1.7

FROM rust:1.85-bookworm AS builder

WORKDIR /src
COPY Cargo.toml Cargo.lock build.rs ./
COPY protos ./protos
COPY src ./src

RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release && \
    cp target/release/rfor /tmp/rfor

FROM debian:bookworm-slim

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install --yes --no-install-recommends \
        bash \
        ca-certificates \
        curl \
        iproute2 \
        iptables \
        netcat-openbsd \
        openssl \
        python3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /tmp/rfor /usr/local/bin/rfor
COPY tests/integration /integration

RUN chmod +x /integration/run.sh /integration/test.sh
