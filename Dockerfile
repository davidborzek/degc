# syntax=docker/dockerfile:1
# degc — label-driven VPN egress policy-routing for Docker.
#
# Alpine runtime: the enforcement backend shells out to `nft` (nftables) and
# `ip` (iproute2), so both must be present. Build is musl (rust:*-alpine) so the
# binary runs on the alpine base. No TLS/C crypto deps → only musl-dev to build.
#
# Runs privileged against the host network stack — deploy with:
#   network_mode: host
#   cap_add: [NET_ADMIN]
# and mount the Docker socket (read-only) + the gateways config.

FROM rust:1-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM alpine:3
RUN apk add --no-cache nftables iproute2
COPY --from=build /src/target/release/degc /usr/local/bin/degc
ENTRYPOINT ["degc"]
CMD ["run"]
