# syntax=docker/dockerfile:1

FROM rust:1-alpine@sha256:a10e64dd139b7387337c7fbe8aca31b959b57b2fd4c8ae20a02cf1d6ea424dce AS build
WORKDIR /build
RUN apk add --no-cache git musl-dev && rustup component add clippy rustfmt
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY tests ./tests
COPY protocol ./protocol
COPY assets.json ./
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fmt --all --check && \
    cargo test --locked --all-targets && \
    cargo test --locked --no-default-features && \
    cargo clippy --locked --all-targets -- -D warnings && \
    cargo clippy --locked --all-targets --no-default-features -- -D warnings && \
    cargo build --locked --release

FROM scratch
ARG VCS_REF
LABEL org.opencontainers.image.source="https://github.com/rm-you/p99-logger-client" \
      org.opencontainers.image.description="Headless Project 1999 and Project Quarm chat logger" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.revision="$VCS_REF"
COPY --from=build /build/target/release/p99-logger-client /p99-logger-client
USER 65534:65534
ENV USER=nobody
ENTRYPOINT ["/p99-logger-client"]
