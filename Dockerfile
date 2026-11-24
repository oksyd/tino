FROM rust:1.100.0-slim-trixie AS builder

ARG TARGETARCH

RUN set -eux; \
    case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) rust_target="x86_64-unknown-linux-musl" ;; \
        arm64|aarch64) rust_target="aarch64-unknown-linux-musl" ;; \
        *) echo "unsupported target architecture: ${TARGETARCH:-$(uname -m)}" >&2; exit 1 ;; \
    esac; \
    echo "$rust_target" > /tmp/rust-target; \
    rustup target add "$rust_target"

WORKDIR /opt/app

COPY Cargo.toml Cargo.lock ./
COPY src/ src/

RUN --mount=type=cache,id=tino-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=tmpfs,target=/opt/app/target \
    set -eux; \
    rust_target="$(cat /tmp/rust-target)"; \
    export RUSTFLAGS="-C linker=rust-lld"; \
    cargo build --locked --release --bin tino --target "$rust_target"; \
    cp "/opt/app/target/$rust_target/release/tino" /opt/app/tino


FROM scratch AS runtime

COPY --from=builder /opt/app/tino /sbin/tino
COPY LICENSE /LICENSE

ENTRYPOINT ["/sbin/tino"]
