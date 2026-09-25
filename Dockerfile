FROM rust:1.98.1-slim-trixie AS builder

ARG TARGETARCH

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates musl-tools; \
    rm -rf /var/lib/apt/lists/*; \
    case "${TARGETARCH:-$(uname -m)}" in \
        amd64|x86_64) rust_target="x86_64-unknown-linux-musl" ;; \
        arm64|aarch64) rust_target="aarch64-unknown-linux-musl" ;; \
        *) echo "unsupported target architecture: ${TARGETARCH:-$(uname -m)}" >&2; exit 1 ;; \
    esac; \
    echo "$rust_target" > /tmp/rust-target; \
    rustup target add "$rust_target"

WORKDIR /opt/app

COPY LICENSE /opt/app/LICENSE
COPY Cargo.toml /opt/app/Cargo.toml
COPY Cargo.lock /opt/app/Cargo.lock

RUN mkdir -p /opt/app/src /opt/app/benches \
    && echo "fn main() {}" > /opt/app/src/main.rs \
    && echo "fn main() {}" > /opt/app/benches/logic_paths.rs

RUN --mount=type=cache,id=tino-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=tino-cargo-target-$TARGETARCH,target=/opt/app/target \
    set -eux; \
    rust_target="$(cat /tmp/rust-target)"; \
    cargo fetch --locked --target "$rust_target"

RUN rm -f /opt/app/src/main.rs
COPY src/ /opt/app/src/
COPY benches/ /opt/app/benches/

RUN --mount=type=cache,id=tino-cargo-registry,target=/usr/local/cargo/registry \
    --mount=type=cache,id=tino-cargo-target-$TARGETARCH,target=/opt/app/target \
    set -eux; \
    rust_target="$(cat /tmp/rust-target)"; \
    export RUSTFLAGS="-C linker=rust-lld"; \
    cargo build --locked --release --target "$rust_target"; \
    cp "/opt/app/target/$rust_target/release/tino" /opt/app/tino


FROM scratch AS runtime

COPY --from=builder /opt/app/tino /sbin/tino
COPY --from=builder /opt/app/LICENSE /LICENSE

ENTRYPOINT ["/sbin/tino"]
