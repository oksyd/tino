<p align="center">
  <img src="assets/logo.svg" alt="tino - tiny init process for containers" width="320">
</p>

<p align="center">
  tiny init process (PID 1) for Docker, Kubernetes, and other containers
</p>

<p align="center">
  <a href="https://crates.io/crates/tino"><img src="https://img.shields.io/crates/v/tino?style=flat&logo=rust&logoColor=ffffff&label=crate&labelColor=64748b&color=0f766e" alt="Crate Version"></a>
  <a href="https://github.com/lvillis/tino/actions"><img src="https://img.shields.io/github/actions/workflow/status/lvillis/tino/ci.yaml?style=flat&logo=githubactions&logoColor=ffffff&label=ci&labelColor=64748b&color=0f766e" alt="CI Status"></a>
  <a href="https://github.com/lvillis/tino/pkgs/container/tino"><img src="https://img.shields.io/badge/ghcr-image-0f766e?style=flat&logo=github&logoColor=ffffff&labelColor=64748b" alt="GHCR Image"></a>
</p>

`tino` is a tiny init process (PID 1) for Docker, Kubernetes, and other container workloads. It is a practical `tini` alternative with signal forwarding, subreaper support, command argument expansion without `/bin/sh`, and optional Linux Landlock restrictions.

## Why Use tino as PID 1

- Runs as PID 1 and forwards signals to the managed process.
- Reaps orphaned children with `-s/--subreaper`.
- Supports parent-death signals, grace timeouts, and exit-code remapping.
- Expands `${VAR}` and `${VAR:-default}` in child arguments without requiring `/bin/sh`.
- On Linux, can restrict writes, TCP ports, IPC scope, executable paths, and device `ioctl` with Landlock.

## Install tino

Install with Cargo:

```bash
cargo install tino
```

Build a release binary:

```bash
cargo build --release --target x86_64-unknown-linux-musl
```

Copy `tino` into your own image:

```dockerfile
COPY --from=ghcr.io/lvillis/tino:latest /sbin/tino /sbin/tino
ENTRYPOINT ["/sbin/tino", "-g", "-s", "--"]
CMD ["/opt/app/service"]
```

## Use tino in Docker and Kubernetes

Run a command locally:

```bash
tino -- /usr/bin/sleep 10
```

Use argument expansion without a shell:

```dockerfile
ENTRYPOINT ["/sbin/tino", "--expand-env", "--"]
CMD ["/opt/app/service", "--port=${SERVICE_PORT:-8900}"]
```

Inspect the final command and effective restrictions without executing the child:

```bash
/sbin/tino --expand-env --write-preset runtime --write-allow /data/logs --explain -- \
  /opt/app/service --port=${SERVICE_PORT:-8900}
```

`--expand-env` is not a shell. Supported forms are `${VAR}`, `${VAR:-default}`, and `$$` for a literal dollar sign. Unbraced `$VAR` is left unchanged.

## Configure tino

The binary reads `/etc/tino/tino.conf` when the file exists. Use `--no-config` to skip it.

The format is line-based: one long option per line, blank lines and lines starting with `#` ignored, no child command.

```text
expand-env
write-preset runtime
write-allow /data/logs
bind-tcp-allow 8900
exec-allow /opt/app/service
```

CLI arguments are applied after the config file.

Use `--print-config` to validate and preview the generated file, or `--write-config` to validate and write `/etc/tino/tino.conf`.

Generate and validate a config during image build:
Run this after the referenced files and directories already exist, so invalid
paths fail during the image build instead of at runtime.

```dockerfile
RUN mkdir -p /data/logs \
  && /sbin/tino --no-config --write-config \
    --expand-env \
    --write-preset runtime \
    --write-allow /data/logs \
    --bind-tcp-allow 8900 \
    --exec-allow /opt/app/service \
  && /sbin/tino --check-config
```

Complete option example:

```text
# /etc/tino/tino.conf
subreaper
pdeath TERM
verbosity 2
warn-on-reap
pgroup-kill
remap-exit 3
grace-ms 500
write-restrict
write-allow /data/logs
write-preset runtime
restrict-warn-only
write-no-dev
bind-tcp-allow 8900
connect-tcp-allow 11800
scope-signals
scope-abstract-unix
exec-allow /opt/app/service
device-ioctl-allow /dev/null
expand-env
```

## Restrict container access with Landlock

Landlock-based restrictions require Linux 5.13+ with Landlock enabled.

- `--write-restrict`, `--write-allow`, `--write-preset` require Landlock ABI v3+ (Linux 6.2+) to cover file truncation; `--write-no-dev` modifies these restrictions
- `--restrict-warn-only` applies to all requested Landlock access restrictions
- `--bind-tcp-allow`, `--connect-tcp-allow` require Landlock ABI v4+
- `--device-ioctl-allow` requires Landlock ABI v5+
- `--scope-signals`, `--scope-abstract-unix` require Landlock ABI v6+
- `--exec-allow` restricts which executables the child may launch after startup

`--write-allow` and `--write-preset` enable write restriction automatically.
Use `--write-restrict` when you want write restriction without adding writable
paths. `/dev` remains writable unless `--write-no-dev` is set.
On older kernels, requested write restrictions prevent the child from starting.
With `--restrict-warn-only`, tino reports the unsupported restriction and starts
the child without applying the requested Landlock restrictions.

Use absolute filesystem paths for write and device `ioctl` allowlists.
`--exec-allow` accepts either an absolute path or a command name resolved from
`PATH`.
Command names allow matching executable files across `PATH`, including fallback
candidates when an earlier match cannot run. Use an absolute path to allow a
specific file.

Example:

```bash
/sbin/tino \
  --write-preset runtime \
  --write-allow /data/logs \
  --bind-tcp-allow 8900 \
  --exec-allow /opt/app/service \
  -- \
  /opt/app/service --port=8900
```

If Docker blocks `landlock_*` syscalls, pass a seccomp profile that allows
them. This repository provides `seccomp-landlock.json` for Docker-based tests
and deployments:

```bash
docker run --rm -it \
  --security-opt seccomp=./seccomp-landlock.json \
  <image> \
  /sbin/tino --write-restrict --write-allow /data -- /opt/app/service
```

To set it as the Docker default:

```json
{
  "seccomp-profile": "/etc/docker/seccomp-landlock.json"
}
```

## Download binary releases

GitHub Releases publish versioned archives with a single top-level directory:

```text
tino-<version>-<os>-<arch>-<abi>/
  tino
  LICENSE
  README.md
```

Supported assets:

| OCI platform | Rust target | Release asset |
| --- | --- | --- |
| `linux/amd64` | `x86_64-unknown-linux-gnu` | `tino-<version>-linux-x86_64-gnu.tar.gz` |
| `linux/amd64` | `x86_64-unknown-linux-musl` | `tino-<version>-linux-x86_64-musl.tar.gz` |
| `linux/arm64` | `aarch64-unknown-linux-musl` | `tino-<version>-linux-aarch64-musl.tar.gz` |
| `linux/arm/v6` | `arm-unknown-linux-gnueabihf` | `tino-<version>-linux-arm-gnueabihf.tar.gz` |
| `linux/arm/v7` | `armv7-unknown-linux-gnueabihf` | `tino-<version>-linux-armv7-gnueabihf.tar.gz` |

Each release also includes:

- `SHA256SUMS`
- per-asset `*.spdx.json` SBOM files
- GitHub artifact attestations for archives and SBOMs

## Environment defaults

Default successful runs are quiet. Use `-v` for `INFO` logs and `-vv` for `DEBUG`.

These environment variables act as defaults. Explicit CLI flags still win.

- `TINO_SUBREAPER`
- `TINO_KILL_PROCESS_GROUP`
- `TINO_VERBOSITY`

The matching `TINI_*` names are also accepted for compatibility. When both are set,
`TINO_*` wins.

## Testing

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-features --locked
cargo test --doc --all-features --locked
cargo package --allow-dirty --locked
cargo bench --bench logic_paths
```

On Unix targets, `tests/unix_behaviour.rs` covers the CLI license output, missing-command errors, exit-code remapping, environment expansion, and Landlock behavior.
