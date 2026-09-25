<p align="center">
  <img src="assets/logo.svg" alt="tino - tiny init process for containers" width="320">
</p>

<p align="center">
  tiny init process (PID 1) for Docker, Kubernetes, and other containers
</p>

<p align="center">
  <a href="https://crates.io/crates/tino"><img src="https://img.shields.io/crates/v/tino?style=flat&logo=rust&logoColor=ffffff&label=crate&labelColor=64748b&color=0f766e" alt="Crate Version"></a>
  <a href="https://github.com/oksyd/tino/actions"><img src="https://img.shields.io/github/actions/workflow/status/oksyd/tino/ci.yaml?style=flat&logo=githubactions&logoColor=ffffff&label=ci&labelColor=64748b&color=0f766e" alt="CI Status"></a>
  <a href="https://github.com/oksyd/tino/pkgs/container/tino"><img src="https://img.shields.io/badge/ghcr-image-0f766e?style=flat&logo=github&logoColor=ffffff&labelColor=64748b" alt="GHCR Image"></a>
</p>

`tino` is a Linux init process for containers, written in Rust. It forwards
signals, reaps orphaned processes, and supports optional Landlock access restrictions.

## Installation

```bash
cargo install tino
```

[Binary releases](https://github.com/oksyd/tino/releases) support x86_64
(GNU/musl), aarch64 (musl), and ARMv6/v7 (GNU). Each release includes checksums,
SPDX SBOMs, and GitHub artifact attestations.

For container images:

```dockerfile
COPY --from=ghcr.io/oksyd/tino:latest /sbin/tino /sbin/tino
ENTRYPOINT ["/sbin/tino", "-g", "-s", "--"]
CMD ["/opt/app/service"]
```

## Usage

```bash
tino -- /usr/bin/sleep 10
tino --expand-env -- /opt/app/service '--port=${SERVICE_PORT:-8900}'
tino --help
```

Options precede the command; subsequent arguments are passed to the child.
`-g` forwards signals to the child's process group, and `-s` enables subreaping.
Use `-v` / `--verbose` for INFO logs and `-vv` for DEBUG.

`--expand-env` supports `${VAR}`, `${VAR:-default}`, and `$$` without a shell.
Quote expressions when invoking tino from a shell; unbraced `$VAR` is unchanged.

Child exit status is preserved unless remapped with `--remap-exit`. Signals return
`128 + signal`; lookup and execution failures return `127` and `126`.
Usage errors return `2`; operational errors return `1`. Errors go to stderr.

## Configuration

`/etc/tino/tino.conf` accepts one setting per line; blank lines and `#` comments
are ignored. Most keys match long options; use `verbosity 0-3` for logging.

```text
subreaper
pgroup-kill
write-preset runtime
write-allow /data/logs
```

CLI scalars override file values, lists append, and boolean flags only enable
settings. `--no-config` skips the file. `TINO_SUBREAPER`,
`TINO_KILL_PROCESS_GROUP`, and `TINO_VERBOSITY` supply defaults for settings still
false or zero. Matching `TINI_*` names are accepted; `TINO_*` takes precedence.

| Option | Purpose |
| --- | --- |
| `--print-config` | Validate and print config from CLI options and built-in defaults |
| `--write-config` | Validate and replace the config file using the same inputs |
| `--check-config` | Validate the existing file; accepts no runtime options |
| `--explain` | Inspect effective settings and an optional command without running it |

These modes are mutually exclusive; only `--explain` accepts a command.
`--print-config` and `--write-config` ignore existing file and environment defaults.
Ensure referenced files and directories already exist before validation.

## Access restrictions

Landlock must be enabled in the kernel. Required ABI versions vary by feature:

| Feature | Options | Minimum ABI |
| --- | --- | --- |
| Execution | `--exec-allow` | v1 |
| Filesystem writes | `--write-restrict`, `--write-allow`, `--write-preset` | v3 |
| TCP ports | `--bind-tcp-allow`, `--connect-tcp-allow` | v4 |
| Device ioctl | `--device-ioctl-allow` | v5 |
| IPC scope | `--scope-signals`, `--scope-abstract-unix` | v6 |

```bash
tino --write-preset runtime --write-allow /data/logs \
  --bind-tcp-allow 8900 --exec-allow /opt/app/service -- /opt/app/service
```

`--write-allow` and `--write-preset` enable write restriction automatically.
Paths must be absolute; `/dev` stays writable unless `--write-no-dev` is set.
Presets allow `/tmp` and `/var/tmp` (`tmp`), plus `/run` (`runtime`).
Restriction failures prevent startup; `--restrict-warn-only` allows startup
without the requested Landlock restrictions.

`--exec-allow` accepts absolute paths or command names resolved across `PATH`.
The main command and discovered interpreters/loaders are automatically allowed.
Execution restrictions do not block reads or executable memory mappings:
allowed interpreters and loaders can still run code from other readable files.

If Docker blocks Landlock syscalls, use the bundled [seccomp profile](seccomp-landlock.json):

```bash
docker run --rm --security-opt seccomp=./seccomp-landlock.json <image>
```
