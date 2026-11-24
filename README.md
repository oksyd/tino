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

For a container image that runs a fixed service, put the service in `ENTRYPOINT`
and its default arguments in `CMD`.

```dockerfile
COPY --from=ghcr.io/oksyd/tino:latest /sbin/tino /sbin/tino
ENTRYPOINT ["/sbin/tino", "-g", "-s", "--", "/opt/app/service"]
CMD ["--port", "8900"]
```

`docker run IMAGE --help` opens the service's help. Use
`docker run --entrypoint /sbin/tino IMAGE --help` for tino's help.
For an image with a replaceable command, end `ENTRYPOINT` at `"--"` and put the command in `CMD`.

## Usage

```bash
tino -- /usr/bin/sleep 10
tino --expand-env -- /opt/app/service '--port=${SERVICE_PORT:-8900}'
tino --help
```

Options precede the command. The command and its arguments must be valid UTF-8.
`-g` forwards signals to the child's process group, and `-s` enables subreaping.
Omit `-g` in interactive shell pipelines so Ctrl-C reaches every stage when the child reads from the terminal.
Use `-v` / `--verbose` for INFO logs and `-vv` for DEBUG.

SIGTERM, SIGINT and SIGQUIT start shutdown. For a custom Docker `STOPSIGNAL` such as
SIGUSR1, pass `--stop-signal SIGUSR1`. Use the signal number for real-time signals.
By default tino waits after forwarding a stop signal. During `docker stop`, Docker
enforces the timeout. With `--grace-ms MS`, tino sends SIGKILL when its timer expires
or on a second stop signal. A value of `0` makes escalation immediate.
After sending SIGKILL to the group, tino allows up to 500 ms to reap exiting workers.
During shutdown, tino waits for the managed group with `-g`. Without `-g`, PID 1
waits for adopted children, and the service signals its own workers. After a natural
main-process exit, cleanup uses `--grace-ms` or 500 ms by default.

`--expand-env` supports `${VAR}`, `${VAR:-default}`, and `$$` without a shell.
Quote expressions when invoking tino from a shell; unbraced `$VAR` is unchanged.

`--remap-exit CODE` treats a matching service status as success. A signal that
terminates the process during or after exec can also be remapped as `128 + signal`.
If the command or its interpreter cannot be found, tino returns `127`.
Other exec failures return `126` and operational errors return `1`, even with a matching remap.
Usage errors return `2`. Errors go to stderr.

## Configuration

`/etc/tino/tino.conf` takes one `KEY [VALUE]` per line, separated by whitespace.
Put `#` comments on their own lines. A `#` inside a path is literal.
Runtime settings use their long option names. Use `verbosity 0-3` for logging.

```text
subreaper
pgroup-kill
write-preset runtime
write-allow /data/logs
```

CLI scalars override file values; verbosity flags add to the file value.
Lists append, and boolean flags only enable settings. `--no-config` skips the file.
`TINO_SUBREAPER`, `TINO_KILL_PROCESS_GROUP`, and `TINO_VERBOSITY` supply defaults
for settings still false or zero. Each takes precedence over its `TINI_*` counterpart.
Setting `TINI_SUBREAPER` or `TINI_KILL_PROCESS_GROUP` enables that option, even with
an empty value or `0`. `TINI_VERBOSITY` uses tino's 0–3 verbosity scale.

| Option | Purpose |
| --- | --- |
| `--print-config` | Validate and print config from CLI options and built-in defaults |
| `--write-config` | Validate and replace the config file using the same inputs |
| `--check-config` | Validate the existing file; accepts no runtime options |
| `--explain` | Preview effective settings and expanded command arguments |

These modes are mutually exclusive. Only `--explain` accepts a command.
`--explain` returns `0` when it can build the preview, even for a missing executable.
The kernel applies restrictions at launch.
`--print-config` and `--write-config` ignore existing file and environment defaults.
Explicit Landlock allow paths must exist during validation.

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

`--write-allow` takes an existing absolute directory and enables write restriction.
`--write-preset` also enables it for `/tmp` and `/var/tmp` (`tmp`), plus `/run` (`runtime`).
`--write-no-dev` removes the automatic `/dev` grant. Explicit grants still apply.

With only execution or device ioctl restrictions, cross-directory renames and hard
links fail with `EXDEV`, even on one filesystem. With write restrictions enabled,
both parent directories need write grants, and the destination must not give the
object additional Landlock access.

TCP bind and connect are independent. Each direction is unrestricted until given a port.
`--restrict-warn-only` permits startup if applying a valid policy fails. Invalid paths still stop startup.

`--exec-allow` accepts absolute paths or command names resolved across `PATH`.
The main command and discovered interpreters/loaders are automatically allowed.
Execution restrictions do not block reads or executable memory mappings:
allowed interpreters and loaders can still run code from other readable files.

If Docker blocks Landlock syscalls, use the bundled [seccomp profile](seccomp-landlock.json):

```bash
docker run --rm --security-opt seccomp=./seccomp-landlock.json <image>
```
