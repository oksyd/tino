//! Library entry points for `tino`.
//!
//! `tino` is primarily a command-line tool: a tiny init process (PID 1) for
//! Docker, Kubernetes, and other container workloads. The library surface is
//! intentionally small and mirrors the binary's runtime behavior.
//!
//! The main entry point is [`run`], which executes a parsed [`Cli`] value.
//! Linux-specific restrictions such as Landlock are configured through CLI
//! flags and follow the same semantics as the `tino` binary.
//!
//! # Example
//!
//! ```no_run
//! use tino::{Cli, run};
//!
//! let cli = Cli::parse_from(["tino", "--", "/usr/bin/sleep", "10"]);
//! let exit_code = run(cli)?;
//! # let _ = exit_code;
//! # Ok::<(), tino::Error>(())
//! ```
//!
//! This crate is binary-first. Internal helper APIs are not part of the
//! stable public interface unless they are explicitly documented here.

#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod cli;
mod diagnostic;
mod error;
mod logging;
mod platform;
mod signals;

/// Parsed `tino` command-line configuration.
///
/// This type mirrors the `tino` binary CLI and is intended to be constructed
/// through [`Cli::parse`], [`Cli::parse_from`], or [`Cli::try_parse_from`],
/// rather than by manually filling every field.
pub use cli::{Cli, DEFAULT_CONFIG_PATH, WritePreset};

/// Bundled project license text.
///
/// This is the same text printed by the `--license` CLI flag.
pub const LICENSE_TEXT: &str = include_str!("../LICENSE");

pub use error::{Context, Error, Result};

/// Execute `tino` with a parsed [`Cli`] configuration.
///
/// Returns the final process exit code that should be used by the caller.
/// Errors are reserved for configuration, setup, or runtime failures that
/// prevent normal supervision from completing.
///
/// In typical usage, the `tino` binary calls this function and then exits with
/// the returned code.
///
/// On Linux, supervision requires a single-threaded process and procfs mounted
/// at `/proc` so this precondition can be checked. It takes ownership of signal
/// handling and child reaping for the duration of the call. Multithreaded hosts
/// must launch the `tino` binary as a subprocess; otherwise this function returns
/// an error before changing signal state or spawning the managed command.
/// Configuration-only operations do not have this restriction.
pub fn run(cli: Cli) -> Result<i32> {
    platform::run(cli)
}

#[doc(hidden)]
pub mod bench_support {
    use crate::Result;

    pub fn resolve_command_args(cmd: &[String], expand_env: bool) -> Result<Vec<String>> {
        crate::platform::bench_resolve_command_args(cmd, expand_env)
    }

    pub fn parse_shebang_interpreter(bytes: &[u8]) -> Option<String> {
        crate::platform::bench_parse_shebang_interpreter(bytes)
    }

    pub fn parse_elf_interpreter(bytes: &[u8]) -> Result<Option<String>> {
        crate::platform::bench_parse_elf_interpreter(bytes)
    }
}
