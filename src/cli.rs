use crate::{
    Error,
    diagnostic::{escape_bytes, escape_os, escape_str},
    signals::ParentDeathSignal,
};
use osarg::{Arg, Parser, count_flag, set_flag, standard};
use std::error::Error as StdError;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, BufRead, BufReader, Read};
use std::path::Path;

/// Default line-based configuration file read by the `tino` binary.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/tino/tino.conf";

const USAGE: &str = "usage: tino [OPTIONS] [--] CMD [ARGS...]";
const HELP_TEXT: &str = concat!(
    "Options:\n",
    "  -s, --subreaper                Reap orphaned descendants\n",
    "  -p, --parent-death-signal SIG  Signal child if tino dies\n",
    "  -g, --pgroup-kill              Forward signals to the child's process group\n",
    "  -w, --warn-on-reap             Warn on secondary reaps; enables subreaper\n",
    "  -t, --grace-ms MS              Local SIGKILL timer on stop (off by default)\n",
    "      --stop-signal SIG          Recognize an additional shutdown signal\n",
    "  -e, --remap-exit CODE          Treat a service exit of CODE as success\n",
    "  -v, --verbose                  Increase logging (-v: INFO, -vv: DEBUG)\n",
    "      --expand-env               Expand environment variables in CMD/ARGS\n",
    "  -h, --help                     Show help\n",
    "  -V, --version                  Show version\n\n",
    "Landlock (Linux):\n",
    "      --write-restrict           Restrict child filesystem writes\n",
    "      --write-allow DIR          Enable write restriction and allow an existing absolute dir\n",
    "      --write-preset PRESET      Allow tmp/runtime writes; enables restriction\n",
    "      --write-no-dev             Do not automatically allow /dev writes\n",
    "      --bind-tcp-allow PORT      Allow TCP binding only on selected ports\n",
    "      --connect-tcp-allow PORT   Allow TCP connections only to selected ports\n",
    "      --scope-signals            Limit signals to the same Landlock domain\n",
    "      --scope-abstract-unix      Limit abstract sockets to the same domain\n",
    "      --exec-allow PATH|CMD      Allow executing PATH or PATH-resolved CMD\n",
    "      --device-ioctl-allow PATH  Allow device ioctl beneath absolute PATH\n",
    "      --restrict-warn-only       Warn and continue if applying a valid policy fails\n\n",
    "Config (/etc/tino/tino.conf):\n",
    "      --explain                  Preview effective settings and command arguments\n",
    "      --print-config             Validate and print config from CLI options\n",
    "      --write-config             Validate and replace the config file\n",
    "      --check-config             Validate the config file\n",
    "      --no-config                Skip the config file\n\n",
    "Documentation: https://github.com/oksyd/tino#readme\n",
);

const VERSION_TEXT: &str = concat!(env!("CARGO_PKG_NAME"), " ", env!("CARGO_PKG_VERSION"), "\n");

/// Named presets for conservative writable directory allowlists.
///
/// These presets are only meaningful on Linux when Landlock-based write
/// restriction is enabled.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WritePreset {
    /// Allow `/tmp` and `/var/tmp`.
    Tmp,
    /// Allow `/tmp`, `/var/tmp`, and `/run`.
    Runtime,
}

impl WritePreset {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Tmp => "tmp",
            Self::Runtime => "runtime",
        }
    }

    fn parse(raw: &str) -> Result<Self, CliParseError> {
        match raw {
            "tmp" => Ok(Self::Tmp),
            "runtime" => Ok(Self::Runtime),
            _ => Err(CliParseError::message(format!(
                "invalid value for --write-preset: {} (expected tmp or runtime)",
                escape_str(raw)
            ))),
        }
    }
}

/// An additional signal that starts graceful shutdown when tino receives it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StopSignal(i32);

impl StopSignal {
    #[cfg(target_os = "linux")]
    pub(crate) const fn number(self) -> libc::c_int {
        self.0
    }
}

impl std::str::FromStr for StopSignal {
    type Err = CliParseError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        cfg_select! {
            target_os = "linux" => {
                crate::platform::unix::parse_stop_signal(raw).map(Self).ok_or_else(|| {
                    CliParseError::message(format!(
                        "invalid stop signal '{}': expected a forwardable Linux signal name or number",
                        escape_str(raw)
                    ))
                })
            }
            _ => {
                let _ = raw;
                Err(CliParseError::message("--stop-signal requires Linux".into()))
            }
        }
    }
}

impl fmt::Display for StopSignal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        #[cfg(target_os = "linux")]
        if let Some(name) = crate::platform::unix::signal_name(self.0) {
            return write!(formatter, "SIG{name}");
        }
        self.0.fmt(formatter)
    }
}

/// Kind of CLI parsing failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CliParseErrorKind {
    /// Argument parsing failed.
    Message,
    /// Fixed configuration file parsing failed.
    Config,
    /// `--help` or `-h` was requested.
    Help,
    /// `--version` or `-V` was requested.
    Version,
}

/// Error returned by [`Cli::try_parse_from`].
#[derive(Debug)]
pub struct CliParseError {
    kind: CliParseErrorKind,
    error: Error,
}

impl CliParseError {
    fn message(message: String) -> Self {
        std::hint::cold_path();
        Self {
            kind: CliParseErrorKind::Message,
            error: Error::usage(message),
        }
    }

    fn config(error: Error) -> Self {
        std::hint::cold_path();
        Self {
            kind: CliParseErrorKind::Config,
            error,
        }
    }

    fn help() -> Self {
        Self {
            kind: CliParseErrorKind::Help,
            error: Error::msg(format!("{USAGE}\n\n{HELP_TEXT}")),
        }
    }

    fn version() -> Self {
        Self {
            kind: CliParseErrorKind::Version,
            error: Error::msg(VERSION_TEXT),
        }
    }

    /// Returns the parsing error category.
    #[must_use]
    pub const fn kind(&self) -> CliParseErrorKind {
        self.kind
    }

    pub(crate) fn failure_exit_code(&self) -> i32 {
        self.error.exit_code()
    }

    fn print_and_exit(&self) -> ! {
        // This path always exits. Failed output must not replace the intended
        // status with SIGXFSZ when a redirected file reaches its size limit.
        #[cfg(all(unix, not(target_os = "linux")))]
        unsafe {
            libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        }
        match self.kind {
            CliParseErrorKind::Help | CliParseErrorKind::Version => {
                if let Err(err) = crate::platform::write_stdout(self.to_string().as_bytes()) {
                    crate::logging::stderr_line(format_args!("error: {err:#}"));
                    std::process::exit(1);
                }
                std::process::exit(0);
            }
            CliParseErrorKind::Message | CliParseErrorKind::Config => {
                std::hint::cold_path();
                if self.kind == CliParseErrorKind::Message {
                    crate::logging::stderr_line(format_args!(
                        "error: {self}\n\n{USAGE}\nTry 'tino --help' for more information."
                    ));
                } else {
                    crate::logging::stderr_line(format_args!("error: {self}"));
                }
                std::process::exit(self.failure_exit_code());
            }
        }
    }
}

impl fmt::Display for CliParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)?;
        if !f.alternate()
            && let Some(source) = self.source()
        {
            write!(f, ": {source}")?;
        }
        Ok(())
    }
}

impl StdError for CliParseError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.error.source()
    }
}

/// Parsed `tino` command-line configuration.
///
/// This struct mirrors the binary CLI and is the primary configuration type
/// accepted by [`crate::run`]. Most callers should construct it via
/// [`Cli::parse`], [`Cli::parse_from`], or [`Cli::try_parse_from`].
#[derive(Debug, Default)]
pub struct Cli {
    /// Enable `PR_SET_CHILD_SUBREAPER` so this init can reap orphaned grandchildren.
    pub subreaper: bool,
    /// Set a parent-death signal via `PR_SET_PDEATHSIG` (e.g. `TERM`, `SIGTERM`).
    pub pdeath: Option<String>,
    /// Increase log verbosity (-v/--verbose; repeatable).
    pub verbosity: u8,
    /// Emit a warning when reaping secondary child processes.
    pub warn_on_reap: bool,
    /// Forward signals to the child's process group (like `tini -g`).
    pub pgroup_kill: bool,
    /// Treat these service exit codes as success. Launch errors keep their original status.
    pub remap_exit: Vec<u8>,
    /// An additional shutdown signal alongside SIGTERM, SIGINT and SIGQUIT.
    pub stop_signal: Option<StopSignal>,
    /// Optional local grace period before escalating a shutdown signal to SIGKILL.
    /// When omitted, the container runtime controls the shutdown timeout.
    pub grace_ms: Option<u64>,
    /// Restrict child filesystem writes to explicitly allowed directories (Linux only).
    pub write_restrict: bool,
    /// Allow writes beneath an existing absolute directory and enable write restriction (repeatable).
    pub write_allow: Vec<String>,
    /// Add a conservative writable directory preset and enable write restriction.
    pub write_preset: Vec<WritePreset>,
    /// Warn and continue if applying a validated Landlock policy fails.
    pub restrict_warn_only: bool,
    /// Do not automatically allow `/dev` writes (may break TTY/stdout).
    pub write_no_dev: bool,
    /// Allow binding TCP listeners only on these local ports (repeatable; Linux only).
    pub bind_tcp_allow: Vec<u16>,
    /// Allow outbound TCP connections only to these remote ports (repeatable; Linux only).
    pub connect_tcp_allow: Vec<u16>,
    /// Restrict signal delivery to processes within the same Landlock domain (Linux only).
    pub scope_signals: bool,
    /// Restrict abstract UNIX socket connects to the same Landlock domain (Linux only).
    pub scope_abstract_unix: bool,
    /// Allow executing files beneath this path when exec restriction is enabled (repeatable).
    /// Discovered interpreters/loaders are allowed too; they may run other readable code.
    pub exec_allow: Vec<String>,
    /// Allow device ioctl operations beneath this path (directory or device node; repeatable).
    pub device_ioctl_allow: Vec<String>,
    /// Expand `${VAR}` and `${VAR:-default}` in child command arguments; `$$` becomes `$`.
    pub expand_env: bool,
    /// Explain the effective configuration and command, then exit without running the child.
    pub explain: bool,
    /// Print line-based configuration for active options, then exit.
    pub print_config: bool,
    /// Write line-based configuration for active options to [`DEFAULT_CONFIG_PATH`], then exit.
    pub write_config: bool,
    /// Validate the fixed configuration file, then exit.
    pub check_config: bool,
    /// Skip the fixed configuration file at [`DEFAULT_CONFIG_PATH`].
    pub no_config: bool,
    /// Child command and trailing arguments.
    pub cmd: Vec<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlMode {
    CheckConfig,
    WriteConfig,
    PrintConfig,
    Explain,
}

impl ControlMode {
    const fn option(self) -> &'static str {
        match self {
            Self::CheckConfig => "--check-config",
            Self::WriteConfig => "--write-config",
            Self::PrintConfig => "--print-config",
            Self::Explain => "--explain",
        }
    }
}

impl Cli {
    pub(crate) fn control_mode(&self) -> Result<Option<ControlMode>, String> {
        if self.no_config && self.check_config {
            return Err("--no-config cannot be used with --check-config".into());
        }

        let modes = [
            (self.check_config, ControlMode::CheckConfig),
            (self.write_config, ControlMode::WriteConfig),
            (self.print_config, ControlMode::PrintConfig),
            (self.explain, ControlMode::Explain),
        ];
        let mut selected = modes
            .iter()
            .filter_map(|&(enabled, mode)| enabled.then_some(mode));
        let Some(first) = selected.next() else {
            return Ok(None);
        };
        if let Some(second) = selected.next() {
            return Err(format!(
                "{} cannot be used with {}",
                first.option(),
                second.option()
            ));
        }
        if first == ControlMode::CheckConfig
            && let Some(option) = self.check_config_inline_option()
        {
            return Err(format!("--check-config does not accept {option}"));
        }
        if first != ControlMode::Explain && !self.cmd.is_empty() {
            return Err(format!("{} does not accept CMD", first.option()));
        }
        Ok(Some(first))
    }

    fn check_config_inline_option(&self) -> Option<&'static str> {
        [
            (self.subreaper, "--subreaper"),
            (self.pdeath.is_some(), "--parent-death-signal"),
            (self.verbosity > 0, "--verbose"),
            (self.warn_on_reap, "--warn-on-reap"),
            (self.pgroup_kill, "--pgroup-kill"),
            (!self.remap_exit.is_empty(), "--remap-exit"),
            (self.grace_ms.is_some(), "--grace-ms"),
            (self.stop_signal.is_some(), "--stop-signal"),
            (self.write_restrict, "--write-restrict"),
            (!self.write_allow.is_empty(), "--write-allow"),
            (!self.write_preset.is_empty(), "--write-preset"),
            (self.restrict_warn_only, "--restrict-warn-only"),
            (self.write_no_dev, "--write-no-dev"),
            (!self.bind_tcp_allow.is_empty(), "--bind-tcp-allow"),
            (!self.connect_tcp_allow.is_empty(), "--connect-tcp-allow"),
            (self.scope_signals, "--scope-signals"),
            (self.scope_abstract_unix, "--scope-abstract-unix"),
            (!self.exec_allow.is_empty(), "--exec-allow"),
            (!self.device_ioctl_allow.is_empty(), "--device-ioctl-allow"),
            (self.expand_env, "--expand-env"),
        ]
        .into_iter()
        .find_map(|(enabled, option)| enabled.then_some(option))
    }

    fn merge_config(base: Self, cli: Self) -> Self {
        fn merge_list<T>(mut configured: Vec<T>, command_line: Vec<T>) -> Vec<T> {
            if configured.is_empty() {
                return command_line;
            }
            configured.extend(command_line);
            configured
        }

        Cli {
            subreaper: base.subreaper || cli.subreaper,
            pdeath: cli.pdeath.or(base.pdeath),
            verbosity: base.verbosity.saturating_add(cli.verbosity),
            warn_on_reap: base.warn_on_reap || cli.warn_on_reap,
            pgroup_kill: base.pgroup_kill || cli.pgroup_kill,
            remap_exit: merge_list(base.remap_exit, cli.remap_exit),
            stop_signal: cli.stop_signal.or(base.stop_signal),
            grace_ms: cli.grace_ms.or(base.grace_ms),
            write_restrict: base.write_restrict || cli.write_restrict,
            write_allow: merge_list(base.write_allow, cli.write_allow),
            write_preset: merge_list(base.write_preset, cli.write_preset),
            restrict_warn_only: base.restrict_warn_only || cli.restrict_warn_only,
            write_no_dev: base.write_no_dev || cli.write_no_dev,
            bind_tcp_allow: merge_list(base.bind_tcp_allow, cli.bind_tcp_allow),
            connect_tcp_allow: merge_list(base.connect_tcp_allow, cli.connect_tcp_allow),
            scope_signals: base.scope_signals || cli.scope_signals,
            scope_abstract_unix: base.scope_abstract_unix || cli.scope_abstract_unix,
            exec_allow: merge_list(base.exec_allow, cli.exec_allow),
            device_ioctl_allow: merge_list(base.device_ioctl_allow, cli.device_ioctl_allow),
            expand_env: base.expand_env || cli.expand_env,
            explain: cli.explain,
            print_config: cli.print_config,
            write_config: cli.write_config,
            check_config: cli.check_config,
            no_config: cli.no_config,
            cmd: cli.cmd,
        }
    }

    /// Parses command-line arguments from the process environment.
    ///
    /// The binary path reads [`DEFAULT_CONFIG_PATH`] when present. Use
    /// [`Cli::try_parse_from`] for argument-only parsing.
    #[must_use]
    pub fn parse() -> Self {
        match Self::try_parse_with_default_config_from(std::env::args_os()) {
            Ok(cli) => cli,
            Err(err) => err.print_and_exit(),
        }
    }

    /// Parses process-style command-line arguments.
    ///
    /// The first item must be `argv[0]` (the program name). This helper only
    /// parses the provided arguments and does not read [`DEFAULT_CONFIG_PATH`].
    #[must_use]
    pub fn parse_from<I, T>(args: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        match Self::try_parse_from(args) {
            Ok(cli) => cli,
            Err(err) => err.print_and_exit(),
        }
    }

    /// Tries to parse process-style command-line arguments.
    ///
    /// The first item must be `argv[0]` (the program name). This helper only
    /// parses the provided arguments and does not read [`DEFAULT_CONFIG_PATH`].
    ///
    /// Help and version requests return distinct error kinds without exiting:
    ///
    /// ```
    /// use tino::{Cli, CliParseError, CliParseErrorKind};
    ///
    /// let error: CliParseError = Cli::try_parse_from(["tino", "--help"]).unwrap_err();
    /// assert_eq!(error.kind(), CliParseErrorKind::Help);
    /// ```
    pub fn try_parse_from<I, T>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        Self::parse_args(args)
    }

    /// Tries to parse process-like arguments and merge the fixed config file.
    ///
    /// Arguments are parsed once, then merged over the config file.
    /// Passing `--no-config`, `--print-config`,
    /// `--write-config`, or `--check-config` skips config-file loading.
    /// Standard `--help` and `--version` requests return their corresponding
    /// [`CliParseErrorKind`] during CLI-only parsing, without exiting.
    pub fn try_parse_with_default_config_from<I, T>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        Self::try_parse_with_config_from(args, load_default_config)
    }

    fn try_parse_with_config_from<I, T>(
        args: I,
        load: impl FnOnce() -> Result<Self, CliParseError>,
    ) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let cli = Self::parse_args(args)?;
        if cli.no_config || cli.print_config || cli.write_config || cli.check_config {
            return Ok(cli);
        }
        Ok(Self::merge_config(load()?, cli))
    }

    fn parse_args<I, T>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut cli = Self::default();
        let mut argv = args.into_iter().map(Into::into);
        if argv.next().is_none() {
            return Err(CliParseError::message("missing argv[0]".to_owned()));
        }
        let mut parser = Parser::new(argv);
        while let Some(arg) = parser.next().map_err(from_osarg_error)? {
            if let Some(flag) = standard::classify(arg) {
                // Help and version return before next() can reject an attached value.
                parser.check_flag().map_err(from_osarg_error)?;
                return Err(match flag {
                    standard::Flag::Help => CliParseError::help(),
                    standard::Flag::Version => CliParseError::version(),
                });
            }

            let flag_slot = match arg {
                Arg::Short('s') | Arg::Long("subreaper") => Some(&mut cli.subreaper),
                Arg::Short('w') | Arg::Long("warn-on-reap") => Some(&mut cli.warn_on_reap),
                Arg::Short('g') | Arg::Long("pgroup-kill") => Some(&mut cli.pgroup_kill),
                Arg::Long("write-restrict") => Some(&mut cli.write_restrict),
                Arg::Long("restrict-warn-only") => Some(&mut cli.restrict_warn_only),
                Arg::Long("write-no-dev") => Some(&mut cli.write_no_dev),
                Arg::Long("scope-signals") => Some(&mut cli.scope_signals),
                Arg::Long("scope-abstract-unix") => Some(&mut cli.scope_abstract_unix),
                Arg::Long("expand-env") => Some(&mut cli.expand_env),
                Arg::Long("explain") => Some(&mut cli.explain),
                Arg::Long("print-config") => Some(&mut cli.print_config),
                Arg::Long("write-config") => Some(&mut cli.write_config),
                Arg::Long("check-config") => Some(&mut cli.check_config),
                Arg::Long("no-config") => Some(&mut cli.no_config),
                _ => None,
            };
            if let Some(slot) = flag_slot {
                set_flag(slot);
                continue;
            }

            match arg {
                Arg::Short('p') | Arg::Long("parent-death-signal") => {
                    let raw = parser
                        .string()
                        .map_err(|err| option_osarg_error("--parent-death-signal", err))?;
                    cli.pdeath = Some(parse_signal(raw)?);
                }
                Arg::Short('v') | Arg::Long("verbose") => {
                    count_flag(&mut cli.verbosity);
                }
                Arg::Short('e') | Arg::Long("remap-exit") => {
                    cli.remap_exit.push(
                        parser
                            .parse()
                            .map_err(|err| option_osarg_error("--remap-exit", err))?,
                    );
                }
                Arg::Short('t') | Arg::Long("grace-ms") => {
                    cli.grace_ms = Some(
                        parser
                            .parse()
                            .map_err(|err| option_osarg_error("--grace-ms", err))?,
                    );
                }
                Arg::Long("stop-signal") => {
                    let raw = parser
                        .string()
                        .map_err(|err| option_osarg_error("--stop-signal", err))?;
                    cli.stop_signal = Some(raw.parse()?);
                }
                Arg::Long("write-allow") => {
                    cli.write_allow
                        .push(parse_string_value(&mut parser, "--write-allow")?);
                }
                Arg::Long("write-preset") => {
                    let preset = parse_string_value(&mut parser, "--write-preset")?;
                    cli.write_preset.push(WritePreset::parse(&preset)?);
                }
                Arg::Long("bind-tcp-allow") => {
                    cli.bind_tcp_allow
                        .push(parse_port_value(&mut parser, "--bind-tcp-allow")?);
                }
                Arg::Long("connect-tcp-allow") => {
                    cli.connect_tcp_allow
                        .push(parse_port_value(&mut parser, "--connect-tcp-allow")?);
                }
                Arg::Long("exec-allow") => {
                    cli.exec_allow
                        .push(parse_string_value(&mut parser, "--exec-allow")?);
                }
                Arg::Long("device-ioctl-allow") => {
                    cli.device_ioctl_allow
                        .push(parse_string_value(&mut parser, "--device-ioctl-allow")?);
                }
                Arg::Value(_) => {
                    let (command, remaining) = parser
                        .current_value_and_remaining()
                        .map_err(from_osarg_error)?;
                    cli.cmd = std::iter::once(command)
                        .chain(remaining)
                        .enumerate()
                        .map(|(index, arg)| {
                            arg.into_string().map_err(|_| {
                                CliParseError::message(format!(
                                    "child argv[{index}] is not valid UTF-8"
                                ))
                            })
                        })
                        .collect::<Result<_, _>>()?;
                    break;
                }
                other => return Err(from_osarg_error(other.unexpected())),
            }
        }

        cli.control_mode().map_err(CliParseError::message)?;
        Ok(cli)
    }

    pub(crate) fn resolved_verbosity(&self) -> u8 {
        self.verbosity.min(3)
    }

    pub(crate) fn load_required_config(path: &Path) -> crate::Result<Self> {
        load_config(path, true).map_err(|err| err.error)
    }

    pub(crate) fn parent_death_signal(&self) -> Result<Option<&'static ParentDeathSignal>, String> {
        self.pdeath
            .as_deref()
            .map(ParentDeathSignal::parse)
            .transpose()
    }

    pub(crate) fn config_text(&self) -> Result<String, CliParseError> {
        let mut out = String::new();
        push_config_flag(&mut out, self.subreaper, "subreaper");
        if let Some(signal) = self.parent_death_signal().map_err(CliParseError::message)? {
            push_config_value(&mut out, "parent-death-signal", signal.name);
        }
        let verbosity = self.resolved_verbosity();
        if verbosity > 0 {
            push_config_value(&mut out, "verbosity", verbosity);
        }
        push_config_flag(&mut out, self.warn_on_reap, "warn-on-reap");
        push_config_flag(&mut out, self.pgroup_kill, "pgroup-kill");
        for code in &self.remap_exit {
            push_config_value(&mut out, "remap-exit", *code);
        }
        if let Some(millis) = self.grace_ms {
            push_config_value(&mut out, "grace-ms", millis);
        }
        if let Some(signal) = &self.stop_signal {
            push_config_value(&mut out, "stop-signal", signal);
        }
        push_config_flag(&mut out, self.write_restrict, "write-restrict");
        push_config_paths(&mut out, "write-allow", &self.write_allow)?;
        for preset in &self.write_preset {
            push_config_value(&mut out, "write-preset", preset.as_str());
        }
        push_config_flag(&mut out, self.restrict_warn_only, "restrict-warn-only");
        push_config_flag(&mut out, self.write_no_dev, "write-no-dev");
        for port in &self.bind_tcp_allow {
            push_config_value(
                &mut out,
                "bind-tcp-allow",
                validate_port("--bind-tcp-allow", *port)?,
            );
        }
        for port in &self.connect_tcp_allow {
            push_config_value(
                &mut out,
                "connect-tcp-allow",
                validate_port("--connect-tcp-allow", *port)?,
            );
        }
        push_config_flag(&mut out, self.scope_signals, "scope-signals");
        push_config_flag(&mut out, self.scope_abstract_unix, "scope-abstract-unix");
        push_config_paths(&mut out, "exec-allow", &self.exec_allow)?;
        push_config_paths(&mut out, "device-ioctl-allow", &self.device_ioctl_allow)?;
        push_config_flag(&mut out, self.expand_env, "expand-env");
        Ok(out)
    }
}

fn load_default_config() -> Result<Cli, CliParseError> {
    load_config(Path::new(DEFAULT_CONFIG_PATH), false)
}

fn open_config_file(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(target_family = "unix")]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // A mistaken FIFO must not stall startup before its type can be
        // checked. Opening a device must not acquire a controlling terminal.
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY);
    }
    let file = options.open(path)?;
    // Check the opened object, preserving normal configuration symlinks
    // without racing a separate path metadata check against the open.
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "config path is not a regular file",
        ));
    }
    Ok(file)
}

fn load_config(path: &Path, required: bool) -> Result<Cli, CliParseError> {
    match open_config_file(path) {
        Ok(file) => return parse_config(path, BufReader::new(file)),
        Err(err) if !required && err.kind() == io::ErrorKind::NotFound => {
            // A dangling config symlink is a broken configured entry, not an
            // absent optional file. Do not silently discard its policy.
            match fs::symlink_metadata(path) {
                Err(inspect_err) if inspect_err.kind() == io::ErrorKind::NotFound => {
                    Ok(Cli::default())
                }
                Err(inspect_err) => Err(Error::with_source(
                    format!("inspect {}", path.display()),
                    inspect_err,
                )),
                Ok(_) => Err(config_read_error(path, err)),
            }
        }
        Err(err) => Err(config_read_error(path, err)),
    }
    .map_err(CliParseError::config)
}

fn config_read_error(path: &Path, err: io::Error) -> Error {
    Error::with_source(format!("read {}", path.display()), err)
}

fn push_config_flag(out: &mut String, enabled: bool, key: &str) {
    if enabled {
        out.push_str(key);
        out.push('\n');
    }
}

fn push_config_value(out: &mut String, key: &str, value: impl fmt::Display) {
    let _ = fmt::write(out, format_args!("{key} {value}\n"));
}

fn push_config_paths(out: &mut String, key: &str, paths: &[String]) -> Result<(), CliParseError> {
    for path in paths {
        validate_config_value(key, path).map_err(CliParseError::message)?;
        push_config_value(out, key, path);
    }
    Ok(())
}

fn validate_config_value(key: &str, value: &str) -> Result<(), String> {
    let problem = if value.is_empty() || value != value.trim() {
        "cannot be empty or have surrounding whitespace"
    } else if value.contains(['\n', '\r']) {
        "cannot contain newlines"
    } else if value.contains('\0') {
        "cannot contain NUL bytes"
    } else {
        match key {
            "write-allow" | "device-ioctl-allow" if !Path::new(value).is_absolute() => {
                "must be an absolute path"
            }
            "exec-allow" if value.contains('/') && !Path::new(value).is_absolute() => {
                "must be an absolute path when it contains '/'"
            }
            _ => return Ok(()),
        }
    };
    Err(format!("config value for '{key}' {problem}"))
}

fn parse_config(path: &Path, mut reader: impl BufRead) -> Result<Cli, CliParseError> {
    let mut cli = Cli::default();
    let mut buffer = Vec::new();
    for line_no in 1.. {
        if !read_config_line(&mut reader, &mut buffer)
            .map_err(|err| CliParseError::config(config_read_error(path, err)))?
        {
            break;
        }
        let line = str::from_utf8(&buffer)
            .map_err(|_| config_error(path, line_no, "config line is not valid UTF-8".into()))?
            .trim();
        if !line.is_empty() && !line.starts_with('#') {
            apply_config_line(&mut cli, path, line_no, line)?;
        }
    }
    Ok(cli)
}

fn read_config_line(reader: &mut impl BufRead, buffer: &mut Vec<u8>) -> io::Result<bool> {
    // Reserve before each bounded read so an oversized line returns an I/O error.
    const CHUNK: usize = 8192;
    buffer.clear();
    loop {
        buffer.try_reserve(CHUNK)?;
        let count = reader
            .by_ref()
            .take(CHUNK as u64)
            .read_until(b'\n', buffer)?;
        if count < CHUNK || buffer.ends_with(b"\n") {
            return Ok(!buffer.is_empty());
        }
    }
}

#[cfg(test)]
fn parse_config_content(path: &Path, content: &str) -> Result<Cli, CliParseError> {
    parse_config(path, content.as_bytes())
}

fn apply_config_line(
    cli: &mut Cli,
    path: &Path,
    line_no: usize,
    line: &str,
) -> Result<(), CliParseError> {
    let line = line
        .strip_prefix("--")
        .filter(|s| !s.is_empty())
        .unwrap_or(line);
    let end = line
        .find(|ch: char| ch.is_whitespace() || ch == '=')
        .unwrap_or(line.len());
    let (key, tail) = line.split_at(end);
    let assignment = tail.strip_prefix('=');
    let value = assignment.unwrap_or(tail).trim();
    let value = (!value.is_empty()).then_some(value);
    match key {
        "subreaper" => set_config_flag(&mut cli.subreaper, path, line_no, key, value),
        "parent-death-signal" => {
            cli.pdeath = Some(
                parse_signal(config_value(path, line_no, key, value)?)
                    .map_err(|err| config_error(path, line_no, err.to_string()))?,
            );
            Ok(())
        }
        "verbosity" => {
            cli.verbosity = parse_config_verbosity(path, line_no, key, value)?;
            Ok(())
        }
        "warn-on-reap" => set_config_flag(&mut cli.warn_on_reap, path, line_no, key, value),
        "pgroup-kill" => set_config_flag(&mut cli.pgroup_kill, path, line_no, key, value),
        "remap-exit" => {
            cli.remap_exit
                .push(parse_config_value::<u8>(path, line_no, key, value)?);
            Ok(())
        }
        "grace-ms" => {
            cli.grace_ms = Some(parse_config_value::<u64>(path, line_no, key, value)?);
            Ok(())
        }
        "stop-signal" => {
            cli.stop_signal = Some(parse_config_value(path, line_no, key, value)?);
            Ok(())
        }
        "write-restrict" => set_config_flag(&mut cli.write_restrict, path, line_no, key, value),
        "write-allow" => {
            cli.write_allow
                .push(config_value(path, line_no, key, value)?.to_owned());
            Ok(())
        }
        "write-preset" => {
            let preset = config_value(path, line_no, key, value)?;
            cli.write_preset.push(
                WritePreset::parse(preset)
                    .map_err(|err| config_error(path, line_no, err.to_string()))?,
            );
            Ok(())
        }
        "restrict-warn-only" => {
            set_config_flag(&mut cli.restrict_warn_only, path, line_no, key, value)
        }
        "write-no-dev" => set_config_flag(&mut cli.write_no_dev, path, line_no, key, value),
        "bind-tcp-allow" => {
            cli.bind_tcp_allow
                .push(parse_config_port(path, line_no, key, value)?);
            Ok(())
        }
        "connect-tcp-allow" => {
            cli.connect_tcp_allow
                .push(parse_config_port(path, line_no, key, value)?);
            Ok(())
        }
        "scope-signals" => set_config_flag(&mut cli.scope_signals, path, line_no, key, value),
        "scope-abstract-unix" => {
            set_config_flag(&mut cli.scope_abstract_unix, path, line_no, key, value)
        }
        "exec-allow" => {
            cli.exec_allow
                .push(config_value(path, line_no, key, value)?.to_owned());
            Ok(())
        }
        "device-ioctl-allow" => {
            cli.device_ioctl_allow
                .push(config_value(path, line_no, key, value)?.to_owned());
            Ok(())
        }
        "expand-env" => set_config_flag(&mut cli.expand_env, path, line_no, key, value),
        "explain" | "print-config" | "write-config" | "check-config" | "help" | "version"
        | "no-config" => Err(config_error(
            path,
            line_no,
            format!("'{}' is only allowed on the command line", escape_str(key)),
        )),
        _ => Err(config_error(
            path,
            line_no,
            format!("unknown config option '{}'", escape_str(key)),
        )),
    }?;
    if assignment.is_some() {
        let correction = value.map_or_else(|| key.to_owned(), |v| format!("{key} {v}"));
        return Err(config_error(
            path,
            line_no,
            format!("expected KEY [VALUE], use '{}'", escape_str(&correction)),
        ));
    }
    Ok(())
}

fn set_config_flag(
    target: &mut bool,
    path: &Path,
    line_no: usize,
    key: &str,
    value: Option<&str>,
) -> Result<(), CliParseError> {
    if value.is_some() {
        return Err(config_error(
            path,
            line_no,
            format!("'{key}' does not take a value"),
        ));
    }
    *target = true;
    Ok(())
}

fn config_value<'a>(
    path: &Path,
    line_no: usize,
    key: &str,
    value: Option<&'a str>,
) -> Result<&'a str, CliParseError> {
    let value =
        value.ok_or_else(|| config_error(path, line_no, format!("'{key}' requires a value")))?;
    validate_config_value(key, value).map_err(|message| config_error(path, line_no, message))?;
    Ok(value)
}

fn parse_config_value<T>(
    path: &Path,
    line_no: usize,
    key: &str,
    value: Option<&str>,
) -> Result<T, CliParseError>
where
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let raw = config_value(path, line_no, key, value)?;
    raw.parse::<T>()
        .map_err(|err| config_error(path, line_no, format!("invalid value for '{key}': {err}")))
}

fn parse_config_port(
    path: &Path,
    line_no: usize,
    key: &str,
    value: Option<&str>,
) -> Result<u16, CliParseError> {
    let port = parse_config_value::<u16>(path, line_no, key, value)?;
    validate_port(key, port).map_err(|err| config_error(path, line_no, err.to_string()))
}

fn parse_config_verbosity(
    path: &Path,
    line_no: usize,
    key: &str,
    value: Option<&str>,
) -> Result<u8, CliParseError> {
    let raw = config_value(path, line_no, key, value)?;
    parse_verbosity(raw)
        .map_err(|err| config_error(path, line_no, format!("invalid value for '{key}': {err}")))
}

pub(crate) fn parse_verbosity(raw: &str) -> Result<u8, String> {
    let verbosity = raw.parse::<u8>().map_err(|err| err.to_string())?;
    if verbosity > 3 {
        return Err("expected 0-3".into());
    }
    Ok(verbosity)
}

fn config_error(path: &Path, line_no: usize, message: String) -> CliParseError {
    CliParseError::config(Error::usage(format!(
        "{}:{line_no}: {message}",
        escape_os(path.as_os_str())
    )))
}

fn parse_signal(raw: &str) -> Result<String, CliParseError> {
    ParentDeathSignal::parse(raw)
        .map(|signal| signal.name.to_owned())
        .map_err(CliParseError::message)
}

fn parse_string_value<I>(parser: &mut Parser<I>, option: &str) -> Result<String, CliParseError>
where
    I: Iterator<Item = OsString>,
{
    parser
        .string_owned()
        .map_err(|err| option_osarg_error(option, err))
}

fn parse_port_value<I>(parser: &mut Parser<I>, option: &str) -> Result<u16, CliParseError>
where
    I: Iterator<Item = OsString>,
{
    let port = parser
        .parse::<u16>()
        .map_err(|err| option_osarg_error(option, err))?;
    validate_port(option, port)
}

fn validate_port(option: &str, port: u16) -> Result<u16, CliParseError> {
    if port == 0 {
        return Err(CliParseError::message(format!(
            "invalid value for {option}: 0 (expected 1-65535)"
        )));
    }
    Ok(port)
}

fn from_osarg_error(err: osarg::Error) -> CliParseError {
    CliParseError::message(osarg_error_message(&err))
}

fn option_osarg_error(option: &str, err: osarg::Error) -> CliParseError {
    if err.kind() == osarg::ErrorKind::MissingValue {
        return from_osarg_error(err);
    }
    CliParseError::message(format!("{option}: {}", osarg_error_message(&err)))
}

fn osarg_error_message(err: &osarg::Error) -> String {
    use osarg::ErrorKind;

    match (err.kind(), err.argument()) {
        (ErrorKind::InvalidUtf8, Some(raw)) => {
            format!("argument is not valid UTF-8: {}", escape_os(raw))
        }
        (ErrorKind::UnexpectedValue | ErrorKind::InvalidOptionName, Some(raw)) => {
            // osarg attaches the whole token. Only the option name belongs in this diagnostic.
            let token = raw.as_encoded_bytes();
            let end = token.iter().position(|&b| b == b'=').unwrap_or(token.len());
            let name = escape_bytes(&token[..end]);
            if err.kind() == ErrorKind::UnexpectedValue {
                format!("{name} does not take a value")
            } else {
                format!("option name is invalid or not valid UTF-8: {name}")
            }
        }
        _ => escape_str(&err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(target_family = "unix")]
    use std::os::unix::ffi::OsStringExt;

    type FlagCase<'a> = (&'a [&'a str], fn(&Cli) -> bool);

    fn parse_ok<I, T>(args: I) -> Cli
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        Cli::try_parse_from(args).expect("parse cli")
    }

    #[test]
    fn parse_signal_accepts_known_variants() {
        assert_eq!(parse_signal("TERM").unwrap(), "SIGTERM");
        assert_eq!(parse_signal("sigterm").unwrap(), "SIGTERM");
        assert_eq!(parse_signal("SIGUSR1").unwrap(), "SIGUSR1");
    }

    #[test]
    fn parse_signal_rejects_unknown_values() {
        assert!(parse_signal("NOPE").is_err());
        assert!(parse_signal("").is_err());
    }

    #[test]
    fn parse_signal_rejects_unknown_values_without_raw_control_bytes() {
        let err = parse_signal("\u{1b}[31m").expect_err("control-byte signal must fail");
        let message = err.to_string();

        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn parse_counts_grouped_verbosity_and_collects_command_tail() {
        let cli =
            Cli::try_parse_from(["tino", "-vv", "--", "/bin/echo", "--value"]).expect("parse cli");
        assert_eq!(cli.verbosity, 2);
        assert_eq!(cli.cmd, vec!["/bin/echo", "--value"]);
    }

    #[test]
    fn parse_help_and_version_as_control_flow() {
        let help = Cli::try_parse_from(["tino", "--help"]).unwrap_err();
        assert_eq!(help.kind(), CliParseErrorKind::Help);

        let version = Cli::try_parse_from(["tino", "-V"]).unwrap_err();
        assert_eq!(version.kind(), CliParseErrorKind::Version);
    }

    #[test]
    fn parse_rejects_attached_values_for_long_flags() {
        for flag in [
            "subreaper",
            "warn-on-reap",
            "pgroup-kill",
            "write-restrict",
            "restrict-warn-only",
            "write-no-dev",
            "scope-signals",
            "scope-abstract-unix",
            "expand-env",
            "explain",
            "print-config",
            "write-config",
            "check-config",
            "no-config",
            "help",
            "version",
            "verbose",
        ] {
            for value in ["", "false", "\u{1b}[31m"] {
                let arg = format!("--{flag}={value}");
                let err = Cli::try_parse_from(["tino", &arg]).unwrap_err();
                assert_eq!(err.kind(), CliParseErrorKind::Message, "{arg:?}");
                assert_eq!(err.to_string(), format!("--{flag} does not take a value"));
            }
        }
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn parse_rejects_non_utf8_attached_flag_values() {
        let err = Cli::try_parse_from([
            OsString::from("tino"),
            OsString::from_vec(b"--restrict-warn-only=\xff".to_vec()),
        ])
        .unwrap_err();
        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert_eq!(
            err.to_string(),
            "--restrict-warn-only does not take a value"
        );
    }

    #[test]
    fn parse_preserves_flag_like_values_and_command_arguments() {
        for args in [
            vec![
                "tino",
                "--exec-allow",
                "--write-config=false",
                "--",
                "echo",
                "--no-config=false",
            ],
            vec![
                "tino",
                "--exec-allow=--write-config=false",
                "echo",
                "--no-config=false",
            ],
        ] {
            let cli = parse_ok(args);
            assert_eq!(cli.exec_allow, ["--write-config=false"]);
            assert_eq!(cli.cmd, ["echo", "--no-config=false"]);
            assert!(!cli.write_config);
            assert!(!cli.no_config);
        }
    }

    #[test]
    fn parse_check_config_rejects_explicit_grace() {
        for args in [
            vec!["tino", "--check-config", "--grace-ms", "500"],
            vec!["tino", "--grace-ms=500", "--check-config"],
            vec!["tino", "--check-config", "-t500"],
            vec!["tino", "-t", "1", "-t", "500", "--check-config"],
        ] {
            let err = Cli::try_parse_from(args).unwrap_err();
            assert_eq!(err.kind(), CliParseErrorKind::Message);
            assert_eq!(err.to_string(), "--check-config does not accept --grace-ms");
        }
        let cli = parse_ok(["tino", "echo", "--check-config", "--grace-ms=500"]);
        assert_eq!(cli.cmd, ["echo", "--check-config", "--grace-ms=500"]);
    }

    #[test]
    fn parse_rejects_conflicting_control_options() {
        for (args, expected) in [
            (
                ["--check-config", "--verbose"],
                "--check-config does not accept --verbose",
            ),
            (
                ["--explain", "--print-config"],
                "--print-config cannot be used with --explain",
            ),
            (
                ["--write-config", "service"],
                "--write-config does not accept CMD",
            ),
        ] {
            let err = Cli::try_parse_from(["tino", args[0], args[1]]).unwrap_err();
            assert_eq!(err.kind(), CliParseErrorKind::Message);
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn parse_rejects_empty_argv() {
        let err = Cli::try_parse_from(Vec::<OsString>::new()).unwrap_err();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert_eq!(err.to_string(), "missing argv[0]");
    }

    #[test]
    fn parse_supports_short_and_long_flag_spellings() {
        let cases: &[FlagCase<'_>] = &[
            (&["tino", "-s"], |cli| cli.subreaper),
            (&["tino", "--subreaper"], |cli| cli.subreaper),
            (&["tino", "-w"], |cli| cli.warn_on_reap),
            (&["tino", "--warn-on-reap"], |cli| cli.warn_on_reap),
            (&["tino", "-g"], |cli| cli.pgroup_kill),
            (&["tino", "--pgroup-kill"], |cli| cli.pgroup_kill),
            (&["tino", "--write-restrict"], |cli| cli.write_restrict),
            (&["tino", "--restrict-warn-only"], |cli| {
                cli.restrict_warn_only
            }),
            (&["tino", "--write-no-dev"], |cli| cli.write_no_dev),
            (&["tino", "--scope-signals"], |cli| cli.scope_signals),
            (&["tino", "--scope-abstract-unix"], |cli| {
                cli.scope_abstract_unix
            }),
            (&["tino", "--expand-env"], |cli| cli.expand_env),
            (&["tino", "--explain"], |cli| cli.explain),
            (&["tino", "--print-config"], |cli| cli.print_config),
            (&["tino", "--write-config"], |cli| cli.write_config),
            (&["tino", "--check-config"], |cli| cli.check_config),
            (&["tino", "--no-config"], |cli| cli.no_config),
        ];

        for (args, predicate) in cases {
            let cli = parse_ok(*args);
            assert!(predicate(&cli), "flag did not parse as expected: {args:?}");
        }
    }

    #[test]
    fn parse_supports_value_option_spellings() {
        let cases: &[FlagCase<'_>] = &[
            (&["tino", "-p", "TERM"], |cli| {
                cli.pdeath.as_deref() == Some("SIGTERM")
            }),
            (&["tino", "-pTERM"], |cli| {
                cli.pdeath.as_deref() == Some("SIGTERM")
            }),
            (&["tino", "--parent-death-signal", "TERM"], |cli| {
                cli.pdeath.as_deref() == Some("SIGTERM")
            }),
            (&["tino", "--parent-death-signal=TERM"], |cli| {
                cli.pdeath.as_deref() == Some("SIGTERM")
            }),
            (&["tino", "-e", "3"], |cli| cli.remap_exit == vec![3]),
            (&["tino", "--remap-exit", "3"], |cli| {
                cli.remap_exit == vec![3]
            }),
            (&["tino", "--remap-exit=3"], |cli| cli.remap_exit == vec![3]),
            (&["tino", "-t", "250"], |cli| cli.grace_ms == Some(250)),
            (&["tino", "-t250"], |cli| cli.grace_ms == Some(250)),
            (&["tino", "--grace-ms", "250"], |cli| {
                cli.grace_ms == Some(250)
            }),
            (&["tino", "--grace-ms=250"], |cli| cli.grace_ms == Some(250)),
            (&["tino", "--write-allow", "/tmp"], |cli| {
                cli.write_allow == vec!["/tmp"]
            }),
            (&["tino", "--write-allow=/tmp"], |cli| {
                cli.write_allow == vec!["/tmp"]
            }),
            (&["tino", "--write-preset", "tmp"], |cli| {
                cli.write_preset == vec![WritePreset::Tmp]
            }),
            (&["tino", "--write-preset=runtime"], |cli| {
                cli.write_preset == vec![WritePreset::Runtime]
            }),
            (&["tino", "--bind-tcp-allow", "80"], |cli| {
                cli.bind_tcp_allow == vec![80]
            }),
            (&["tino", "--bind-tcp-allow=80"], |cli| {
                cli.bind_tcp_allow == vec![80]
            }),
            (&["tino", "--connect-tcp-allow", "443"], |cli| {
                cli.connect_tcp_allow == vec![443]
            }),
            (&["tino", "--connect-tcp-allow=443"], |cli| {
                cli.connect_tcp_allow == vec![443]
            }),
            (&["tino", "--exec-allow", "/bin/sh"], |cli| {
                cli.exec_allow == vec!["/bin/sh"]
            }),
            (&["tino", "--exec-allow=/bin/sh"], |cli| {
                cli.exec_allow == vec!["/bin/sh"]
            }),
            (&["tino", "--device-ioctl-allow", "/dev/null"], |cli| {
                cli.device_ioctl_allow == vec!["/dev/null"]
            }),
            (&["tino", "--device-ioctl-allow=/dev/null"], |cli| {
                cli.device_ioctl_allow == vec!["/dev/null"]
            }),
        ];

        for (args, predicate) in cases {
            let cli = parse_ok(*args);
            assert!(
                predicate(&cli),
                "value option did not parse as expected: {args:?}"
            );
        }
    }

    #[test]
    fn parse_collects_repeatable_values_in_order() {
        let cli = parse_ok([
            "tino",
            "-e",
            "3",
            "--remap-exit=7",
            "--write-allow=/tmp",
            "--write-allow",
            "/run",
            "--bind-tcp-allow=80",
            "--bind-tcp-allow",
            "443",
            "--connect-tcp-allow=8080",
            "--connect-tcp-allow",
            "8443",
            "--exec-allow=/bin/sh",
            "--exec-allow",
            "/usr/bin/env",
            "--device-ioctl-allow=/dev/null",
            "--device-ioctl-allow",
            "/dev/pts",
        ]);

        assert_eq!(cli.remap_exit, vec![3, 7]);
        assert_eq!(cli.write_allow, vec!["/tmp", "/run"]);
        assert_eq!(cli.bind_tcp_allow, vec![80, 443]);
        assert_eq!(cli.connect_tcp_allow, vec![8080, 8443]);
        assert_eq!(cli.exec_allow, vec!["/bin/sh", "/usr/bin/env"]);
        assert_eq!(cli.device_ioctl_allow, vec!["/dev/null", "/dev/pts"]);
    }

    #[test]
    fn parse_accumulates_repeated_verbosity_flags() {
        let cases: &[(&[&str], u8)] = &[
            (&["tino", "-vvv"], 3),
            (&["tino", "-v", "-v"], 2),
            (&["tino", "--verbose"], 1),
            (&["tino", "--verbose", "--verbose"], 2),
            (&["tino", "--verbose", "-vv"], 3),
        ];

        for (args, expected) in cases {
            let cli = parse_ok(*args);
            assert_eq!(
                cli.verbosity, *expected,
                "unexpected verbosity for {args:?}"
            );
        }
    }

    #[test]
    fn parse_supports_short_long_attached_and_repeatable_options() {
        let args = [
            "tino",
            "-svgw",
            "-pTERM",
            "-e",
            "3",
            "--remap-exit=7",
            "-t250",
            "--write-restrict",
            "--write-allow",
            "/tmp",
            "--write-preset=runtime",
            "--restrict-warn-only",
            "--write-no-dev",
            "--bind-tcp-allow",
            "80",
            "--bind-tcp-allow=443",
            "--connect-tcp-allow",
            "8080",
            "--scope-signals",
            "--scope-abstract-unix",
            "--exec-allow",
            "/bin/sh",
            "--device-ioctl-allow",
            "/dev/null",
            "--expand-env",
            "--explain",
            "--",
            "/bin/echo",
            "hello",
        ];
        for cli in [
            parse_ok(args),
            Cli::try_parse_with_config_from(args, || Ok(Cli::default())).unwrap(),
        ] {
            assert!(cli.subreaper);
            assert_eq!(cli.pdeath.as_deref(), Some("SIGTERM"));
            assert_eq!(cli.verbosity, 1);
            assert!(cli.warn_on_reap);
            assert!(cli.pgroup_kill);
            assert_eq!(cli.remap_exit, vec![3, 7]);
            assert_eq!(cli.grace_ms, Some(250));
            assert!(cli.write_restrict);
            assert_eq!(cli.write_allow, vec!["/tmp"]);
            assert_eq!(cli.write_preset, vec![WritePreset::Runtime]);
            assert!(cli.restrict_warn_only);
            assert!(cli.write_no_dev);
            assert_eq!(cli.bind_tcp_allow, vec![80, 443]);
            assert_eq!(cli.connect_tcp_allow, vec![8080]);
            assert!(cli.scope_signals);
            assert!(cli.scope_abstract_unix);
            assert_eq!(cli.exec_allow, vec!["/bin/sh"]);
            assert_eq!(cli.device_ioctl_allow, vec!["/dev/null"]);
            assert!(cli.expand_env);
            assert!(cli.explain);
            assert!(!cli.print_config);
            assert!(!cli.write_config);
            assert!(!cli.check_config);
            assert!(!cli.no_config);
            assert_eq!(cli.cmd, vec!["/bin/echo", "hello"]);
        }
    }

    #[test]
    fn config_reads_a_long_utf8_comment_before_an_unterminated_option() {
        let content = format!("#{}界\r\nsubreaper", "x".repeat(8190));
        let cli = parse_config_content(Path::new("tino.conf"), &content).unwrap();
        assert!(cli.subreaper);
    }

    #[test]
    fn parse_config_content_accepts_line_based_options() {
        let cli = parse_config_content(
            Path::new(DEFAULT_CONFIG_PATH),
            r#"
                # one tino option per line
                subreaper
                pgroup-kill
                parent-death-signal TERM
                verbosity 2
                remap-exit 3
                grace-ms 250
                write-restrict
                write-allow /data/logs
                write-preset runtime
                restrict-warn-only
                write-no-dev
                bind-tcp-allow 8900
                connect-tcp-allow 11800
                scope-signals
                scope-abstract-unix
                exec-allow /opt/app
                device-ioctl-allow /dev/null
                expand-env
            "#,
        )
        .expect("parse config content");

        assert!(cli.subreaper);
        assert!(cli.pgroup_kill);
        assert_eq!(cli.pdeath.as_deref(), Some("SIGTERM"));
        assert_eq!(cli.verbosity, 2);
        assert_eq!(cli.remap_exit, vec![3]);
        assert_eq!(cli.grace_ms, Some(250));
        assert!(cli.write_restrict);
        assert_eq!(cli.write_allow, vec!["/data/logs"]);
        assert_eq!(cli.write_preset, vec![WritePreset::Runtime]);
        assert!(cli.restrict_warn_only);
        assert!(cli.write_no_dev);
        assert_eq!(cli.bind_tcp_allow, vec![8900]);
        assert_eq!(cli.connect_tcp_allow, vec![11800]);
        assert!(cli.scope_signals);
        assert!(cli.scope_abstract_unix);
        assert_eq!(cli.exec_allow, vec!["/opt/app"]);
        assert_eq!(cli.device_ioctl_allow, vec!["/dev/null"]);
        assert!(cli.expand_env);
        assert!(cli.cmd.is_empty());
    }

    #[test]
    fn parse_config_content_accepts_optional_long_option_prefix() {
        let cli = parse_config_content(
            Path::new(DEFAULT_CONFIG_PATH),
            "--write-allow /data/logs\n--bind-tcp-allow 8900\n",
        )
        .expect("parse config with long option prefixes");

        assert_eq!(cli.write_allow, vec!["/data/logs"]);
        assert_eq!(cli.bind_tcp_allow, vec![8900]);
    }

    #[test]
    fn config_rejects_the_old_pdeath_key() {
        let err = parse_config_content(Path::new("tino.conf"), "pdeath TERM")
            .expect_err("pdeath must be rejected");
        assert_eq!(err.kind(), CliParseErrorKind::Config);
        assert_eq!(
            err.to_string(),
            "tino.conf:1: unknown config option 'pdeath'"
        );
    }

    #[test]
    fn config_assignment_error_shows_the_line_and_correct_syntax() {
        let path = Path::new("service.conf");
        for (line, correction) in [
            ("grace-ms=5000", "grace-ms 5000"),
            ("--write-allow=/logs/file #1", "write-allow /logs/file #1"),
        ] {
            let err = parse_config_content(path, &format!("# settings\n\n{line}\n")).unwrap_err();
            assert_eq!(err.kind(), CliParseErrorKind::Config);
            let message = err.to_string();
            assert!(message.contains("service.conf:3:"), "{message}");
            assert!(
                message.contains(&format!("use '{correction}'")),
                "{message}"
            );
        }
    }

    #[test]
    fn config_path_values_preserve_hashes_and_equals_signs() {
        let cli = parse_config_content(
            Path::new("service.conf"),
            "# a comment\nwrite-allow /logs/a=b #1\n",
        )
        .unwrap();
        assert_eq!(cli.write_allow, ["/logs/a=b #1"]);
    }

    #[test]
    fn config_reports_the_source_line_for_relative_allow_paths() {
        let path = Path::new("service.conf");
        for key in ["write-allow", "device-ioctl-allow", "exec-allow"] {
            let err = parse_config_content(path, &format!("# policy\n{key} ./service\n"))
                .expect_err("relative path must fail during configuration parsing");
            assert_eq!(err.kind(), CliParseErrorKind::Config);
            assert!(err.to_string().contains(&format!(
                "service.conf:2: config value for '{key}' must be an absolute path"
            )));
        }
        let cli = parse_config_content(path, "exec-allow sh\n").unwrap();
        assert_eq!(cli.exec_allow, ["sh"]);
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn optional_config_rejects_dangling_symlink() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "tino-dangling-config-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&dir).expect("create config fixture");
        let path = dir.join("tino.conf");
        let target = dir.join("policy.conf");
        fs::write(&target, "subreaper\n").expect("write config target");
        symlink(&target, &path).expect("create config link");

        let valid = load_config(&path, false);
        fs::remove_file(&target).expect("remove config target");
        let absent = load_config(&target, false);
        let dangling = load_config(&path, false);
        fs::remove_dir_all(&dir).expect("remove config fixture");

        assert!(valid.expect("valid config link should load").subreaper);
        assert!(absent.is_ok(), "absent optional config should use defaults");
        let error = dangling.expect_err("existing broken config entry must not disable policy");
        assert_eq!(error.kind(), CliParseErrorKind::Config);
        assert_eq!(error.error.exit_code(), 1);
        let cause = std::error::Error::source(&error)
            .and_then(|cause| cause.downcast_ref::<io::Error>())
            .expect("config readers should be able to inspect the OS error");
        assert_eq!(cause.kind(), io::ErrorKind::NotFound);
        let reason = cause.to_string();
        assert_eq!(
            error.to_string(),
            format!("read {}: {reason}", path.display())
        );
        let wrapped = Error::with_source("load configuration", error);
        assert_eq!(wrapped.exit_code(), 1);
        assert_eq!(format!("{wrapped:#}").matches(&reason).count(), 1);
    }

    #[test]
    fn parse_config_content_rejects_commands_and_control_flow() {
        let command = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "/bin/echo hello")
            .expect_err("command must not be accepted");
        assert_eq!(command.kind(), CliParseErrorKind::Config);
        assert!(command.to_string().contains("unknown config option"));

        let control = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "explain")
            .expect_err("control-flow options must not be accepted");
        assert_eq!(control.kind(), CliParseErrorKind::Config);
        assert!(
            control
                .to_string()
                .contains("only allowed on the command line")
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn config_rejects_fifo_without_waiting_for_a_writer() {
        use std::ffi::CString;
        use std::io::Write;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("tino-fifo-config-{}-{nanos}", std::process::id()));
        fs::create_dir(&dir).expect("create config fixture");
        let path = dir.join("tino.conf");
        let name = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: the NUL-terminated path belongs to this test's fresh directory.
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

        let reader_path = path.clone();
        let reader = std::thread::spawn(move || load_config(&reader_path, true));
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut supplied = false;
        while !reader.is_finished() {
            assert!(Instant::now() < deadline, "config reader did not finish");
            if !supplied {
                match fs::OpenOptions::new()
                    .write(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open(&path)
                {
                    Ok(mut writer) => {
                        // Bound the old blocking implementation: let it read a
                        // valid config and reach the rejecting assertion below.
                        // The fixed reader can close before this write occurs.
                        let _ = writer.write_all(b"subreaper\n");
                        supplied = true;
                    }
                    Err(error) if error.raw_os_error() == Some(libc::ENXIO) => {}
                    Err(error) => panic!("open FIFO writer: {error}"),
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        let result = reader.join().unwrap();
        fs::remove_dir_all(dir).expect("remove config fixture");
        let error = result.expect_err("a FIFO must not be accepted as configuration");
        assert_eq!(error.kind(), CliParseErrorKind::Config);
        assert!(error.to_string().contains("not a regular file"));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn config_rejects_character_devices() {
        let error = load_config(Path::new("/dev/null"), false)
            .expect_err("an empty character device is not an absent configuration");
        assert_eq!(error.kind(), CliParseErrorKind::Config);
        assert!(error.to_string().contains("not a regular file"));
    }

    #[test]
    fn config_reports_invalid_utf8_in_regular_files() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "tino-nonutf8-config-{}-{nanos}",
            std::process::id()
        ));
        fs::write(&path, b"subreaper\n\xff").expect("write invalid UTF-8 fixture");
        let result = load_config(&path, false);
        fs::remove_file(&path).expect("remove config fixture");
        let error = result.expect_err("non-UTF-8 configuration must fail");
        assert_eq!(error.kind(), CliParseErrorKind::Config);
        assert_eq!(error.error.exit_code(), 2);
        assert!(
            error.to_string().contains(&format!(
                "{}:2: config line is not valid UTF-8",
                path.display()
            )),
            "{error}"
        );
    }

    #[test]
    fn required_config_distinguishes_invalid_content_from_read_failure() {
        let dir = std::env::temp_dir().join(format!("tino-config-status-{}", std::process::id()));
        fs::create_dir(&dir).expect("create config fixture");
        let path = dir.join("tino.conf");
        for content in [&b"verbosity 4\n"[..], b"typo\n", b"\xff"] {
            fs::write(&path, content).expect("write invalid config");
            let err = Cli::load_required_config(&path).expect_err("invalid config must fail");
            assert_eq!(err.exit_code(), 2, "{err}");
        }
        fs::write(&path, b"subreaper\ntypo\n\xff").unwrap();
        let err = Cli::load_required_config(&path).unwrap_err();
        assert!(
            err.to_string().contains(":2: unknown config option 'typo'"),
            "{err}"
        );
        fs::remove_file(&path).expect("remove config");
        let err = Cli::load_required_config(&path).expect_err("missing required config must fail");
        fs::remove_dir(dir).expect("remove config fixture");
        assert_eq!(err.exit_code(), 1, "{err}");
        assert_eq!(
            err.source()
                .and_then(|source| source.downcast_ref::<io::Error>())
                .map(io::Error::kind),
            Some(io::ErrorKind::NotFound)
        );
    }

    #[test]
    fn parse_config_content_rejects_unknown_option_without_raw_control_bytes() {
        let err = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "\u{1b}[31m true")
            .expect_err("unknown config option must fail");
        let message = err.to_string();

        assert_eq!(err.kind(), CliParseErrorKind::Config);
        assert!(message.contains("unknown config option"));
        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn parse_config_content_rejects_unrepresentable_values_early() {
        for (config, expected) in [
            ("write-allow /tmp\0x\n", "cannot contain NUL bytes"),
            ("exec-allow /bin/sh\rx\n", "cannot contain newlines"),
        ] {
            let err = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), config)
                .expect_err("unrepresentable config value must fail");

            assert_eq!(err.kind(), CliParseErrorKind::Config);
            assert!(
                err.to_string().contains(expected),
                "unexpected config value error for {config:?}: {err}"
            );
        }
    }

    #[test]
    fn parse_config_content_rejects_verbosity_above_effective_max() {
        let err = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "verbosity 4\n")
            .expect_err("unsupported config verbosity must fail");

        assert_eq!(err.kind(), CliParseErrorKind::Config);
        assert!(
            err.to_string().contains("expected 0-3"),
            "unexpected verbosity range error: {err}"
        );
    }

    #[test]
    fn grace_config_preserves_explicit_timeouts() {
        for (args, expected) in [
            (&["tino"][..], ""),
            (&["tino", "-t0"], "grace-ms 0\n"),
            (&["tino", "--grace-ms=500"], "grace-ms 500\n"),
        ] {
            let cli = parse_ok(args.iter().copied());
            let text = cli.config_text().unwrap();
            assert_eq!(text, expected);
            let config = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), &text).unwrap();
            assert_eq!(config.grace_ms, cli.grace_ms);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stop_signal_config_round_trips_and_cli_takes_precedence() {
        for (args, expected) in [
            (&["tino"][..], "stop-signal SIGUSR1\n"),
            (&["tino", "--stop-signal=hup"][..], "stop-signal SIGHUP\n"),
        ] {
            let cli = Cli::try_parse_with_config_from(args.iter().copied(), || {
                parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "stop-signal usr1\n")
            })
            .unwrap();
            assert_eq!(cli.config_text().unwrap(), expected);
            let parsed = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), expected).unwrap();
            assert_eq!(parsed.config_text().unwrap(), expected);
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stop_signal_rejects_unforwardable_and_invalid_values() {
        for value in [
            "KILL", "STOP", "CHLD", "TTOU", "TTIN", "SEGV", "0", "999", "USR3",
        ] {
            let error = Cli::try_parse_from(["tino", "--stop-signal", value]).unwrap_err();
            assert!(
                error.to_string().contains("stop signal"),
                "{value}: {error}"
            );
            let config = format!("stop-signal {value}\n");
            assert!(parse_config_content(Path::new(DEFAULT_CONFIG_PATH), &config).is_err());
        }
    }

    #[test]
    fn config_text_serializes_active_options() {
        let cli = parse_ok([
            "tino",
            "-s",
            "-g",
            "-p",
            "TERM",
            "-v",
            "-e",
            "3",
            "--grace-ms",
            "250",
            "--write-restrict",
            "--write-allow",
            "/data/logs",
            "--write-preset",
            "runtime",
            "--restrict-warn-only",
            "--write-no-dev",
            "--bind-tcp-allow",
            "8900",
            "--connect-tcp-allow",
            "11800",
            "--scope-signals",
            "--scope-abstract-unix",
            "--exec-allow",
            "/opt/app/service",
            "--device-ioctl-allow",
            "/dev/null",
            "--expand-env",
        ]);

        assert_eq!(
            cli.config_text().expect("serialize config text"),
            concat!(
                "subreaper\n",
                "parent-death-signal SIGTERM\n",
                "verbosity 1\n",
                "pgroup-kill\n",
                "remap-exit 3\n",
                "grace-ms 250\n",
                "write-restrict\n",
                "write-allow /data/logs\n",
                "write-preset runtime\n",
                "restrict-warn-only\n",
                "write-no-dev\n",
                "bind-tcp-allow 8900\n",
                "connect-tcp-allow 11800\n",
                "scope-signals\n",
                "scope-abstract-unix\n",
                "exec-allow /opt/app/service\n",
                "device-ioctl-allow /dev/null\n",
                "expand-env\n",
            )
        );
    }

    #[test]
    fn config_text_serializes_effective_verbosity() {
        let cli = parse_ok(["tino", "-vvvv"]);

        assert_eq!(
            cli.config_text().expect("serialize capped verbosity"),
            "verbosity 3\n"
        );
    }

    #[test]
    fn config_text_rejects_multiline_values() {
        let cli = parse_ok(["tino", "--write-allow", "/tmp\nexec-allow /bin/sh"]);

        let err = cli.config_text().expect_err("multiline value must fail");
        assert!(
            err.to_string().contains("cannot contain newlines"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn config_text_rejects_non_roundtrippable_values() {
        for value in ["", "  ", " /tmp", "/tmp ", "/tmp\0x"] {
            let cli = parse_ok(["tino", "--write-allow", value]);
            let err = cli
                .config_text()
                .expect_err("non-roundtrippable config value must fail");
            assert!(
                err.to_string().contains("cannot"),
                "unexpected error for {value:?}: {err}"
            );
        }
    }

    #[test]
    fn config_text_rejects_relative_landlock_paths() {
        let cases = [
            Cli {
                write_allow: vec!["logs".into()],
                ..Cli::default()
            },
            Cli {
                exec_allow: vec!["./service".into()],
                ..Cli::default()
            },
            Cli {
                device_ioctl_allow: vec!["dev/null".into()],
                ..Cli::default()
            },
        ];

        for cli in cases {
            let err = cli
                .config_text()
                .expect_err("relative landlock path must not serialize");
            assert!(
                err.to_string().contains("absolute path"),
                "unexpected relative-path serialization error: {err}"
            );
        }
    }

    #[test]
    fn config_text_allows_exec_command_names() {
        let cli = Cli {
            exec_allow: vec!["sh".into()],
            ..Cli::default()
        };

        assert_eq!(
            cli.config_text().expect("serialize exec command name"),
            "exec-allow sh\n"
        );
    }

    #[test]
    fn config_text_rejects_manual_values_that_would_not_parse_back() {
        let invalid_signal = Cli {
            pdeath: Some("\u{1b}[31m".into()),
            ..Cli::default()
        };
        let err = invalid_signal
            .config_text()
            .expect_err("invalid manual pdeath signal must fail");
        let message = err.to_string();
        assert!(message.contains("invalid signal"));
        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));

        for cli in [
            Cli {
                bind_tcp_allow: vec![0],
                ..Cli::default()
            },
            Cli {
                connect_tcp_allow: vec![0],
                ..Cli::default()
            },
        ] {
            let err = cli
                .config_text()
                .expect_err("zero TCP port must not be serialized");
            assert!(
                err.to_string().contains("expected 1-65535"),
                "unexpected zero-port serialization error: {err}"
            );
        }
    }

    #[test]
    fn cli_args_apply_on_top_of_config_content() {
        let base = parse_config_content(
            Path::new(DEFAULT_CONFIG_PATH),
            "expand-env\nwrite-allow /data/logs\nwrite-preset tmp\nremap-exit 7\n\
             bind-tcp-allow 8900\nconnect-tcp-allow 443\nexec-allow /bin/sh\n\
             device-ioctl-allow /dev/null\nparent-death-signal TERM\nverbosity 1\ngrace-ms 100\n",
        )
        .expect("parse config content");
        let cli = Cli::try_parse_with_config_from(
            [
                "tino",
                "--write-allow",
                "/tmp",
                "--write-preset=runtime",
                "--remap-exit=9",
                "--bind-tcp-allow",
                "9090",
                "--connect-tcp-allow=8443",
                "--exec-allow=/usr/bin/env",
                "--device-ioctl-allow=/dev/pts",
                "--parent-death-signal=USR1",
                "--verbose",
                "--grace-ms=250",
                "--",
                "/bin/echo",
                "${MESSAGE:-ok}",
            ],
            || Ok(base),
        )
        .expect("parse args over config");

        assert!(cli.expand_env);
        assert_eq!(cli.write_allow, vec!["/data/logs", "/tmp"]);
        assert_eq!(
            cli.write_preset,
            vec![WritePreset::Tmp, WritePreset::Runtime]
        );
        assert_eq!(cli.remap_exit, vec![7, 9]);
        assert_eq!(cli.bind_tcp_allow, vec![8900, 9090]);
        assert_eq!(cli.connect_tcp_allow, vec![443, 8443]);
        assert_eq!(cli.exec_allow, vec!["/bin/sh", "/usr/bin/env"]);
        assert_eq!(cli.device_ioctl_allow, vec!["/dev/null", "/dev/pts"]);
        assert_eq!(cli.pdeath.as_deref(), Some("SIGUSR1"));
        assert_eq!(cli.verbosity, 2);
        assert_eq!(cli.grace_ms, Some(250));
        assert_eq!(cli.cmd, vec!["/bin/echo", "${MESSAGE:-ok}"]);
    }

    #[test]
    fn cli_omitted_settings_inherit_config() {
        let base = parse_config_content(
            Path::new(DEFAULT_CONFIG_PATH),
            "subreaper\nparent-death-signal TERM\nverbosity 2\nwarn-on-reap\npgroup-kill\n\
             remap-exit 7\ngrace-ms 1250\nwrite-restrict\nwrite-allow /data\nwrite-preset runtime\n\
             restrict-warn-only\nwrite-no-dev\nbind-tcp-allow 8900\nconnect-tcp-allow 443\n\
             scope-signals\nscope-abstract-unix\nexec-allow /bin/sh\ndevice-ioctl-allow /dev/null\n\
             expand-env\n",
        )
        .unwrap();
        let expected = base.config_text().unwrap();
        let cli = Cli::try_parse_with_config_from(
            ["tino", "echo", "--no-config", "--help", "--grace-ms=500"],
            || Ok(base),
        )
        .unwrap();

        assert_eq!(cli.config_text().unwrap(), expected);
        assert_eq!(cli.cmd, ["echo", "--no-config", "--help", "--grace-ms=500"]);
    }

    #[test]
    fn cli_explicit_grace_overrides_config() {
        for (options, expected) in [
            (vec![], 1250),
            (vec!["--grace-ms", "500"], 500),
            (vec!["-t0"], 0),
            (vec!["-t", "0", "--grace-ms=500"], 500),
        ] {
            let args = ["tino"].into_iter().chain(options).chain(["echo"]);
            let cli = Cli::try_parse_with_config_from(args, || {
                parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "grace-ms 1250\n")
            })
            .unwrap();
            assert_eq!(cli.grace_ms, Some(expected));
        }
    }

    #[test]
    fn cli_control_requests_bypass_invalid_config() {
        let invalid_config =
            || parse_config_content(Path::new(DEFAULT_CONFIG_PATH), "unknown-option\n");
        for args in [
            vec!["tino", "--no-config", "echo"],
            vec!["tino", "--print-config"],
            vec!["tino", "--write-config"],
            vec!["tino", "--check-config"],
        ] {
            Cli::try_parse_with_config_from(args, invalid_config).unwrap();
        }
        for (option, kind) in [
            ("--help", CliParseErrorKind::Help),
            ("--version", CliParseErrorKind::Version),
            ("--unknown", CliParseErrorKind::Message),
        ] {
            let error =
                Cli::try_parse_with_config_from(["tino", option], invalid_config).unwrap_err();
            assert_eq!(error.kind(), kind);
        }
        for args in [
            vec!["tino", "echo", "--no-config"],
            vec!["tino", "--exec-allow", "--no-config", "echo"],
            vec!["tino", "--explain", "echo"],
        ] {
            let error = Cli::try_parse_with_config_from(args, invalid_config).unwrap_err();
            assert_eq!(error.kind(), CliParseErrorKind::Config);
        }
    }

    #[test]
    fn parse_first_positional_collects_remaining_command() {
        let cli = parse_ok(["tino", "--expand-env", "/bin/echo", "--literal-flag"]);

        assert!(cli.expand_env);
        assert_eq!(cli.cmd, vec!["/bin/echo", "--literal-flag"]);
    }

    #[test]
    fn parse_rejects_unknown_argument() {
        let err = Cli::try_parse_from(["tino", "--nope"]).unwrap_err();
        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(err.to_string().contains("unexpected argument"));
    }

    #[test]
    fn parse_rejects_unknown_argument_without_raw_control_bytes() {
        let err = Cli::try_parse_from(["tino", "--\u{1b}[31m"]).unwrap_err();
        let message = err.to_string();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(message.contains("unexpected argument"));
        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn parse_rejects_missing_option_value() {
        let cases = [
            ["tino", "-p"],
            ["tino", "--parent-death-signal"],
            ["tino", "-e"],
            ["tino", "-t"],
            ["tino", "--grace-ms"],
            ["tino", "--stop-signal"],
            ["tino", "--write-allow"],
            ["tino", "--write-preset"],
            ["tino", "--bind-tcp-allow"],
            ["tino", "--connect-tcp-allow"],
            ["tino", "--exec-allow"],
            ["tino", "--device-ioctl-allow"],
        ];

        for args in cases {
            let err = Cli::try_parse_from(args).unwrap_err();
            assert_eq!(err.kind(), CliParseErrorKind::Message);
            assert_eq!(
                err.to_string(),
                format!("missing value for argument: {}", args[1])
            );
        }
    }

    #[test]
    fn invalid_numeric_values_identify_their_option() {
        for option in [
            "--grace-ms",
            "--remap-exit",
            "--bind-tcp-allow",
            "--connect-tcp-allow",
        ] {
            let err = Cli::try_parse_from(["tino", option, "abc"]).unwrap_err();
            assert_eq!(err.to_string(), format!("{option}: invalid value: abc"));
        }
    }

    #[test]
    fn parse_rejects_invalid_numeric_value() {
        let cases = [
            ["tino", "-e", "256"],
            ["tino", "--bind-tcp-allow", "0"],
            ["tino", "--bind-tcp-allow", "70000"],
            ["tino", "--connect-tcp-allow", "0"],
            ["tino", "--connect-tcp-allow", "70000"],
            ["tino", "--grace-ms", "abc"],
        ];

        for args in cases {
            let err = Cli::try_parse_from(args).unwrap_err();
            assert_eq!(err.kind(), CliParseErrorKind::Message);
            assert!(
                err.to_string().contains("invalid value")
                    || err.to_string().contains("invalid digit")
                    || err.to_string().contains("number too large"),
                "unexpected numeric parse error for {args:?}: {err}"
            );
        }
    }

    #[test]
    fn parse_rejects_invalid_numeric_value_without_raw_control_bytes() {
        let err = Cli::try_parse_from(["tino", "--grace-ms", "\u{1b}[31m"]).unwrap_err();
        let message = err.to_string();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(message.contains("invalid value"));
        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn parse_config_content_rejects_zero_tcp_ports() {
        for config in ["bind-tcp-allow 0\n", "connect-tcp-allow 0\n"] {
            let err = parse_config_content(Path::new(DEFAULT_CONFIG_PATH), config)
                .expect_err("zero tcp port must fail");
            assert_eq!(err.kind(), CliParseErrorKind::Config);
            assert!(
                err.to_string().contains("expected 1-65535"),
                "unexpected port range error for {config:?}: {err}"
            );
        }
    }

    #[test]
    fn parse_rejects_invalid_write_preset() {
        let err = Cli::try_parse_from(["tino", "--write-preset", "logs"]).unwrap_err();
        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(err.to_string().contains("invalid value for --write-preset"));
    }

    #[test]
    fn parse_rejects_invalid_write_preset_without_raw_control_bytes() {
        let err = Cli::try_parse_from(["tino", "--write-preset", "\u{1b}[31m"]).unwrap_err();
        let message = err.to_string();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(message.contains("invalid value for --write-preset"));
        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn parse_preserves_invalid_option_bytes_in_diagnostics() {
        for option in [
            "--parent-death-signal",
            "--stop-signal",
            "--write-allow",
            "--grace-ms",
        ] {
            let err = Cli::try_parse_from([
                OsString::from("tino"),
                OsString::from(option),
                OsString::from_vec(vec![0xff, 0x1b]),
            ])
            .unwrap_err();
            assert_eq!(
                err.to_string(),
                format!(r"{option}: argument is not valid UTF-8: \xff\x1b")
            );
        }

        let err = Cli::try_parse_from([
            OsString::from("tino"),
            OsString::from_vec(b"--bad\xff=value".to_vec()),
        ])
        .unwrap_err();
        assert_eq!(
            err.to_string(),
            r"option name is invalid or not valid UTF-8: --bad\xff"
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn parse_rejects_non_utf8_command_arguments() {
        let err = Cli::try_parse_from([
            OsString::from("tino"),
            OsString::from("--"),
            OsString::from_vec(vec![0xff, 0xfe]),
        ])
        .unwrap_err();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert_eq!(err.to_string(), "child argv[0] is not valid UTF-8");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn parse_reports_invalid_child_argument_by_position_without_echoing_its_value() {
        let err = Cli::try_parse_from([
            OsString::from("tino"),
            OsString::from("--"),
            OsString::from("/bin/echo"),
            OsString::from("--token"),
            OsString::from_vec(b"private-value\x1b\xff".to_vec()),
        ])
        .unwrap_err();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert_eq!(err.to_string(), "child argv[2] is not valid UTF-8");
    }
}
