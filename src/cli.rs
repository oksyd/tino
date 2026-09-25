use crate::{
    diagnostic::{escape_os, escape_str},
    signals::{SIGNAL_NAMES, canonical_signal_name},
};
use osarg::{Arg, Parser, count_flag, set_flag, standard};
use std::cell::Cell;
use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::{self, Write};
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
    "  -t, --grace-ms MS              Delay before SIGKILL (default: 500 ms)\n",
    "  -e, --remap-exit CODE          Treat child exit CODE as success\n",
    "  -v, --verbose                  Increase logging (-v: INFO, -vv: DEBUG)\n",
    "      --expand-env               Expand environment variables in CMD/ARGS\n",
    "  -h, --help                     Show help\n",
    "  -V, --version                  Show version\n\n",
    "Landlock (Linux):\n",
    "      --write-restrict           Restrict child filesystem writes\n",
    "      --write-allow PATH         Allow writes to PATH; enables restriction\n",
    "      --write-preset PRESET      Allow tmp/runtime writes; enables restriction\n",
    "      --write-no-dev             Do not automatically allow /dev writes\n",
    "      --bind-tcp-allow PORT      Allow TCP binding only on selected ports\n",
    "      --connect-tcp-allow PORT   Allow TCP connections only to selected ports\n",
    "      --scope-signals            Limit signals to the same Landlock domain\n",
    "      --scope-abstract-unix      Limit abstract sockets to the same domain\n",
    "      --exec-allow PATH|CMD      Allow executing PATH or PATH-resolved CMD\n",
    "      --device-ioctl-allow PATH  Allow device ioctl beneath absolute PATH\n",
    "      --restrict-warn-only       Warn and continue when access restriction fails\n\n",
    "Config (/etc/tino/tino.conf):\n",
    "      --explain                  Show effective settings without running CMD\n",
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
    message: String,
}

impl CliParseError {
    fn message(message: String) -> Self {
        std::hint::cold_path();
        Self {
            kind: CliParseErrorKind::Message,
            message,
        }
    }

    fn config(message: String) -> Self {
        std::hint::cold_path();
        Self {
            kind: CliParseErrorKind::Config,
            message,
        }
    }

    fn help() -> Self {
        Self {
            kind: CliParseErrorKind::Help,
            message: format!("{USAGE}\n\n{HELP_TEXT}"),
        }
    }

    fn version() -> Self {
        Self {
            kind: CliParseErrorKind::Version,
            message: VERSION_TEXT.to_string(),
        }
    }

    /// Returns the parsing error category.
    #[must_use]
    pub const fn kind(&self) -> CliParseErrorKind {
        self.kind
    }

    fn print_and_exit(&self) -> ! {
        match self.kind {
            CliParseErrorKind::Help | CliParseErrorKind::Version => {
                let mut stdout = io::stdout().lock();
                let _ = stdout.write_all(self.message.as_bytes());
                let _ = stdout.flush();
                std::process::exit(0);
            }
            CliParseErrorKind::Config => {
                std::hint::cold_path();
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {}", self.message);
                let _ = stderr.flush();
                std::process::exit(2);
            }
            CliParseErrorKind::Message => {
                std::hint::cold_path();
                let mut stderr = io::stderr().lock();
                let _ = writeln!(stderr, "error: {}", self.message);
                let _ = writeln!(stderr);
                let _ = writeln!(stderr, "{USAGE}\nTry 'tino --help' for more information.");
                let _ = stderr.flush();
                std::process::exit(2);
            }
        }
    }
}

impl fmt::Display for CliParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliParseError {}

/// Parsed `tino` command-line configuration.
///
/// This struct mirrors the binary CLI and is the primary configuration type
/// accepted by [`crate::run`]. Most callers should construct it via
/// [`Cli::parse`], [`Cli::parse_from`], or [`Cli::try_parse_from`].
#[derive(Debug)]
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
    /// Remap these child exit codes to success (repeatable).
    pub remap_exit: Vec<u8>,
    /// Grace period in milliseconds before escalating SIGTERM/SIGINT/SIGQUIT to SIGKILL.
    pub grace_ms: u64,
    /// Restrict child filesystem writes to explicitly allowed directories (Linux only).
    pub write_restrict: bool,
    /// Allow writes beneath this path and enable write restriction (repeatable).
    pub write_allow: Vec<String>,
    /// Add a conservative writable directory preset and enable write restriction.
    pub write_preset: Vec<WritePreset>,
    /// Continue even if requested Landlock restrictions cannot be applied (warn and continue).
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

impl Cli {
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
    pub fn try_parse_from<I, T>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        Self::try_parse_from_base(args, Self::default())
    }

    /// Tries to parse process-like arguments and merge the fixed config file.
    ///
    /// The config file is read first and the provided CLI arguments are applied
    /// afterward. Passing `--no-config`, `--print-config`,
    /// `--write-config`, or `--check-config` skips config-file loading.
    /// Standard `--help` and `--version` requests exit during CLI-only parsing.
    pub fn try_parse_with_default_config_from<I, T>(args: I) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let argv = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let cli_only = Self::try_parse_from(argv.clone())?;
        if cli_only.no_config
            || cli_only.print_config
            || cli_only.write_config
            || cli_only.check_config
        {
            return Ok(cli_only);
        }
        let base = load_default_config()?;
        Self::try_parse_from_base(argv, base)
    }

    fn try_parse_from_base<I, T>(args: I, mut cli: Cli) -> Result<Self, CliParseError>
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString>,
    {
        let mut argv = args.into_iter().map(Into::into);
        if argv.next().is_none() {
            return Err(CliParseError::message("missing argv[0]".to_owned()));
        }
        // osarg separates --name=value into a name and an optional value, then
        // discards an unread value on next(). Track the raw token so flags can
        // reject attached values without consuming the following command.
        let attached_long_value = Cell::new(false);
        let mut parser = Parser::new(argv.inspect(|raw| {
            let bytes = raw.as_encoded_bytes();
            attached_long_value.set(bytes.starts_with(b"--") && bytes.contains(&b'='));
        }));
        let mut grace_ms_supplied = false;

        while let Some(arg) = parser.next().map_err(from_osarg_error)? {
            if let Some(flag) = standard::classify(arg) {
                reject_attached_flag_value(arg, attached_long_value.get())?;
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
                reject_attached_flag_value(arg, attached_long_value.get())?;
                set_flag(slot);
                continue;
            }

            match arg {
                Arg::Short('p') | Arg::Long("parent-death-signal") => {
                    let raw = parser.value().map_err(from_osarg_error)?;
                    cli.pdeath = Some(parse_signal(raw.to_str().map_err(from_osarg_error)?)?);
                }
                Arg::Short('v') | Arg::Long("verbose") => {
                    reject_attached_flag_value(arg, attached_long_value.get())?;
                    count_flag(&mut cli.verbosity);
                }
                Arg::Short('e') | Arg::Long("remap-exit") => {
                    *cli.remap_exit.push_mut(0) = parser.parse::<u8>().map_err(from_osarg_error)?;
                }
                Arg::Short('t') | Arg::Long("grace-ms") => {
                    cli.grace_ms = parser.parse::<u64>().map_err(from_osarg_error)?;
                    grace_ms_supplied = true;
                }
                Arg::Long("write-allow") => {
                    *cli.write_allow.push_mut(String::new()) =
                        parse_string_value(&mut parser, "--write-allow")?;
                }
                Arg::Long("write-preset") => {
                    let preset = parse_string_value(&mut parser, "--write-preset")?;
                    *cli.write_preset.push_mut(WritePreset::Tmp) = WritePreset::parse(&preset)?;
                }
                Arg::Long("bind-tcp-allow") => {
                    *cli.bind_tcp_allow.push_mut(0) =
                        parse_port_value(&mut parser, "--bind-tcp-allow")?;
                }
                Arg::Long("connect-tcp-allow") => {
                    *cli.connect_tcp_allow.push_mut(0) =
                        parse_port_value(&mut parser, "--connect-tcp-allow")?;
                }
                Arg::Long("exec-allow") => {
                    *cli.exec_allow.push_mut(String::new()) =
                        parse_string_value(&mut parser, "--exec-allow")?;
                }
                Arg::Long("device-ioctl-allow") => {
                    *cli.device_ioctl_allow.push_mut(String::new()) =
                        parse_string_value(&mut parser, "--device-ioctl-allow")?;
                }
                Arg::Value(value) => {
                    let _ = value;
                    let (command, remaining) = parser
                        .current_value_and_remaining()
                        .map_err(from_osarg_error)?;
                    *cli.cmd.push_mut(String::new()) = os_string_into_string(command)?;
                    cli.cmd.extend(
                        remaining
                            .into_iter()
                            .map(os_string_into_string)
                            .collect::<Result<Vec<_>, _>>()?,
                    );
                    break;
                }
                other => return Err(from_osarg_error(other.unexpected())),
            }
        }

        if cli.check_config && grace_ms_supplied {
            return Err(CliParseError::message(
                "--check-config does not accept --grace-ms".into(),
            ));
        }
        Ok(cli)
    }

    pub(crate) fn resolved_verbosity(&self) -> u8 {
        self.verbosity.min(3)
    }

    pub(crate) fn load_required_default_config() -> Result<Self, CliParseError> {
        load_config(Path::new(DEFAULT_CONFIG_PATH), true)
    }

    pub(crate) fn config_text(&self) -> Result<String, CliParseError> {
        let mut out = String::new();
        push_config_flag(&mut out, self.subreaper, "subreaper");
        if let Some(signal) = &self.pdeath {
            push_config_value(&mut out, "pdeath", parse_signal(signal)?)?;
        }
        let verbosity = self.resolved_verbosity();
        if verbosity > 0 {
            push_config_value(&mut out, "verbosity", verbosity)?;
        }
        push_config_flag(&mut out, self.warn_on_reap, "warn-on-reap");
        push_config_flag(&mut out, self.pgroup_kill, "pgroup-kill");
        for code in &self.remap_exit {
            push_config_value(&mut out, "remap-exit", *code)?;
        }
        if self.grace_ms != 500 {
            push_config_value(&mut out, "grace-ms", self.grace_ms)?;
        }
        push_config_flag(&mut out, self.write_restrict, "write-restrict");
        for path in &self.write_allow {
            push_config_absolute_path(&mut out, "write-allow", path)?;
        }
        for preset in &self.write_preset {
            push_config_value(&mut out, "write-preset", preset.as_str())?;
        }
        push_config_flag(&mut out, self.restrict_warn_only, "restrict-warn-only");
        push_config_flag(&mut out, self.write_no_dev, "write-no-dev");
        for port in &self.bind_tcp_allow {
            push_config_value(
                &mut out,
                "bind-tcp-allow",
                validate_port("--bind-tcp-allow", *port)?,
            )?;
        }
        for port in &self.connect_tcp_allow {
            push_config_value(
                &mut out,
                "connect-tcp-allow",
                validate_port("--connect-tcp-allow", *port)?,
            )?;
        }
        push_config_flag(&mut out, self.scope_signals, "scope-signals");
        push_config_flag(&mut out, self.scope_abstract_unix, "scope-abstract-unix");
        for path in &self.exec_allow {
            push_config_exec_path(&mut out, "exec-allow", path)?;
        }
        for path in &self.device_ioctl_allow {
            push_config_absolute_path(&mut out, "device-ioctl-allow", path)?;
        }
        push_config_flag(&mut out, self.expand_env, "expand-env");
        Ok(out)
    }
}

fn reject_attached_flag_value(arg: Arg<'_>, attached: bool) -> Result<(), CliParseError> {
    if attached && let Arg::Long(name) = arg {
        return Err(CliParseError::message(format!(
            "--{name} does not take a value"
        )));
    }
    Ok(())
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            subreaper: false,
            pdeath: None,
            verbosity: 0,
            warn_on_reap: false,
            pgroup_kill: false,
            remap_exit: Vec::new(),
            grace_ms: 500,
            write_restrict: false,
            write_allow: Vec::new(),
            write_preset: Vec::new(),
            restrict_warn_only: false,
            write_no_dev: false,
            bind_tcp_allow: Vec::new(),
            connect_tcp_allow: Vec::new(),
            scope_signals: false,
            scope_abstract_unix: false,
            exec_allow: Vec::new(),
            device_ioctl_allow: Vec::new(),
            expand_env: false,
            explain: false,
            print_config: false,
            write_config: false,
            check_config: false,
            no_config: false,
            cmd: Vec::new(),
        }
    }
}

fn load_default_config() -> Result<Cli, CliParseError> {
    load_config(Path::new(DEFAULT_CONFIG_PATH), false)
}

fn load_config(path: &Path, required: bool) -> Result<Cli, CliParseError> {
    match fs::read_to_string(path) {
        Ok(content) => parse_config_content(path, &content),
        Err(err) if !required && err.kind() == io::ErrorKind::NotFound => Ok(Cli::default()),
        Err(err) if required && err.kind() == io::ErrorKind::NotFound => Err(
            CliParseError::config(format!("{}: file not found", path.display())),
        ),
        Err(err) => Err(CliParseError::config(format!(
            "read {}: {err}",
            path.display()
        ))),
    }
}

fn push_config_flag(out: &mut String, enabled: bool, key: &str) {
    if enabled {
        out.push_str(key);
        out.push('\n');
    }
}

fn push_config_value(
    out: &mut String,
    key: &str,
    value: impl fmt::Display,
) -> Result<(), CliParseError> {
    let value = validate_config_value(key, value.to_string())?;
    let _ = fmt::write(out, format_args!("{key} {value}\n"));
    Ok(())
}

fn validate_config_value(key: &str, value: String) -> Result<String, CliParseError> {
    if value.is_empty() || value != value.trim() {
        return Err(CliParseError::message(format!(
            "config value for '{key}' cannot be empty or have surrounding whitespace"
        )));
    }
    if value.contains(['\n', '\r']) {
        return Err(CliParseError::message(format!(
            "config value for '{key}' cannot contain newlines"
        )));
    }
    if value.contains('\0') {
        return Err(CliParseError::message(format!(
            "config value for '{key}' cannot contain NUL bytes"
        )));
    }
    Ok(value)
}

fn push_config_absolute_path(
    out: &mut String,
    key: &str,
    value: impl fmt::Display,
) -> Result<(), CliParseError> {
    let value = validate_config_value(key, value.to_string())?;
    if !Path::new(&value).is_absolute() {
        return Err(CliParseError::message(format!(
            "config value for '{key}' must be an absolute path"
        )));
    }
    let _ = fmt::write(out, format_args!("{key} {value}\n"));
    Ok(())
}

fn push_config_exec_path(
    out: &mut String,
    key: &str,
    value: impl fmt::Display,
) -> Result<(), CliParseError> {
    let value = validate_config_value(key, value.to_string())?;
    if value.contains('/') && !Path::new(&value).is_absolute() {
        return Err(CliParseError::message(format!(
            "config value for '{key}' must be an absolute path when it contains '/'"
        )));
    }
    let _ = fmt::write(out, format_args!("{key} {value}\n"));
    Ok(())
}

fn parse_config_content(path: &Path, content: &str) -> Result<Cli, CliParseError> {
    let mut cli = Cli::default();
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx + 1;
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        apply_config_line(&mut cli, path, line_no, line)?;
    }
    Ok(cli)
}

fn apply_config_line(
    cli: &mut Cli,
    path: &Path,
    line_no: usize,
    line: &str,
) -> Result<(), CliParseError> {
    let (key, value) = split_config_line(line);
    match key {
        "subreaper" => set_config_flag(&mut cli.subreaper, path, line_no, key, value),
        "pdeath" | "parent-death-signal" => {
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
            *cli.remap_exit.push_mut(0) = parse_config_value::<u8>(path, line_no, key, value)?;
            Ok(())
        }
        "grace-ms" => {
            cli.grace_ms = parse_config_value::<u64>(path, line_no, key, value)?;
            Ok(())
        }
        "write-restrict" => set_config_flag(&mut cli.write_restrict, path, line_no, key, value),
        "write-allow" => {
            *cli.write_allow.push_mut(String::new()) =
                config_value(path, line_no, key, value)?.to_owned();
            Ok(())
        }
        "write-preset" => {
            let preset = config_value(path, line_no, key, value)?;
            *cli.write_preset.push_mut(WritePreset::Tmp) = WritePreset::parse(preset)
                .map_err(|err| config_error(path, line_no, err.to_string()))?;
            Ok(())
        }
        "restrict-warn-only" => {
            set_config_flag(&mut cli.restrict_warn_only, path, line_no, key, value)
        }
        "write-no-dev" => set_config_flag(&mut cli.write_no_dev, path, line_no, key, value),
        "bind-tcp-allow" => {
            *cli.bind_tcp_allow.push_mut(0) = parse_config_port(path, line_no, key, value)?;
            Ok(())
        }
        "connect-tcp-allow" => {
            *cli.connect_tcp_allow.push_mut(0) = parse_config_port(path, line_no, key, value)?;
            Ok(())
        }
        "scope-signals" => set_config_flag(&mut cli.scope_signals, path, line_no, key, value),
        "scope-abstract-unix" => {
            set_config_flag(&mut cli.scope_abstract_unix, path, line_no, key, value)
        }
        "exec-allow" => {
            *cli.exec_allow.push_mut(String::new()) =
                config_value(path, line_no, key, value)?.to_owned();
            Ok(())
        }
        "device-ioctl-allow" => {
            *cli.device_ioctl_allow.push_mut(String::new()) =
                config_value(path, line_no, key, value)?.to_owned();
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
    }
}

fn split_config_line(line: &str) -> (&str, Option<&str>) {
    let (raw_key, value) = if let Some(idx) = line.find(char::is_whitespace) {
        let value = line[idx..].trim();
        (&line[..idx], (!value.is_empty()).then_some(value))
    } else {
        (line, None)
    };
    let key = raw_key
        .strip_prefix("--")
        .filter(|stripped| !stripped.is_empty())
        .unwrap_or(raw_key);
    (key, value)
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
    validate_parsed_config_value(path, line_no, key, value)?;
    Ok(value)
}

fn validate_parsed_config_value(
    path: &Path,
    line_no: usize,
    key: &str,
    value: &str,
) -> Result<(), CliParseError> {
    if value.contains(['\n', '\r']) {
        return Err(config_error(
            path,
            line_no,
            format!("config value for '{key}' cannot contain newlines"),
        ));
    }
    if value.contains('\0') {
        return Err(config_error(
            path,
            line_no,
            format!("config value for '{key}' cannot contain NUL bytes"),
        ));
    }
    Ok(())
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
    let verbosity = parse_config_value::<u8>(path, line_no, key, value)?;
    if verbosity > 3 {
        return Err(config_error(
            path,
            line_no,
            "invalid value for 'verbosity': expected 0-3".into(),
        ));
    }
    Ok(verbosity)
}

fn config_error(path: &Path, line_no: usize, message: String) -> CliParseError {
    CliParseError::config(format!("{}:{line_no}: {message}", path.display()))
}

fn parse_signal(raw: &str) -> Result<String, CliParseError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(CliParseError::message("signal name cannot be empty".into()));
    }
    if let Some(name) = canonical_signal_name(trimmed) {
        Ok(format!("SIG{}", name))
    } else {
        Err(CliParseError::message(format!(
            "invalid signal '{}'; supported values: {}",
            escape_str(raw),
            SIGNAL_NAMES.join(", ")
        )))
    }
}

fn parse_string_value<I>(parser: &mut Parser<I>, option: &str) -> Result<String, CliParseError>
where
    I: Iterator<Item = OsString>,
{
    parser
        .value()
        .map_err(|err| option_osarg_error(option, err))?
        .to_str()
        .map(str::to_owned)
        .map_err(from_osarg_error)
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

fn os_string_into_string(value: OsString) -> Result<String, CliParseError> {
    value.into_string().map_err(|value| {
        CliParseError::message(format!(
            "argument is not valid UTF-8: {}",
            escape_os(&value)
        ))
    })
}

fn from_osarg_error(err: osarg::Error) -> CliParseError {
    CliParseError::message(escape_str(&err.to_string()))
}

fn option_osarg_error(option: &str, err: osarg::Error) -> CliParseError {
    CliParseError::message(format!("{option}: {}", escape_str(&err.to_string())))
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
    fn parse_check_config_rejects_explicit_default_grace() {
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
            (&["tino", "-t", "250"], |cli| cli.grace_ms == 250),
            (&["tino", "-t250"], |cli| cli.grace_ms == 250),
            (&["tino", "--grace-ms", "250"], |cli| cli.grace_ms == 250),
            (&["tino", "--grace-ms=250"], |cli| cli.grace_ms == 250),
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
        let cli = parse_ok([
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
        ]);

        assert!(cli.subreaper);
        assert_eq!(cli.pdeath.as_deref(), Some("SIGTERM"));
        assert_eq!(cli.verbosity, 1);
        assert!(cli.warn_on_reap);
        assert!(cli.pgroup_kill);
        assert_eq!(cli.remap_exit, vec![3, 7]);
        assert_eq!(cli.grace_ms, 250);
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

    #[test]
    fn parse_config_content_accepts_line_based_options() {
        let cli = parse_config_content(
            Path::new(DEFAULT_CONFIG_PATH),
            r#"
                # one tino option per line
                subreaper
                pgroup-kill
                pdeath TERM
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
        assert_eq!(cli.grace_ms, 250);
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
                "pdeath SIGTERM\n",
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
            "expand-env\nwrite-allow /data/logs\nbind-tcp-allow 8900\nparent-death-signal TERM\nverbosity 1\ngrace-ms 100\n",
        )
        .expect("parse config content");
        let cli = Cli::try_parse_from_base(
            [
                "tino",
                "--write-allow",
                "/tmp",
                "--bind-tcp-allow",
                "9090",
                "--parent-death-signal=USR1",
                "--verbose",
                "--grace-ms=250",
                "--",
                "/bin/echo",
                "${MESSAGE:-ok}",
            ],
            base,
        )
        .expect("parse args over config");

        assert!(cli.expand_env);
        assert_eq!(cli.write_allow, vec!["/data/logs", "/tmp"]);
        assert_eq!(cli.bind_tcp_allow, vec![8900, 9090]);
        assert_eq!(cli.pdeath.as_deref(), Some("SIGUSR1"));
        assert_eq!(cli.verbosity, 2);
        assert_eq!(cli.grace_ms, 250);
        assert_eq!(cli.cmd, vec!["/bin/echo", "${MESSAGE:-ok}"]);
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
            assert!(
                err.to_string().contains("missing value"),
                "unexpected missing-value error for {args:?}: {err}"
            );
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
    fn parse_rejects_non_utf8_command_arguments() {
        let err = Cli::try_parse_from([
            OsString::from("tino"),
            OsString::from("--"),
            OsString::from_vec(vec![0xff, 0xfe]),
        ])
        .unwrap_err();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(err.to_string().contains("not valid UTF-8"));
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn parse_rejects_non_utf8_command_arguments_without_raw_control_bytes() {
        let err = Cli::try_parse_from([
            OsString::from("tino"),
            OsString::from("--"),
            OsString::from_vec(vec![0x1b, b'[', b'3', b'1', b'm', 0xff]),
        ])
        .unwrap_err();
        let message = err.to_string();

        assert_eq!(err.kind(), CliParseErrorKind::Message);
        assert!(message.contains("not valid UTF-8"));
        assert!(message.contains(r"\x1b"));
        assert!(!message.contains('\u{1b}'));
    }
}
