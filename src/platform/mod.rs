use crate::{
    Context, Error, Result, bail,
    cli::{Cli, ControlMode, DEFAULT_CONFIG_PATH},
    diagnostic::escape_os,
    logging,
};
use std::ffi::{OsStr, OsString};
use std::fmt::Write as FmtWrite;
use std::fs;
use std::io::{self, Write};
use std::mem::DropGuard;
use std::path::{Path, PathBuf};

cfg_select! {
    target_os = "linux" => {
        pub(crate) mod unix;
        use unix as platform_impl;
    }
    _ => {
        mod stub;
        use stub as platform_impl;
    }
}

pub fn run(mut cli: Cli) -> Result<i32> {
    match cli.control_mode().map_err(Error::usage)? {
        Some(ControlMode::CheckConfig) => {
            let config = Cli::load_required_config(Path::new(DEFAULT_CONFIG_PATH))?;
            platform_impl::validate_landlock_config(&config)?;
            write_stdout(format!("tino: config OK: {DEFAULT_CONFIG_PATH}\n").as_bytes())?;
            return Ok(0);
        }
        Some(ControlMode::WriteConfig) => {
            write_config(Path::new(DEFAULT_CONFIG_PATH), &cli)?;
            write_stdout(format!("tino: config written: {DEFAULT_CONFIG_PATH}\n").as_bytes())?;
            return Ok(0);
        }
        Some(ControlMode::PrintConfig) => {
            let config_text = validated_config_text(&cli)?;
            write_stdout(config_text.as_bytes())?;
            return Ok(0);
        }
        Some(ControlMode::Explain) | None => {}
    }

    let env_defaults = apply_env_defaults(&mut cli);
    let warn_implies_subreaper = cli.warn_on_reap && !cli.subreaper;
    if warn_implies_subreaper {
        cli.subreaper = true;
    }

    logging::with_verbosity(cli.resolved_verbosity(), || {
        if cli.explain {
            return explain(cli, &env_defaults, warn_implies_subreaper);
        }
        env_defaults.emit();
        if warn_implies_subreaper {
            logging::debug(format_args!("subreaper enabled via --warn-on-reap"));
        }

        if cli.cmd.is_empty() {
            return Err(Error::usage("missing CMD (use --help)"));
        }

        platform_impl::run_impl(cli)
    })
}

pub(crate) fn bench_resolve_command_args(cmd: &[String], expand_env: bool) -> Result<Vec<String>> {
    cfg_select! {
        target_os = "linux" => {
            platform_impl::bench_resolve_command_args(cmd, expand_env)
        }
        _ => {
            let _ = (cmd, expand_env);
            bail!("bench support is only available on Linux")
        }
    }
}

pub(crate) fn bench_parse_shebang_interpreter(bytes: &[u8]) -> Option<String> {
    cfg_select! {
        target_os = "linux" => {
            unix::bench_parse_shebang_interpreter(bytes)
        }
        _ => {
            let _ = bytes;
            None
        }
    }
}

pub(crate) fn bench_parse_elf_interpreter(bytes: &[u8]) -> Result<Option<String>> {
    cfg_select! {
        target_os = "linux" => {
            unix::bench_parse_elf_interpreter(bytes)
        }
        _ => {
            let _ = bytes;
            bail!("bench support is only available on Linux")
        }
    }
}

#[derive(Default)]
struct EnvDefaultLog {
    subreaper_env: Option<(&'static str, bool)>,
    pgroup_env: Option<(&'static str, bool)>,
    verbosity_env: Option<(&'static str, u8)>,
    warnings: Vec<String>,
}

#[derive(Default)]
struct LandlockExplain {
    write_requested: bool,
    exec_requested: bool,
    warn_only: bool,
    auto_allow_dev: bool,
    preset_names: Vec<&'static str>,
    writable_dirs: Vec<String>,
    bind_tcp_ports: Vec<u16>,
    connect_tcp_ports: Vec<u16>,
    scope_signals: bool,
    scope_abstract_unix: bool,
    exec_allow_paths: Vec<String>,
    device_ioctl_allow_paths: Vec<String>,
}

impl EnvDefaultLog {
    fn emit(&self) {
        for (setting, applied) in [
            ("subreaper", self.subreaper_env),
            ("process group kill", self.pgroup_env),
        ] {
            if let Some((name, enabled)) = applied {
                let state = if enabled { "enabled" } else { "disabled" };
                logging::debug(format_args!("{setting} {state} via {name}"));
            }
        }
        if let Some((name, level)) = self.verbosity_env {
            logging::debug(format_args!("verbosity sourced from {name}: {level}"));
        }
        for warning in &self.warnings {
            logging::warn(format_args!("{warning}"));
        }
    }
}

fn apply_env_defaults(cli: &mut Cli) -> EnvDefaultLog {
    apply_env_defaults_with(cli, std::env::var_os)
}

fn apply_env_defaults_with(
    cli: &mut Cli,
    mut lookup: impl FnMut(&'static str) -> Option<OsString>,
) -> EnvDefaultLog {
    let mut env_default = |native, tini| {
        [native, tini]
            .into_iter()
            .find_map(|name| lookup(name).map(|raw| (name, raw)))
    };
    let mut log = EnvDefaultLog::default();
    for (native, tini, flag, applied) in [
        (
            "TINO_SUBREAPER",
            "TINI_SUBREAPER",
            &mut cli.subreaper,
            &mut log.subreaper_env,
        ),
        (
            "TINO_KILL_PROCESS_GROUP",
            "TINI_KILL_PROCESS_GROUP",
            &mut cli.pgroup_kill,
            &mut log.pgroup_env,
        ),
    ] {
        if !*flag && let Some((name, raw)) = env_default(native, tini) {
            // Tini enables these switches whenever the variable exists.
            let parsed = if name == tini {
                Some(true)
            } else {
                interpret_env_flag(&raw)
            };
            match parsed {
                Some(enabled) => {
                    *flag = enabled;
                    *applied = Some((name, enabled));
                }
                None => log.warnings.push(format!(
                    "invalid boolean env default: {name}={}",
                    escape_os(&raw)
                )),
            }
        }
    }
    if cli.verbosity == 0
        && let Some((name, raw)) = env_default("TINO_VERBOSITY", "TINI_VERBOSITY")
    {
        match parse_env_verbosity(&raw) {
            Ok(parsed) => {
                cli.verbosity = parsed;
                log.verbosity_env = Some((name, parsed));
            }
            Err(error) => log
                .warnings
                .push(format!("invalid {name}={}: {error}", escape_os(&raw))),
        }
    }
    log
}

fn interpret_env_flag(raw: &OsStr) -> Option<bool> {
    let trimmed = raw.to_str()?.trim();
    if let Ok(number) = trimmed.parse::<u8>() {
        return bool::try_from(number).ok();
    }
    if trimmed.eq_ignore_ascii_case("true")
        || trimmed.eq_ignore_ascii_case("yes")
        || trimmed.eq_ignore_ascii_case("on")
    {
        return Some(true);
    }
    if trimmed.eq_ignore_ascii_case("false")
        || trimmed.eq_ignore_ascii_case("no")
        || trimmed.eq_ignore_ascii_case("off")
    {
        return Some(false);
    }
    None
}

fn parse_env_verbosity(raw: &OsStr) -> std::result::Result<u8, String> {
    let raw = raw.to_str().ok_or("not valid UTF-8")?;
    crate::cli::parse_verbosity(raw.trim())
}

fn explain(cli: Cli, env_defaults: &EnvDefaultLog, warn_implies_subreaper: bool) -> Result<i32> {
    let pdeath = explain_pdeath(&cli)?;
    let (effective_cmd, policy) = platform_impl::explain_config(&cli)?;
    let mut out = String::new();

    let mut line = |args: std::fmt::Arguments<'_>| {
        let _ = out.write_fmt(args);
        let _ = out.write_char('\n');
    };

    line(format_args!("mode: explain"));
    line(format_args!("subreaper: {}", cli.subreaper));
    let subreaper_source = if warn_implies_subreaper {
        "--warn-on-reap".into()
    } else {
        setting_source(cli.subreaper, env_defaults.subreaper_env)
    };
    line(format_args!("subreaper.source: {subreaper_source}"));
    line(format_args!("parent_death_signal: {pdeath}"));
    line(format_args!("verbosity: {}", cli.resolved_verbosity()));
    line(format_args!(
        "verbosity.source: {}",
        setting_source(cli.verbosity > 0, env_defaults.verbosity_env)
    ));
    line(format_args!("warn_on_reap: {}", cli.warn_on_reap));
    line(format_args!("pgroup_kill: {}", cli.pgroup_kill));
    line(format_args!(
        "pgroup_kill.source: {}",
        setting_source(cli.pgroup_kill, env_defaults.pgroup_env)
    ));
    match cli.grace_ms {
        Some(ms) => line(format_args!("grace_ms: {ms}")),
        None => line(format_args!("grace_ms: external")),
    }
    if let Some(signal) = &cli.stop_signal {
        line(format_args!("additional_stop_signal: {signal}"));
    }
    line(format_args!("remap_exit: {:?}", cli.remap_exit));
    line(format_args!("expand_env: {}", cli.expand_env));
    line(format_args!("command.original: {:?}", cli.cmd));
    line(format_args!("command.effective: {effective_cmd:?}"));

    if policy.write_requested {
        line(format_args!("write_restrict.enabled: true"));
        line(format_args!("write_restrict.backend: landlock"));
        line(format_args!(
            "write_restrict.presets: {:?}",
            policy.preset_names
        ));
        line(format_args!(
            "write_restrict.warn_only: {}",
            policy.warn_only
        ));
        line(format_args!(
            "write_restrict.auto_allow_dev: {}",
            policy.auto_allow_dev
        ));
        line(format_args!(
            "write_restrict.allow_dirs: {}",
            escaped_list(&policy.writable_dirs)
        ));
    } else {
        line(format_args!("write_restrict.enabled: false"));
    }

    let enabled = !policy.bind_tcp_ports.is_empty() || !policy.connect_tcp_ports.is_empty();
    line(format_args!("tcp_restrict.enabled: {enabled}"));
    if enabled {
        line(format_args!("tcp_restrict.backend: landlock"));
        line(format_args!("tcp_restrict.warn_only: {}", policy.warn_only));
    }
    for (direction, ports) in [
        ("bind", &policy.bind_tcp_ports),
        ("connect", &policy.connect_tcp_ports),
    ] {
        let mode = if ports.is_empty() {
            "unrestricted"
        } else {
            "allowlist"
        };
        line(format_args!("tcp_restrict.{direction}_mode: {mode}"));
        if enabled {
            line(format_args!(
                "tcp_restrict.{direction}_allow_ports: {ports:?}"
            ));
        }
    }

    if policy.scope_signals || policy.scope_abstract_unix {
        line(format_args!("ipc_scope.enabled: true"));
        line(format_args!("ipc_scope.backend: landlock"));
        line(format_args!("ipc_scope.warn_only: {}", policy.warn_only));
        line(format_args!("ipc_scope.signals: {}", policy.scope_signals));
        line(format_args!(
            "ipc_scope.abstract_unix: {}",
            policy.scope_abstract_unix
        ));
    } else {
        line(format_args!("ipc_scope.enabled: false"));
    }

    if policy.exec_requested {
        line(format_args!("exec_restrict.enabled: true"));
        line(format_args!("exec_restrict.backend: landlock"));
        line(format_args!(
            "exec_restrict.warn_only: {}",
            policy.warn_only
        ));
        line(format_args!(
            "exec_restrict.allow_paths: {}",
            escaped_list(&policy.exec_allow_paths)
        ));
    } else {
        line(format_args!("exec_restrict.enabled: false"));
    }

    if !policy.device_ioctl_allow_paths.is_empty() {
        line(format_args!("device_ioctl_restrict.enabled: true"));
        line(format_args!("device_ioctl_restrict.backend: landlock"));
        line(format_args!(
            "device_ioctl_restrict.warn_only: {}",
            policy.warn_only
        ));
        line(format_args!(
            "device_ioctl_restrict.allow_paths: {}",
            escaped_list(&policy.device_ioctl_allow_paths)
        ));
    } else {
        line(format_args!("device_ioctl_restrict.enabled: false"));
    }

    if !env_defaults.warnings.is_empty() {
        line(format_args!("warnings:"));
        for warning in &env_defaults.warnings {
            line(format_args!("- {warning}"));
        }
    }

    write_stdout(out.as_bytes())?;
    Ok(0)
}

pub(crate) fn write_stdout(content: &[u8]) -> Result<()> {
    write_with_signal_protection(|| {
        let mut stdout = io::stdout().lock();
        // Flush any buffered output from a library caller before writing ours.
        stdout.flush()?;
        #[cfg(unix)]
        {
            // Rust's Stdout silently treats EBADF as a successful write.
            // Write to the original descriptor while holding the stdout lock.
            let mut remaining = content;
            while !remaining.is_empty() {
                // SAFETY: remaining is readable for the supplied length.
                let written = unsafe {
                    libc::write(
                        libc::STDOUT_FILENO,
                        remaining.as_ptr().cast(),
                        remaining.len(),
                    )
                };
                if written < 0 {
                    let error = io::Error::last_os_error();
                    if error.kind() == io::ErrorKind::Interrupted {
                        continue;
                    }
                    return Err(error);
                }
                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }
                remaining = &remaining[written.cast_unsigned()..];
            }
            Ok(())
        }
        #[cfg(not(unix))]
        {
            stdout.write_all(content)?;
            stdout.flush()
        }
    })
    .context("write stdout")
}

fn write_with_signal_protection(write: impl FnOnce() -> io::Result<()>) -> io::Result<()> {
    // Preserve the caller's signal dispositions. If a write-generated signal
    // cannot be consumed, keep only that signal blocked while returning the
    // original I/O error rather than unexpectedly delivering it to the caller.
    #[cfg(target_os = "linux")]
    let mut signals = unix::sys::DiagnosticWriteGuard::new()
        .ok_or_else(|| io::Error::other("could not protect output signal state"))?;
    let result = write();
    #[cfg(target_os = "linux")]
    if let Err(error) = &result
        && let Some(errno) = error.raw_os_error()
    {
        signals.consume_failure(errno);
    }
    result
}

fn escaped_list(values: &[String]) -> String {
    let mut out = String::from("[");
    for (idx, value) in values.iter().enumerate() {
        if idx > 0 {
            out.push_str(", ");
        }
        out.push('"');
        out.push_str(value);
        out.push('"');
    }
    out.push(']');
    out
}

fn setting_source<T>(non_default: bool, applied_env: Option<(&str, T)>) -> String {
    if let Some((name, _)) = applied_env {
        format!("env:{name}")
    } else if non_default {
        "configured".into()
    } else {
        "default".into()
    }
}

fn explain_pdeath(cli: &Cli) -> Result<&'static str> {
    cli.parent_death_signal()
        .map(|signal| signal.map_or("none", |signal| signal.name))
        .map_err(Error::usage)
}

fn validated_config_text(cli: &Cli) -> Result<String> {
    let text = cli
        .config_text()
        .map_err(|err| Error::usage(err.to_string()))?;
    platform_impl::validate_landlock_config(cli)?;
    Ok(text)
}

fn write_config(path: &Path, cli: &Cli) -> Result<()> {
    let config_text = validated_config_text(cli)?;
    let parent = path
        .parent()
        .context("config path has no parent directory")?;
    fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    write_file_atomically(path, config_text.as_bytes())
}

fn write_file_atomically(path: &Path, content: &[u8]) -> Result<()> {
    let original = existing_config_metadata(path)?;
    // Acquire the handle needed for the final sync before replacing the config.
    #[cfg(unix)]
    let parent_dir = {
        let parent = path
            .parent()
            .context("config path has no parent directory")?;
        fs::File::open(parent).with_context(|| format!("open {}", parent.display()))?
    };
    let (temp_path, mut file) = create_temp_file(path, original.is_some())?;
    let temp_path = DropGuard::new(temp_path, |path| {
        let _ = fs::remove_file(path);
    });
    write_with_signal_protection(|| file.write_all(content))
        .with_context(|| format!("write {}", temp_path.display()))?;
    if let Some(original) = original {
        preserve_config_permissions(path, &file, &original)
            .with_context(|| format!("set ownership and permissions on {}", temp_path.display()))?;
    }
    file.sync_all()
        .with_context(|| format!("sync {}", temp_path.display()))?;
    drop(file);
    fs::rename(&*temp_path, path)
        .with_context(|| format!("rename {} to {}", temp_path.display(), path.display()))?;
    DropGuard::dismiss(temp_path);
    #[cfg(unix)]
    parent_dir
        .sync_all()
        .with_context(|| format!("sync parent directory of {}", path.display()))?;
    Ok(())
}

fn existing_config_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing to replace symlink config path {}", path.display())
        }
        Ok(metadata) if !metadata.is_file() => {
            bail!("config path {} is not a regular file", path.display())
        }
        Ok(metadata) => Ok(Some(metadata)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err).with_context(|| format!("inspect {}", path.display())),
    }
}

#[cfg(target_family = "unix")]
fn preserve_config_permissions(
    _path: &Path,
    file: &fs::File,
    original: &fs::Metadata,
) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt, fchown};

    let created = file.metadata()?;
    let uid = (created.uid() != original.uid()).then(|| original.uid());
    let gid = (created.gid() != original.gid()).then(|| original.gid());
    if uid.is_some() || gid.is_some() {
        fchown(file, uid, gid)?;
    }
    #[cfg(target_os = "linux")]
    if copy_config_access_acl(_path, file)? {
        // Setting the ACL also sets the owner, group-mask and other mode bits.
        return Ok(());
    }
    file.set_permissions(fs::Permissions::from_mode(original.mode() & 0o777))
}

#[cfg(target_os = "linux")]
fn copy_config_access_acl(path: &Path, file: &fs::File) -> io::Result<bool> {
    use std::os::{fd::AsRawFd, unix::ffi::OsStrExt};

    fn acl_len(len: libc::ssize_t) -> io::Result<Option<usize>> {
        if len >= 0 {
            return Ok(Some(len.cast_unsigned()));
        }
        let err = io::Error::last_os_error();
        match err.raw_os_error() {
            Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(None),
            _ => Err(err),
        }
    }

    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    let name = c"system.posix_acl_access".as_ptr();
    // Linux limits one extended attribute to 64 KiB. Read it in one syscall.
    let mut acl = vec![0_u8; 64 * 1024];
    // SAFETY: the names are NUL-terminated and acl has the given writable length.
    let len = unsafe { libc::lgetxattr(path.as_ptr(), name, acl.as_mut_ptr().cast(), acl.len()) };
    let fd = file.as_raw_fd();
    if let Some(len) = acl_len(len)? {
        // SAFETY: the kernel initialized the first len bytes. file owns fd.
        if unsafe { libc::fsetxattr(fd, name, acl.as_ptr().cast(), len, 0) } == -1 {
            return Err(io::Error::last_os_error());
        }
        return Ok(true);
    }
    // A new inode may carry the directory's default ACL even if the old
    // config lacked one. Remove it before chmod can enable inherited entries.
    // SAFETY: file owns fd, name is NUL-terminated, and size zero only queries the length.
    let inherited = unsafe { libc::fgetxattr(fd, name, std::ptr::null_mut(), 0) };
    if acl_len(inherited)?.is_some()
        // SAFETY: file owns fd and name is NUL-terminated.
        && unsafe { libc::fremovexattr(fd, name) } == -1
    {
        return Err(io::Error::last_os_error());
    }
    Ok(false)
}

#[cfg(not(target_family = "unix"))]
fn preserve_config_permissions(
    _path: &Path,
    file: &fs::File,
    original: &fs::Metadata,
) -> io::Result<()> {
    file.set_permissions(original.permissions())
}

fn create_temp_file(path: &Path, _replacing: bool) -> Result<(PathBuf, fs::File)> {
    const MAX_TEMP_ATTEMPTS: u32 = 100;

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // Let the kernel apply the caller's umask when creating a new config.
        options.mode(if _replacing { 0o600 } else { 0o644 });
    }
    for attempt in 0..MAX_TEMP_ATTEMPTS {
        let temp_path = temp_path_for_attempt(path, attempt)?;
        match options.open(&temp_path) {
            Ok(file) => return Ok((temp_path, file)),
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(err).with_context(|| format!("create {}", temp_path.display()));
            }
        }
    }

    bail!(
        "create temporary config file for {} after {} attempts",
        path.display(),
        MAX_TEMP_ATTEMPTS
    )
}

#[cfg(test)]
fn temp_path_for(path: &Path) -> Result<PathBuf> {
    temp_path_for_attempt(path, 0)
}

fn temp_path_for_attempt(path: &Path, attempt: u32) -> Result<PathBuf> {
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .context("config path has no valid UTF-8 file name")?;
    let mut temp_path = path.to_path_buf();
    temp_path.set_file_name(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        attempt
    ));
    Ok(temp_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_boolean_env_default_is_rejected() {
        assert!(interpret_env_flag(OsStr::new("   ")).is_none());
    }

    fn base_cli() -> Cli {
        Cli {
            cmd: vec!["/bin/true".into()],
            ..Cli::default()
        }
    }

    #[test]
    fn control_modes_are_mutually_exclusive() {
        let mut cli = base_cli();
        cli.check_config = true;
        cli.write_config = true;

        let err = run(cli).expect_err("conflicting modes must fail");

        assert!(
            format!("{err}").contains("--check-config cannot be used with --write-config"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn no_config_cannot_check_config() {
        let mut cli = base_cli();
        cli.no_config = true;
        cli.check_config = true;

        let err = run(cli).expect_err("contradictory config modes must fail");

        assert!(
            format!("{err}").contains("--no-config cannot be used with --check-config"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn check_config_rejects_inline_runtime_options() {
        let cli = Cli {
            check_config: true,
            write_allow: vec!["/tmp".into()],
            ..Cli::default()
        };

        let err = run(cli).expect_err("inline config options must fail");

        assert!(
            format!("{err}").contains("--check-config does not accept --write-allow"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn print_and_explain_report_the_same_invalid_parent_death_signal_as_the_parser() {
        let invalid = "\u{1b}[31m";
        let expected = Cli::try_parse_from(["tino", "--parent-death-signal", invalid])
            .unwrap_err()
            .to_string();
        assert!(expected.contains("supported values:"));
        for explain in [false, true] {
            let cli = Cli {
                pdeath: Some(invalid.into()),
                print_config: !explain,
                explain,
                ..Cli::default()
            };
            let err = run(cli).unwrap_err();
            assert_eq!(err.exit_code(), 2);
            assert_eq!(err.to_string(), expected);
        }
    }

    #[test]
    fn explain_pdeath_normalizes_manual_signal() {
        let cli = Cli {
            pdeath: Some(" term ".into()),
            ..Cli::default()
        };

        let pdeath = explain_pdeath(&cli).expect("manual pdeath signal should normalize");

        assert_eq!(pdeath, "SIGTERM");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn explain_rejects_manual_command_with_embedded_nul() {
        let cli = Cli {
            explain: true,
            cmd: vec!["/bin/true".into(), "embedded\0argument".into()],
            ..Cli::default()
        };
        let err = explain(cli, &EnvDefaultLog::default(), false)
            .expect_err("explain must reject arguments that cannot be executed");

        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("embedded NUL byte"));
    }

    #[test]
    fn escaped_list_keeps_preescaped_path_diagnostics_readable() {
        assert_eq!(
            escaped_list(&["/tmp/a\\xff".into(), "/tmp/quote\\\"".into()]),
            r#"["/tmp/a\xff", "/tmp/quote\""]"#
        );
    }

    fn apply_env_defaults_from(
        cli: &mut Cli,
        vars: &[(&'static str, &'static str)],
    ) -> EnvDefaultLog {
        apply_env_defaults_with(cli, |name| {
            vars.iter()
                .find_map(|&(key, value)| (key == name).then(|| OsString::from(value)))
        })
    }

    #[test]
    fn env_boolean_defaults_take_effect() {
        let mut cli = base_cli();

        let log = apply_env_defaults_from(
            &mut cli,
            &[("TINO_SUBREAPER", "true"), ("TINO_KILL_PROCESS_GROUP", "0")],
        );
        assert!(cli.subreaper);
        assert!(!cli.pgroup_kill);
        assert_eq!(log.subreaper_env, Some(("TINO_SUBREAPER", true)));
        assert_eq!(log.pgroup_env, Some(("TINO_KILL_PROCESS_GROUP", false)));
        assert!(log.warnings.is_empty());
    }

    #[test]
    fn invalid_boolean_env_is_reported() {
        let mut cli = base_cli();

        let log = apply_env_defaults_from(
            &mut cli,
            &[("TINO_SUBREAPER", "maybe"), ("TINI_SUBREAPER", "1")],
        );
        assert_eq!(
            log.warnings,
            ["invalid boolean env default: TINO_SUBREAPER=maybe"]
        );
        assert!(!cli.subreaper);
    }

    #[test]
    fn verbosity_env_applies_when_flags_absent() {
        let mut cli = base_cli();

        let log = apply_env_defaults_from(&mut cli, &[("TINO_VERBOSITY", "3")]);
        assert_eq!(cli.verbosity, 3);
        assert_eq!(log.verbosity_env, Some(("TINO_VERBOSITY", 3)));
        assert!(log.warnings.is_empty());
    }

    #[test]
    fn invalid_verbosity_is_logged_without_panicking() {
        let mut cli = base_cli();

        let log = apply_env_defaults_from(
            &mut cli,
            &[("TINO_VERBOSITY", "noise"), ("TINI_VERBOSITY", "3")],
        );
        assert_eq!(cli.verbosity, 0);
        assert!(log.verbosity_env.is_none());
        assert_eq!(
            log.warnings,
            ["invalid TINO_VERBOSITY=noise: invalid digit found in string"]
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn non_utf8_env_defaults_are_preserved_in_diagnostics() {
        use std::os::unix::ffi::OsStringExt;

        let mut cli = base_cli();
        let raw = OsString::from_vec(vec![b'1', 0xff]);
        let log = apply_env_defaults_with(&mut cli, |name| {
            (name == "TINO_SUBREAPER").then(|| raw.clone())
        });

        assert_eq!(
            log.warnings,
            [r"invalid boolean env default: TINO_SUBREAPER=1\xff"]
        );
        assert!(!cli.subreaper);
    }

    #[test]
    fn verbosity_flag_wins_over_env() {
        let mut cli = base_cli();
        cli.verbosity = 2;

        let log = apply_env_defaults_from(&mut cli, &[("TINO_VERBOSITY", "3")]);
        assert_eq!(cli.verbosity, 2);
        assert!(log.verbosity_env.is_none());
    }

    #[test]
    fn boolean_flags_win_over_env() {
        let mut cli = base_cli();
        cli.subreaper = true;
        cli.pgroup_kill = true;
        let log = apply_env_defaults_from(
            &mut cli,
            &[
                ("TINO_SUBREAPER", "false"),
                ("TINO_KILL_PROCESS_GROUP", "0"),
            ],
        );

        assert!(cli.subreaper);
        assert!(cli.pgroup_kill);
        assert!(log.subreaper_env.is_none());
        assert!(log.pgroup_env.is_none());
    }

    #[test]
    fn explain_sources_use_configured_for_merged_cli_state() {
        let mut cli = Cli {
            subreaper: true,
            pgroup_kill: true,
            verbosity: 1,
            ..Cli::default()
        };
        let env = apply_env_defaults_with(&mut cli, |_| Some("0".into()));

        assert_eq!(
            setting_source(cli.subreaper, env.subreaper_env),
            "configured"
        );
        assert_eq!(
            setting_source(cli.pgroup_kill, env.pgroup_env),
            "configured"
        );
        assert_eq!(
            setting_source(cli.verbosity > 0, env.verbosity_env),
            "configured"
        );
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("tino-{name}-{}-{nanos}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn atomic_write_replaces_existing_file() {
        let dir = unique_test_dir("atomic-write-replace");
        let path = dir.join("tino.conf");
        fs::write(&path, b"old\n").expect("write old config");

        write_file_atomically(&path, b"new\n").expect("atomic write");

        assert_eq!(fs::read_to_string(&path).expect("read new config"), "new\n");
        assert!(
            !temp_path_for(&path).expect("temp path").exists(),
            "temporary config file should be renamed away"
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_write_cleans_temp_file_after_file_size_limit() {
        use std::os::unix::process::CommandExt;
        use std::process::Command;

        const PROBE_PATH: &str = "TINO_TEST_CONFIG_FILE_SIZE_LIMIT_PATH";
        if let Some(path) = std::env::var_os(PROBE_PATH) {
            let error = write_file_atomically(Path::new(&path), b"new\n")
                .expect_err("partial config write must fail");
            let source = std::error::Error::source(&error)
                .unwrap()
                .downcast_ref::<io::Error>()
                .unwrap();
            assert_eq!(source.raw_os_error(), Some(libc::EFBIG));
            return;
        }

        let dir = unique_test_dir("atomic-write-file-size-limit");
        let path = dir.join("config");
        fs::write(&path, b"old\n").unwrap();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "platform::tests::atomic_write_cleans_temp_file_after_file_size_limit",
                "--nocapture",
            ])
            .env(PROBE_PATH, &path);
        // SAFETY: only the isolated test process receives this resource limit.
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 1,
                    rlim_max: 1,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let output = command.output().unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(fs::read(&path).unwrap(), b"old\n");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        fs::remove_dir_all(dir).unwrap();
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn atomic_write_preserves_existing_permissions() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};

        let dir = unique_test_dir("atomic-write-permissions");
        let path = dir.join("tino.conf");
        fs::write(&path, b"old\n").expect("write old config");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640))
            .expect("set old config permissions");
        let initial = fs::metadata(&path).unwrap();
        // Root can exercise both IDs. Other runners can exercise group
        // preservation if they belong to a second group.
        let groups = std::process::Command::new("id").arg("-G").output().unwrap();
        assert!(groups.status.success());
        let alternate_group = std::str::from_utf8(&groups.stdout)
            .unwrap()
            .split_whitespace()
            .map(|group| group.parse::<u32>().unwrap())
            .find(|&group| group != initial.gid());
        let other_uid = (initial.uid() == 0).then_some(1);
        let other_gid = alternate_group.or(other_uid);
        // Single-ID user namespaces cannot assign the alternate owner.
        if let Err(err) = chown(&path, other_uid, other_gid) {
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::InvalidInput
                ),
                "{err}"
            );
        }
        let original = fs::metadata(&path).unwrap();

        write_file_atomically(&path, b"new\n").expect("atomic write");

        let new = fs::metadata(&path).expect("stat new config");
        assert_eq!((new.uid(), new.gid()), (original.uid(), original.gid()));
        assert_eq!(new.mode() & 0o777, 0o640);
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn atomic_write_preserves_the_files_access_acl() {
        use std::os::fd::AsRawFd;

        let dir = unique_test_dir("config-acl");
        let dir = DropGuard::new(dir, |dir| fs::remove_dir_all(dir).unwrap());
        let path = dir.join("tino.conf");
        let original = fs::File::create(&path).unwrap();
        let access = c"system.posix_acl_access";
        // Linux ACL xattr v2: owner rw, named group r, owning group none, mask r, other none.
        let mut acl = 2_u32.to_le_bytes().to_vec();
        let gid = unsafe { libc::getgid() };
        for (tag, perms, id) in [
            (1_u16, 6_u16, u32::MAX),
            (4, 0, u32::MAX),
            (8, 4, gid),
            (16, 4, u32::MAX),
            (32, 0, u32::MAX),
        ] {
            acl.extend(tag.to_le_bytes());
            acl.extend(perms.to_le_bytes());
            acl.extend(id.to_le_bytes());
        }
        let set_acl = |file: &fs::File, name: &std::ffi::CStr| unsafe {
            libc::fsetxattr(
                file.as_raw_fd(),
                name.as_ptr(),
                acl.as_ptr().cast(),
                acl.len(),
                0,
            )
        };
        if set_acl(&original, access) == -1 {
            let err = io::Error::last_os_error();
            assert_eq!(err.raw_os_error(), Some(libc::EOPNOTSUPP), "{err}");
            return;
        }

        write_file_atomically(&path, b"new\n").unwrap();
        let get_acl = |path: &Path| {
            let file = fs::File::open(path).unwrap();
            let mut buf = vec![0; acl.len()];
            let n = unsafe {
                libc::fgetxattr(
                    file.as_raw_fd(),
                    access.as_ptr(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                )
            };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            buf.truncate(n.cast_unsigned());
            Ok(buf)
        };
        assert_eq!(get_acl(&path).unwrap(), acl);

        let plain = dir.join("without-acl.conf");
        fs::write(&plain, b"old\n").unwrap();
        assert_eq!(
            set_acl(&fs::File::open(&*dir).unwrap(), c"system.posix_acl_default"),
            0
        );
        write_file_atomically(&plain, b"new\n").unwrap();
        assert_eq!(
            get_acl(&plain).unwrap_err().raw_os_error(),
            Some(libc::ENODATA)
        );
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn atomic_write_respects_creation_permissions_for_new_config() {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

        let dir = unique_test_dir("atomic-write-new-permissions");
        let path = dir.join("tino.conf");
        let reference = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(dir.join("reference"))
            .unwrap();

        write_file_atomically(&path, b"new\n").expect("atomic write");

        assert_eq!(
            fs::metadata(&path).unwrap().mode() & 0o777,
            reference.metadata().unwrap().mode() & 0o777
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn atomic_write_does_not_follow_existing_temp_symlink() {
        use std::os::unix::fs::symlink;

        let dir = unique_test_dir("atomic-write-symlink");
        let path = dir.join("tino.conf");
        let outside = dir.join("outside");
        fs::write(&path, b"old\n").expect("write old config");
        fs::write(&outside, b"outside\n").expect("write outside marker");
        symlink(&outside, temp_path_for(&path).expect("temp path")).expect("create temp symlink");

        write_file_atomically(&path, b"new\n").expect("atomic write");

        assert_eq!(fs::read_to_string(&path).expect("read new config"), "new\n");
        assert_eq!(
            fs::read_to_string(&outside).expect("read outside marker"),
            "outside\n"
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[cfg(target_family = "unix")]
    #[test]
    fn atomic_write_rejects_destination_symlink() {
        use std::os::unix::fs::symlink;

        let dir = unique_test_dir("atomic-write-destination-symlink");
        let path = dir.join("tino.conf");
        let outside = dir.join("outside");
        fs::write(&outside, b"outside\n").expect("write outside marker");
        symlink(&outside, &path).expect("create destination symlink");

        let err = write_file_atomically(&path, b"new\n")
            .expect_err("destination symlink must be rejected");

        assert!(
            format!("{err:#}").contains("refusing to replace symlink config path"),
            "unexpected symlink error: {err:#}"
        );
        assert_eq!(
            fs::read_to_string(&outside).expect("read outside marker"),
            "outside\n"
        );
        assert!(
            fs::symlink_metadata(&path)
                .expect("stat destination symlink")
                .file_type()
                .is_symlink(),
            "destination symlink should remain untouched"
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn atomic_write_rejects_non_file_destination() {
        let dir = unique_test_dir("atomic-write-destination-directory");
        let path = dir.join("tino.conf");
        fs::create_dir_all(&path).expect("create destination directory");

        let err = write_file_atomically(&path, b"new\n")
            .expect_err("directory destination must be rejected");

        assert!(
            format!("{err:#}").contains("is not a regular file"),
            "unexpected non-file error: {err:#}"
        );
        assert!(
            path.is_dir(),
            "destination directory should remain untouched"
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }

    #[test]
    fn write_config_does_not_create_parent_when_serialization_fails() {
        let dir = unique_test_dir("write-config-invalid");
        let parent = dir.join("missing-parent");
        let path = parent.join("tino.conf");
        let cli = Cli {
            write_allow: vec!["relative/path".into()],
            ..Cli::default()
        };

        let err = write_config(&path, &cli).expect_err("invalid config must fail before writing");

        assert!(
            format!("{err:#}").contains("must be an absolute path"),
            "unexpected error: {err:#}"
        );
        assert!(
            !parent.exists(),
            "invalid config must not create parent directories"
        );
        fs::remove_dir_all(&dir).expect("remove temp dir");
    }
}
