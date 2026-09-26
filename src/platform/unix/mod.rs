use crate::{
    Context, Error, Result, bail,
    cli::{Cli, WritePreset},
    diagnostic::{escape_bytes, escape_path, escape_str},
    logging,
};
#[cfg(test)]
use std::cell::RefCell;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{CString, OsString},
    fs::File,
    io,
    os::fd::AsFd,
    os::unix::ffi::{OsStrExt, OsStringExt},
    os::unix::fs::FileExt,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

mod child;
mod landlock;
#[cfg(test)]
mod policy_tests;
mod signals;
pub(crate) mod sys;

use child::{
    ForegroundTtyRestore, configure_parent_prctl, manage_process_group, owned_foreground_tty,
    pdeath_signal, prepare_resolved_command, resolve_command_args, spawn_child,
};
use landlock::{LandlockConfig, PathRuleKind, PinnedPath};
use signals::{
    ChildReapingRestore, read_forwardable_signal, restore_signal_delivery, send_signal,
    setup_signal_delivery,
};
#[cfg(test)]
use sys::Signal;
use sys::{
    Errno, Pid, PollFd, PollFlags, PollTimeout, SIGCHLD, SIGINT, SIGKILL, SIGQUIT, SIGTERM,
    SIGTTIN, SIGTTOU, SigSet, SignalFd, WaitStatus, poll_fds, process_group_exists,
    process_group_of, send_process_group_signal, send_process_signal, waitpid_any_nohang,
    waitpid_child, waitpid_group_nohang,
};

type ExitCodeRemap = super::ExitCodeRemap;
type PinnedPaths = BTreeMap<Vec<u8>, PinnedPath>;

// Tests that fork or call waitpid(-1) share the libtest process under cargo test.
#[cfg(test)]
static CHILD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
thread_local! {
    static TEST_EXEC_SEARCH_PATH: RefCell<ExecSearchPathOverride> =
        const { RefCell::new(ExecSearchPathOverride::Inherit) };
    static TEST_ENV_IDENTITY_PATHS: RefCell<Option<(PathBuf, PathBuf)>> =
        const { RefCell::new(None) };
}

#[cfg(test)]
#[derive(Clone)]
enum ExecSearchPathOverride {
    Inherit,
    Value(OsString),
    Default,
}

pub(super) struct LandlockExplain {
    pub write_requested: bool,
    pub exec_requested: bool,
    pub warn_only: bool,
    pub no_dev: bool,
    pub preset_names: Vec<String>,
    pub writable_dirs: Vec<String>,
    pub bind_tcp_ports: Vec<u16>,
    pub connect_tcp_ports: Vec<u16>,
    pub scope_signals: bool,
    pub scope_abstract_unix: bool,
    pub exec_allow_paths: Vec<String>,
    pub device_ioctl_allow_paths: Vec<String>,
}

pub(super) fn run_impl(cli: Cli, expect_zero: ExitCodeRemap) -> Result<i32> {
    let (previous_mask, mut signal_fd) = setup_signal_delivery()?;
    let signal_mask_restore = SignalMaskRestore::new(&previous_mask);
    // Reset inherited SIG_IGN/SA_NOCLDWAIT before fork, and restore the caller's
    // disposition before unblocking signals when supervision ends.
    let child_reaping_restore = ChildReapingRestore::enable()?;
    let child_pdeath = pdeath_signal(&cli)?;
    let effective_cmd =
        resolve_command_args(&cli.cmd, cli.expand_env).context("prepare child command")?;
    let landlock_config = build_landlock_config_for_args(&cli, &effective_cmd)?;
    if let Some(config) = &landlock_config {
        logging::debug(format_args!(
            "landlock restriction enabled: warn_only={}, no_dev={}, writable_dirs={}, bind_tcp_ports={}, connect_tcp_ports={}, scope_signals={}, scope_abstract_unix={}, exec_allow_paths={}, device_ioctl_allow_paths={}",
            config.warn_only,
            config.no_dev,
            config.writable_dirs.len(),
            config.bind_tcp_ports.len(),
            config.connect_tcp_ports.len(),
            config.scope_signals,
            config.scope_abstract_unix,
            config.exec_allow_paths.len(),
            config.device_ioctl_allow_paths.len()
        ));
        if logging::debug_enabled() {
            for path in &config.writable_dirs {
                logging::debug(format_args!(
                    "write allow dir: {}",
                    escape_bytes(path.as_c_str().to_bytes())
                ));
            }
            for port in &config.bind_tcp_ports {
                logging::debug(format_args!("bind TCP allow port: {}", port));
            }
            for port in &config.connect_tcp_ports {
                logging::debug(format_args!("connect TCP allow port: {}", port));
            }
            for path in &config.exec_allow_paths {
                logging::debug(format_args!(
                    "exec allow path: {}",
                    escape_bytes(path.as_c_str().to_bytes())
                ));
            }
            for path in &config.device_ioctl_allow_paths {
                logging::debug(format_args!(
                    "device ioctl allow path: {}",
                    escape_bytes(path.as_c_str().to_bytes())
                ));
            }
        }
    }

    let (cmd_c, argv_c) =
        prepare_resolved_command(&effective_cmd).context("prepare child command")?;
    let parent_prctl = configure_parent_prctl(&cli)?;
    let previous_foreground_group = cli.pgroup_kill.then(owned_foreground_tty).flatten();
    let child_pid = spawn_child(
        &previous_mask,
        child_pdeath,
        landlock_config.as_ref(),
        cli.pgroup_kill,
        previous_foreground_group.is_some(),
        &cmd_c,
        &argv_c,
    )
    .context("spawn child")?;
    let foreground_tty_restore =
        previous_foreground_group.map(|previous| ForegroundTtyRestore::new(previous, child_pid));
    // The child has its own copies, all closed by exec. The supervisor need
    // not retain policy descriptors for the entire workload lifetime.
    drop(landlock_config);
    let use_pgroup = manage_process_group(cli.pgroup_kill, child_pid);

    let mut result = supervise_child(
        &cli,
        &expect_zero,
        child_pid,
        use_pgroup,
        &mut signal_fd,
        foreground_tty_restore.as_ref(),
    );
    // Restore process and terminal state while supervision's signals remain
    // blocked. Attempt every restoration even after a failure, preserving the
    // supervision error when one already exists.
    drop(foreground_tty_restore);
    let restores = [
        parent_prctl.finish(),
        child_reaping_restore.finish(),
        signal_mask_restore.finish(),
    ];
    for restore in restores {
        if let Err(restore_err) = restore {
            if result.is_ok() {
                result = Err(restore_err);
            } else {
                logging::warn(format_args!(
                    "restore process state failed: {restore_err:#}"
                ));
            }
        }
    }
    result
}

struct SignalMaskRestore<'a> {
    previous_mask: &'a SigSet,
    active: bool,
}

impl<'a> SignalMaskRestore<'a> {
    const fn new(previous_mask: &'a SigSet) -> Self {
        Self {
            previous_mask,
            active: true,
        }
    }

    fn finish(mut self) -> Result<()> {
        self.active = false;
        restore_signal_delivery(self.previous_mask)
    }
}

impl Drop for SignalMaskRestore<'_> {
    fn drop(&mut self) {
        if self.active
            && let Err(err) = restore_signal_delivery(self.previous_mask)
        {
            logging::warn(format_args!("restore signal mask failed: {}", err));
        }
    }
}

pub(super) fn explain_effective_command(cmd: &[String], expand_env: bool) -> Result<Vec<String>> {
    resolve_command_args(cmd, expand_env)
}

pub(crate) fn bench_resolve_command_args(cmd: &[String], expand_env: bool) -> Result<Vec<String>> {
    resolve_command_args(cmd, expand_env)
}

pub(crate) fn bench_parse_shebang_interpreter(bytes: &[u8]) -> Option<String> {
    parse_shebang_interpreter(bytes)
}

pub(crate) fn bench_parse_elf_interpreter(bytes: &[u8]) -> Result<Option<String>> {
    parse_elf_interpreter(bytes)
}

pub(super) fn explain_landlock_config(
    cli: &Cli,
    effective_cmd: &[String],
) -> Result<Option<LandlockExplain>> {
    let config = build_landlock_config_for_args(cli, effective_cmd)?;
    Ok(config.map(|config| LandlockExplain {
        write_requested: config.write_requested,
        exec_requested: config.exec_requested,
        warn_only: config.warn_only,
        no_dev: config.no_dev,
        preset_names: config
            .preset_names
            .iter()
            .map(|name| (*name).to_string())
            .collect(),
        writable_dirs: config
            .writable_dirs
            .iter()
            .map(|path| explain_landlock_path(path.as_c_str()))
            .collect(),
        bind_tcp_ports: config.bind_tcp_ports,
        connect_tcp_ports: config.connect_tcp_ports,
        scope_signals: config.scope_signals,
        scope_abstract_unix: config.scope_abstract_unix,
        exec_allow_paths: config
            .exec_allow_paths
            .iter()
            .map(|path| explain_landlock_path(path.as_c_str()))
            .collect(),
        device_ioctl_allow_paths: config
            .device_ioctl_allow_paths
            .iter()
            .map(|path| explain_landlock_path(path.as_c_str()))
            .collect(),
    }))
}

fn explain_landlock_path(path: &std::ffi::CStr) -> String {
    escape_bytes(path.to_bytes())
}

#[cfg(test)]
fn build_landlock_config(cli: &Cli) -> Result<Option<LandlockConfig>> {
    let effective_cmd = resolve_command_args(&cli.cmd, cli.expand_env)?;
    build_landlock_config_for_args(cli, &effective_cmd)
}

fn build_landlock_config_for_args(
    cli: &Cli,
    effective_cmd: &[String],
) -> Result<Option<LandlockConfig>> {
    let write_requested =
        cli.write_restrict || !cli.write_allow.is_empty() || !cli.write_preset.is_empty();
    let tcp_requested = !cli.bind_tcp_allow.is_empty() || !cli.connect_tcp_allow.is_empty();
    let scope_requested = cli.scope_signals || cli.scope_abstract_unix;
    let exec_requested = !cli.exec_allow.is_empty();
    let device_ioctl_requested = !cli.device_ioctl_allow.is_empty();
    let enabled = write_requested
        || tcp_requested
        || scope_requested
        || exec_requested
        || device_ioctl_requested;
    if !enabled {
        return Ok(None);
    }

    let mut unique = PinnedPaths::new();
    let mut preset_names = Vec::new();
    let mut exec_allow = PinnedPaths::new();
    let mut device_ioctl_allow = PinnedPaths::new();

    for preset in &cli.write_preset {
        let name = preset.as_str();
        if !preset_names.contains(&name) {
            let _ = preset_names.push_mut(name);
        }
        for raw in preset_paths(*preset) {
            insert_landlock_writable_dir(&mut unique, raw, true)?;
        }
    }

    for raw in &cli.write_allow {
        let path = landlock_absolute_path_option("--write-allow", raw)?;
        insert_landlock_writable_dir(&mut unique, path, false)?;
    }

    if exec_requested && let Some(program) = effective_cmd.first() {
        insert_landlock_main_exec_path(&mut exec_allow, program)?;
    }

    for raw in &cli.exec_allow {
        let path = landlock_exec_path_option("--exec-allow", raw)?;
        insert_landlock_exec_path(&mut exec_allow, path)?;
    }

    for raw in &cli.device_ioctl_allow {
        let path = landlock_absolute_path_option("--device-ioctl-allow", raw)?;
        insert_landlock_device_ioctl_path(&mut device_ioctl_allow, path)?;
    }

    let writable_dirs = unique.into_values().collect();
    let exec_allow_paths = exec_allow.into_values().collect();
    let device_ioctl_allow_paths = device_ioctl_allow.into_values().collect();
    let dev_dir = if write_requested && !cli.write_no_dev {
        pin_allow_path(
            "/dev",
            true,
            "default writable directory",
            PathRuleKind::Directory,
        )?
    } else {
        None
    };

    let bind_tcp_ports = unique_ports("--bind-tcp-allow", &cli.bind_tcp_allow)?;
    let connect_tcp_ports = unique_ports("--connect-tcp-allow", &cli.connect_tcp_allow)?;

    Ok(Some(LandlockConfig {
        write_requested,
        warn_only: cli.restrict_warn_only,
        no_dev: cli.write_no_dev,
        preset_names,
        writable_dirs,
        dev_dir,
        bind_tcp_ports,
        connect_tcp_ports,
        scope_signals: cli.scope_signals,
        scope_abstract_unix: cli.scope_abstract_unix,
        exec_requested,
        exec_allow_paths,
        device_ioctl_allow_paths,
    }))
}

fn unique_ports(option: &str, raw_ports: &[u16]) -> Result<Vec<u16>> {
    for &port in raw_ports {
        if port == 0 {
            return Err(Error::usage(format!(
                "invalid value for {option}: 0 (expected 1-65535)"
            )));
        }
    }

    Ok(raw_ports
        .iter()
        .copied()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect())
}

fn landlock_path_option<'a>(option: &str, raw: &'a str) -> Result<&'a str> {
    if raw.is_empty() {
        return Err(Error::usage(format!("{option} PATH cannot be empty")));
    }
    if raw != raw.trim() {
        return Err(Error::usage(format!(
            "{option} PATH cannot have surrounding whitespace"
        )));
    }
    Ok(raw)
}

fn landlock_absolute_path_option<'a>(option: &str, raw: &'a str) -> Result<&'a str> {
    let path = landlock_path_option(option, raw)?;
    if !Path::new(path).is_absolute() {
        return Err(Error::usage(format!("{option} PATH must be absolute")));
    }
    Ok(path)
}

fn landlock_exec_path_option<'a>(option: &str, raw: &'a str) -> Result<&'a str> {
    let path = landlock_path_option(option, raw)?;
    if path.contains('/') && !Path::new(path).is_absolute() {
        return Err(Error::usage(format!(
            "{option} PATH must be absolute when it contains '/'"
        )));
    }
    Ok(path)
}

const fn preset_paths(preset: WritePreset) -> &'static [&'static str] {
    match preset {
        WritePreset::Tmp => &["/tmp", "/var/tmp"],
        WritePreset::Runtime => &["/tmp", "/var/tmp", "/run"],
    }
}

fn insert_landlock_writable_dir(
    unique: &mut PinnedPaths,
    raw: &str,
    allow_missing: bool,
) -> Result<()> {
    let Some(path) = pin_allow_path(
        raw,
        allow_missing,
        "write allow path",
        PathRuleKind::Directory,
    )?
    else {
        return Ok(());
    };
    unique.insert(path.as_c_str().to_bytes().to_vec(), path);
    Ok(())
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct ExecContext {
    environment: BTreeMap<OsString, OsString>,
    cwd: Option<PathBuf>,
}

impl ExecContext {
    fn inherited() -> Self {
        #[allow(unused_mut)]
        let mut environment: BTreeMap<OsString, OsString> = std::env::vars_os().collect();
        #[cfg(test)]
        match test_exec_search_path_override() {
            ExecSearchPathOverride::Inherit => {}
            ExecSearchPathOverride::Value(path) => {
                environment.insert("PATH".into(), path);
            }
            ExecSearchPathOverride::Default => {
                environment.remove(std::ffi::OsStr::new("PATH"));
            }
        }
        Self {
            environment,
            cwd: None,
        }
    }

    fn search_path(&self) -> OsString {
        self.environment
            .get(std::ffi::OsStr::new("PATH"))
            .cloned()
            .unwrap_or_else(default_exec_search_path)
    }

    fn path(&self, path: &Path) -> PathBuf {
        if path.is_relative()
            && let Some(cwd) = &self.cwd
        {
            return cwd.join(path);
        }
        path.to_path_buf()
    }
}

type ExecVisits = BTreeSet<(PathBuf, ExecContext)>;

fn insert_landlock_exec_path(unique: &mut PinnedPaths, raw: &str) -> Result<()> {
    let mut visited = BTreeSet::new();
    insert_landlock_exec_path_inner(
        unique,
        raw,
        &mut visited,
        ExecAllowMode::Strict,
        &ExecContext::inherited(),
    )
}

fn insert_landlock_main_exec_path(unique: &mut PinnedPaths, raw: &str) -> Result<()> {
    let mut visited = BTreeSet::new();
    insert_landlock_exec_path_inner(
        unique,
        raw,
        &mut visited,
        ExecAllowMode::Auto,
        &ExecContext::inherited(),
    )
}

fn insert_landlock_exec_path_inner(
    unique: &mut PinnedPaths,
    raw: &str,
    visited: &mut ExecVisits,
    mode: ExecAllowMode,
    context: &ExecContext,
) -> Result<()> {
    if !raw.contains('/') {
        let candidates =
            executable_paths_in_search_path(raw, &context.search_path(), context.cwd.as_deref());
        if candidates.is_empty() && mode == ExecAllowMode::Strict {
            bail!("resolve exec allow path '{}' from PATH", escape_str(raw));
        }
        return insert_exec_search_candidates(unique, candidates, visited, context);
    }
    let resolved = match mode {
        ExecAllowMode::Strict => Some(resolve_exec_allow_path(raw)?),
        ExecAllowMode::Auto => resolve_main_exec_allow_path(raw)?,
    };
    let Some(resolved) = resolved else {
        return Ok(());
    };
    insert_resolved_exec_path(unique, resolved, visited, mode, context)
}

fn insert_exec_search_candidates(
    unique: &mut PinnedPaths,
    candidates: Vec<PathBuf>,
    visited: &mut ExecVisits,
    context: &ExecContext,
) -> Result<()> {
    // execvp can fall back to another candidate. An unreadable or otherwise
    // uninspectable candidate must not prevent a different match from running.
    // Keep only discovered file grants; never grant a containing directory.
    for path in candidates {
        let result = (|| {
            let Some(resolved) =
                resolve_exec_allow_path_from_path(path.clone(), ExecAllowMode::Auto)?
            else {
                return Ok(());
            };
            if is_executable_file(&resolved.metadata) {
                insert_resolved_exec_path(unique, resolved, visited, ExecAllowMode::Auto, context)?;
            }
            Ok::<(), Error>(())
        })();
        if let Err(err) = result {
            logging::debug(format_args!(
                "skip interpreter discovery for PATH candidate '{}': {err}",
                escape_path(&path)
            ));
        }
    }
    Ok(())
}

fn insert_resolved_exec_path(
    unique: &mut PinnedPaths,
    resolved: ResolvedExecAllowPath,
    visited: &mut ExecVisits,
    mode: ExecAllowMode,
    context: &ExecContext,
) -> Result<()> {
    if !visited.insert((resolved.canonical.clone(), context.clone())) {
        return Ok(());
    }
    // env can re-exec a script with a different environment or directory. Bound
    // that graph as well as detecting cycles with identical execution contexts.
    if visited.len() > 256 {
        bail!("exec interpreter discovery exceeds 256 file/context pairs");
    }
    let interpreters = if is_executable_file(&resolved.metadata) {
        detect_exec_interpreters_in_context(&resolved.pinned, context)
    } else {
        Ok(Vec::new())
    };
    // Pin the executable even when optional interpreter discovery fails. This
    // applies equally to absolute main commands and PATH candidates; explicitly
    // listed files still require successful inspection.
    unique.insert(
        resolved.canonical.as_os_str().as_bytes().to_vec(),
        resolved.pinned,
    );
    let discovery = (|| {
        for interpreter in interpreters? {
            insert_exec_interpreter(unique, interpreter, visited, mode, context)?;
        }
        Ok(())
    })();
    if mode == ExecAllowMode::Auto
        && let Err(err) = &discovery
    {
        logging::debug(format_args!(
            "skip interpreter discovery for executable '{}': {err}",
            escape_path(&resolved.canonical)
        ));
        return Ok(());
    }
    discovery
}

fn insert_exec_interpreter(
    unique: &mut PinnedPaths,
    interpreter: ExecInterpreter,
    visited: &mut ExecVisits,
    mode: ExecAllowMode,
    context: &ExecContext,
) -> Result<()> {
    match interpreter {
        ExecInterpreter::Candidate(path) => {
            insert_landlock_exec_path_candidate(unique, path, None, visited, mode, context)
        }
        ExecInterpreter::ShebangCandidate { path, argument } => {
            insert_landlock_exec_path_candidate(
                unique,
                path,
                Some(argument),
                visited,
                mode,
                context,
            )
        }
        ExecInterpreter::SearchCandidates(paths) => {
            insert_exec_search_candidates(unique, paths, visited, context)
        }
        ExecInterpreter::EnvCommand(command) => {
            insert_exec_interpreter(unique, command.resolve(), visited, mode, &command.context)
        }
        ExecInterpreter::Missing { .. } | ExecInterpreter::Unresolved { .. }
            if mode == ExecAllowMode::Auto =>
        {
            Ok(())
        }
        ExecInterpreter::Missing { command } => bail!(
            "resolve exec allow path '{}' from shebang PATH",
            escape_str(&command)
        ),
        ExecInterpreter::Unresolved { reason } => bail!("{reason}"),
    }
}

fn insert_landlock_exec_path_candidate(
    unique: &mut PinnedPaths,
    path: PathBuf,
    shebang_argument: Option<OwnedShebangArgument>,
    visited: &mut ExecVisits,
    mode: ExecAllowMode,
    context: &ExecContext,
) -> Result<()> {
    if !path.as_os_str().as_bytes().contains(&b'/') {
        let Some(command) = path.to_str() else {
            if mode == ExecAllowMode::Auto {
                return Ok(());
            }
            bail!("resolve exec allow path from non-Unicode PATH command");
        };
        return insert_landlock_exec_path_inner(unique, command, visited, mode, context);
    }
    let Some(resolved) = resolve_exec_allow_path_from_path(context.path(&path), mode)? else {
        return Ok(());
    };
    if !is_executable_file(&resolved.metadata) {
        if mode == ExecAllowMode::Auto {
            return Ok(());
        }
        bail!(
            "exec interpreter path '{}' is not an executable file",
            escape_path(&resolved.canonical)
        );
    }
    // Identify aliases from the same pinned object used for the rule, rather
    // than assuming an executable named "env" implements GNU env semantics.
    let env_argument = shebang_argument.filter(|_| is_env_executable(&resolved.metadata));
    insert_resolved_exec_path(unique, resolved, visited, mode, context)?;
    if let Some(argument) = env_argument {
        let argument = match argument {
            OwnedShebangArgument::Utf8(argument) => argument,
            OwnedShebangArgument::InvalidUtf8 => {
                bail!("env shebang argument is not valid UTF-8");
            }
        };
        if let Some(command) = env_shebang_command(&argument, context).map_err(Error::msg)? {
            insert_exec_interpreter(
                unique,
                ExecInterpreter::EnvCommand(command),
                visited,
                mode,
                context,
            )?;
        }
    }
    Ok(())
}

fn is_executable_file(metadata: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;

    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

fn insert_landlock_device_ioctl_path(unique: &mut PinnedPaths, raw: &str) -> Result<()> {
    use std::os::unix::fs::FileTypeExt;

    let path = PinnedPath::open(Path::new(raw), PathRuleKind::Any).with_context(|| {
        format!(
            "open device ioctl allow path '{}'",
            escape_path(Path::new(raw))
        )
    })?;
    let metadata = path.metadata().with_context(|| {
        format!(
            "inspect device ioctl allow path '{}'",
            escape_path(path.path())
        )
    })?;
    let file_type = metadata.file_type();
    if !metadata.is_dir() && !file_type.is_char_device() && !file_type.is_block_device() {
        bail!(
            "device ioctl allow path '{}' is neither a directory nor a device node",
            escape_path(path.path())
        );
    }
    unique.insert(path.as_c_str().to_bytes().to_vec(), path);
    Ok(())
}

fn pin_allow_path(
    raw: &str,
    allow_missing: bool,
    kind: &str,
    rule_kind: PathRuleKind,
) -> Result<Option<PinnedPath>> {
    match PinnedPath::open(Path::new(raw), rule_kind) {
        Ok(path) => Ok(Some(path)),
        Err(err) if allow_missing && err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => {
            Err(err).with_context(|| format!("open {kind} '{}'", escape_path(Path::new(raw))))
        }
    }
}

struct ResolvedExecAllowPath {
    canonical: PathBuf,
    metadata: std::fs::Metadata,
    pinned: PinnedPath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExecAllowMode {
    Strict,
    Auto,
}

fn resolve_exec_allow_path(raw: &str) -> Result<ResolvedExecAllowPath> {
    let resolved = resolve_exec_allow_path_candidate(raw)?;
    resolved_exec_allow_path_from_candidate(&resolved)
}

fn resolve_main_exec_allow_path(raw: &str) -> Result<Option<ResolvedExecAllowPath>> {
    let Some(candidate) = resolve_main_exec_allow_path_candidate(raw)? else {
        return Ok(None);
    };
    let resolved = resolved_exec_allow_path_from_candidate(&candidate)?;
    if is_executable_file(&resolved.metadata) {
        Ok(Some(resolved))
    } else {
        Ok(None)
    }
}

fn resolved_exec_allow_path_from_candidate(resolved: &Path) -> Result<ResolvedExecAllowPath> {
    let pinned = PinnedPath::open(resolved, PathRuleKind::Any)
        .with_context(|| format!("open exec allow path '{}'", escape_path(resolved)))?;
    let canonical = pinned.path().to_path_buf();
    let metadata = pinned
        .metadata()
        .with_context(|| format!("inspect exec allow path '{}'", escape_path(&canonical)))?;
    if !metadata.is_dir() && !metadata.is_file() {
        bail!(
            "exec allow path '{}' is neither a regular file nor a directory",
            escape_path(&canonical)
        );
    }
    Ok(ResolvedExecAllowPath {
        canonical,
        metadata,
        pinned,
    })
}

fn resolve_exec_allow_path_from_path(
    path: PathBuf,
    mode: ExecAllowMode,
) -> Result<Option<ResolvedExecAllowPath>> {
    if mode == ExecAllowMode::Auto {
        match std::fs::metadata(&path) {
            Ok(_) => {}
            Err(err) if auto_exec_candidate_is_unavailable(&err) => return Ok(None),
            Err(err) => {
                return Err(err).with_context(|| {
                    format!(
                        "inspect main exec allow path candidate '{}'",
                        escape_path(&path)
                    )
                });
            }
        }
    }

    resolved_exec_allow_path_from_candidate(&path).map(Some)
}

fn resolve_main_exec_allow_path_candidate(raw: &str) -> Result<Option<PathBuf>> {
    if raw.contains('/') {
        return match std::fs::metadata(raw) {
            // FIFOs, device nodes and directories cannot be main executables.
            // Leave their native execution failure to the child without grants.
            Ok(metadata) if !metadata.is_file() => Ok(None),
            Ok(_) => Ok(Some(PathBuf::from(raw))),
            Err(err) if auto_exec_candidate_is_unavailable(&err) => Ok(None),
            Err(err) => Err(err).with_context(|| {
                format!(
                    "inspect main exec allow path candidate '{}'",
                    escape_path(Path::new(raw))
                )
            }),
        };
    }

    let search_path = exec_search_path();
    Ok(find_executable_in_search_path(raw, &search_path, None))
}

fn auto_exec_candidate_is_unavailable(err: &io::Error) -> bool {
    // Automatic discovery must leave inaccessible main commands to execvp so
    // their native execution error and exit status are preserved. No grant is
    // added for these candidates; explicit allow paths still fail validation.
    matches!(
        err.raw_os_error(),
        Some(
            libc::ENOENT
                | libc::ENOTDIR
                | libc::EACCES
                | libc::EPERM
                | libc::ELOOP
                | libc::ENAMETOOLONG
        )
    )
}

fn resolve_exec_allow_path_candidate(raw: &str) -> Result<PathBuf> {
    let path = PathBuf::from(raw);
    if raw.contains('/') {
        return Ok(path);
    }

    let search_path = exec_search_path();
    if let Some(candidate) = find_executable_in_search_path(raw, &search_path, None) {
        return Ok(candidate);
    }

    bail!("resolve exec allow path '{}' from PATH", escape_str(raw))
}

fn find_executable_in_search_path(
    raw: &str,
    search_path: &OsString,
    relative_to: Option<&Path>,
) -> Option<PathBuf> {
    executable_paths_in_search_path(raw, search_path, relative_to)
        .into_iter()
        .next()
}

fn executable_paths_in_search_path(
    raw: &str,
    search_path: &OsString,
    relative_to: Option<&Path>,
) -> Vec<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let mut candidates = Vec::new();
    for dir in std::env::split_paths(&search_path) {
        let candidate = if dir.is_relative() {
            relative_to.map_or_else(|| dir.join(raw), |base| base.join(&dir).join(raw))
        } else {
            dir.join(raw)
        };
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            let Ok(path) = CString::new(candidate.as_os_str().as_bytes()) else {
                continue;
            };
            if sys::check_executable_access(&path).is_ok() {
                candidates.push(candidate);
            }
        }
    }
    candidates
}

fn exec_search_path() -> OsString {
    #[cfg(test)]
    match test_exec_search_path_override() {
        ExecSearchPathOverride::Inherit => {}
        ExecSearchPathOverride::Value(path) => return path,
        ExecSearchPathOverride::Default => return default_exec_search_path(),
    }

    std::env::var_os("PATH").unwrap_or_else(default_exec_search_path)
}

#[cfg(test)]
fn test_exec_search_path_override() -> ExecSearchPathOverride {
    TEST_EXEC_SEARCH_PATH.with(|path| path.borrow().clone())
}

fn default_exec_search_path() -> OsString {
    let fallback = || OsString::from("/bin:/usr/bin");
    // SAFETY: the first call queries the required buffer length for _CS_PATH.
    let len = unsafe { libc::confstr(libc::_CS_PATH, std::ptr::null_mut(), 0) };
    if len == 0 {
        return fallback();
    }

    let mut buf = vec![0u8; len];
    // SAFETY: buffer is valid for writes of `buf.len()` bytes.
    let written = unsafe { libc::confstr(libc::_CS_PATH, buf.as_mut_ptr().cast(), buf.len()) };
    if written == 0 || written > buf.len() {
        return fallback();
    }
    buf.truncate(written.saturating_sub(1));
    OsString::from_vec(buf)
}

#[cfg(test)]
fn detect_exec_interpreters(path: &Path) -> Result<Vec<ExecInterpreter>> {
    let pinned = PinnedPath::open(path, PathRuleKind::Any).context("pin interpreter fixture")?;
    detect_exec_interpreters_in_context(&pinned, &ExecContext::inherited())
}

fn detect_exec_interpreters_in_context(
    pinned: &PinnedPath,
    context: &ExecContext,
) -> Result<Vec<ExecInterpreter>> {
    let path = pinned.path();
    let file = pinned.open_read().with_context(|| {
        format!(
            "open exec allow file '{}' for interpreter discovery",
            escape_path(path)
        )
    })?;
    let shebang_prefix = read_file_prefix_from(&file, EXEC_PROBE_PREFIX_LEN)
        .with_context(|| format!("read exec allow file '{}'", escape_path(path)))?;
    let shebang_interpreters = parse_shebang_exec_interpreters_in_context(&shebang_prefix, context);
    if !shebang_interpreters.is_empty() {
        return Ok(shebang_interpreters);
    }
    if shebang_prefix.starts_with(b"#!") {
        return Ok(Vec::new());
    }
    if shebang_prefix.starts_with(ELF_MAGIC) {
        return Ok(match read_elf_interpreter_from_file(&file, path)? {
            // PT_INTERP is a filesystem path, even when it is a bare name.
            // Keep it out of the command-name PATH search, as with shebangs.
            ElfInterpreter::Interpreter(path) => vec![ExecInterpreter::Candidate(
                filesystem_interpreter_path(path.into_os_string()),
            )],
            ElfInterpreter::NoInterpreter => Vec::new(),
            ElfInterpreter::Invalid => {
                vec![ExecInterpreter::Candidate(PathBuf::from(
                    EXECVP_FALLBACK_SHELL,
                ))]
            }
        });
    }
    Ok(vec![ExecInterpreter::Candidate(PathBuf::from(
        EXECVP_FALLBACK_SHELL,
    ))])
}

const EXEC_PROBE_PREFIX_LEN: usize = 4096;
const ELF_INTERPRETER_MAX_LEN: usize = 4096;
const ELF_PROGRAM_HEADER_TABLE_MAX_LEN: usize = 1024 * 1024;
const ELF_MAGIC: &[u8; 4] = b"\x7FELF";
const EXECVP_FALLBACK_SHELL: &str = "/bin/sh";
const LINUX_BINPRM_BUF_SIZE: usize = 256;

enum ElfInterpreter {
    Interpreter(PathBuf),
    NoInterpreter,
    Invalid,
}

fn read_file_prefix_from(file: &File, max_len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; max_len];
    let mut len = 0usize;
    while len < max_len {
        match file.read_at(&mut buf[len..], len as u64) {
            Ok(0) => break,
            Ok(read) => len += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    buf.truncate(len);
    Ok(buf)
}

fn parse_shebang_interpreter(bytes: &[u8]) -> Option<String> {
    parse_shebang_exec_paths(bytes).into_iter().next()
}

fn parse_shebang_exec_paths(bytes: &[u8]) -> Vec<String> {
    parse_shebang_exec_interpreters(bytes)
        .into_iter()
        .flat_map(ExecInterpreter::into_display_paths)
        .collect()
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ExecInterpreter {
    Candidate(PathBuf),
    ShebangCandidate {
        path: PathBuf,
        argument: OwnedShebangArgument,
    },
    SearchCandidates(Vec<PathBuf>),
    EnvCommand(EnvShebangCommand),
    Missing {
        command: String,
    },
    Unresolved {
        reason: &'static str,
    },
}

impl ExecInterpreter {
    fn into_display_paths(self) -> Vec<String> {
        match self {
            Self::Candidate(path) => vec![path.to_string_lossy().into_owned()],
            Self::ShebangCandidate { path, .. } => vec![path.to_string_lossy().into_owned()],
            Self::SearchCandidates(paths) => paths
                .into_iter()
                .map(|path| path.to_string_lossy().into_owned())
                .collect(),
            Self::EnvCommand(command) => command.resolve().into_display_paths(),
            Self::Missing { command } => vec![command],
            Self::Unresolved { reason } => vec![reason.to_owned()],
        }
    }
}

fn parse_shebang_exec_interpreters(bytes: &[u8]) -> Vec<ExecInterpreter> {
    parse_shebang_exec_interpreters_in_context(bytes, &ExecContext::inherited())
}

fn parse_shebang_exec_interpreters_in_context(
    bytes: &[u8],
    context: &ExecContext,
) -> Vec<ExecInterpreter> {
    let Some(shebang) = parse_shebang(bytes) else {
        return Vec::new();
    };
    let parts = match shebang {
        Shebang::Parts(parts) => parts,
        Shebang::ExecvpFallback => {
            return vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL,
            ))];
        }
    };

    let path = shebang_interpreter_path(parts.interpreter);
    if !is_env_interpreter(parts.interpreter) {
        return vec![match parts.argument {
            ShebangArgument::None => ExecInterpreter::Candidate(path),
            ShebangArgument::Utf8(argument) => ExecInterpreter::ShebangCandidate {
                path,
                argument: OwnedShebangArgument::Utf8(argument.to_owned()),
            },
            ShebangArgument::InvalidUtf8 => ExecInterpreter::ShebangCandidate {
                path,
                argument: OwnedShebangArgument::InvalidUtf8,
            },
        }];
    }
    let mut paths = vec![ExecInterpreter::Candidate(path)];
    if is_env_interpreter(parts.interpreter) {
        match parts.argument {
            ShebangArgument::None => {}
            ShebangArgument::Utf8(argument) => match env_shebang_command(argument, context) {
                Ok(Some(command)) => paths.push(ExecInterpreter::EnvCommand(command)),
                Ok(None) => {}
                Err(reason) => paths.push(ExecInterpreter::Unresolved { reason }),
            },
            ShebangArgument::InvalidUtf8 => {
                let _ = paths.push_mut(ExecInterpreter::Unresolved {
                    reason: "env shebang argument is not valid UTF-8",
                });
            }
        }
    }
    paths
}

struct ShebangParts<'a> {
    interpreter: &'a [u8],
    argument: ShebangArgument<'a>,
}

enum ShebangArgument<'a> {
    None,
    Utf8(&'a str),
    InvalidUtf8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum OwnedShebangArgument {
    Utf8(String),
    InvalidUtf8,
}

enum Shebang<'a> {
    Parts(ShebangParts<'a>),
    ExecvpFallback,
}

fn parse_shebang(bytes: &[u8]) -> Option<Shebang<'_>> {
    if !bytes.starts_with(b"#!") {
        return None;
    }

    // Linux binfmt_script only makes the first BINPRM_BUF_SIZE bytes visible.
    // A terminator at byte 255 is usable; one at byte 256 is already invisible.
    let visible_len = bytes.len().min(LINUX_BINPRM_BUF_SIZE);
    let visible = &bytes[..visible_len];
    let line = if let Some(end) = visible.iter().position(|byte| *byte == b'\n' || *byte == 0) {
        &visible[2..end]
    } else if bytes.len() < LINUX_BINPRM_BUF_SIZE || shebang_interpreter_is_terminated(visible) {
        // Linux replaces the last byte of a full buffer with NUL before
        // passing the optional argument to the interpreter.
        &visible[2..visible.len().min(LINUX_BINPRM_BUF_SIZE - 1)]
    } else {
        return Some(Shebang::ExecvpFallback);
    };

    Some(parse_shebang_line(line))
}

fn parse_shebang_line(line: &[u8]) -> Shebang<'_> {
    let line = trim_shebang_space_end(line);
    let interpreter_start = line.iter().position(|byte| !is_shebang_space(*byte));
    let Some(interpreter_start) = interpreter_start else {
        return Shebang::ExecvpFallback;
    };
    let rest = &line[interpreter_start..];
    let interpreter_end = rest
        .iter()
        .position(|byte| is_shebang_space(*byte))
        .unwrap_or(rest.len());
    let interpreter = &rest[..interpreter_end];
    let argument = trim_shebang_space_start(&rest[interpreter_end..]);
    let argument = if argument.is_empty() {
        ShebangArgument::None
    } else {
        match std::str::from_utf8(argument) {
            Ok(argument) => ShebangArgument::Utf8(argument),
            Err(_) => ShebangArgument::InvalidUtf8,
        }
    };
    Shebang::Parts(ShebangParts {
        interpreter,
        argument,
    })
}

fn shebang_interpreter_path(interpreter: &[u8]) -> PathBuf {
    filesystem_interpreter_path(OsString::from_vec(interpreter.to_vec()))
}

fn filesystem_interpreter_path(path: OsString) -> PathBuf {
    if path.as_bytes().contains(&b'/') {
        PathBuf::from(path)
    } else {
        PathBuf::from(".").join(path)
    }
}

const ENV_INTERPRETER_PATHS: &[&str] = &["/usr/bin/env", "/bin/env"];

fn is_env_interpreter(path: &[u8]) -> bool {
    ENV_INTERPRETER_PATHS
        .iter()
        .any(|candidate| path == candidate.as_bytes())
}

fn is_env_executable(metadata: &std::fs::Metadata) -> bool {
    #[cfg(test)]
    if let Some((env, shell)) = TEST_ENV_IDENTITY_PATHS.with(|paths| paths.borrow().clone()) {
        return env_reference_matches(metadata, &env, &shell);
    }
    ENV_INTERPRETER_PATHS.iter().any(|path| {
        env_reference_matches(metadata, Path::new(path), Path::new(EXECVP_FALLBACK_SHELL))
    })
}

fn env_reference_matches(metadata: &std::fs::Metadata, env: &Path, shell: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;

    // Multicall binaries dispatch by argv[0], so inode identity alone does not
    // make an alias behave as env. Reject references to another executable name
    // and hardlink installs that share their inode with the system shell.
    if !std::fs::canonicalize(env)
        .is_ok_and(|path| path.file_name() == Some(std::ffi::OsStr::new("env")))
        || std::fs::metadata(shell)
            .is_ok_and(|known| known.dev() == metadata.dev() && known.ino() == metadata.ino())
    {
        return false;
    }
    std::fs::metadata(env)
        .is_ok_and(|known| known.dev() == metadata.dev() && known.ino() == metadata.ino())
}

fn shebang_interpreter_is_terminated(visible: &[u8]) -> bool {
    let Some(line) = visible.get(2..) else {
        return false;
    };
    let Some(interpreter_start) = line.iter().position(|byte| !is_shebang_space(*byte)) else {
        return false;
    };
    line[interpreter_start..]
        .iter()
        .any(|byte| is_shebang_space(*byte) || *byte == 0)
}

const fn is_shebang_space(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t')
}

fn trim_shebang_space_start(mut bytes: &[u8]) -> &[u8] {
    while bytes.first().is_some_and(|byte| is_shebang_space(*byte)) {
        bytes = &bytes[1..];
    }
    bytes
}

fn trim_shebang_space_end(mut bytes: &[u8]) -> &[u8] {
    while bytes.last().is_some_and(|byte| is_shebang_space(*byte)) {
        bytes = &bytes[..bytes.len() - 1];
    }
    bytes
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct EnvShebangCommand {
    command: String,
    context: ExecContext,
    search_modified: bool,
}

struct EnvShebangFields {
    fields: Vec<String>,
    ignore_environment: bool,
}

#[derive(Default)]
struct EnvShebangOptions {
    ignore_environment: bool,
    unset_names: Vec<String>,
    chdir: Option<String>,
    invalid_signal_disposition: bool,
}

struct EnvSplitString<'a> {
    value: &'a str,
    ignore_environment: bool,
}

enum EnvSplitExpansion {
    Value(String),
    Unset,
}

enum EnvOptionAction {
    Continue,
    Return(Option<EnvShebangCommand>),
    SplitString(String),
    Invalid,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EnvLongOption {
    Argv0,
    BlockSignal,
    Chdir,
    Debug,
    DefaultSignal,
    Help,
    IgnoreEnvironment,
    IgnoreSignal,
    ListSignalHandling,
    Null,
    SplitString,
    Unset,
    Version,
}

const ENV_LONG_OPTIONS: &[(EnvLongOption, &str)] = &[
    (EnvLongOption::Argv0, "argv0"),
    (EnvLongOption::BlockSignal, "block-signal"),
    (EnvLongOption::Chdir, "chdir"),
    (EnvLongOption::Debug, "debug"),
    (EnvLongOption::DefaultSignal, "default-signal"),
    (EnvLongOption::Help, "help"),
    (EnvLongOption::IgnoreEnvironment, "ignore-environment"),
    (EnvLongOption::IgnoreSignal, "ignore-signal"),
    (EnvLongOption::ListSignalHandling, "list-signal-handling"),
    (EnvLongOption::Null, "null"),
    (EnvLongOption::SplitString, "split-string"),
    (EnvLongOption::Unset, "unset"),
    (EnvLongOption::Version, "version"),
];

impl EnvShebangCommand {
    fn new(command: &str, context: ExecContext, inherited: &ExecContext) -> Self {
        let search_modified = context.cwd != inherited.cwd
            || context.environment.get(std::ffi::OsStr::new("PATH"))
                != inherited.environment.get(std::ffi::OsStr::new("PATH"));
        Self {
            command: command.to_owned(),
            context,
            search_modified,
        }
    }

    fn resolve(&self) -> ExecInterpreter {
        if self.command.contains('/') {
            return ExecInterpreter::Candidate(self.context.path(Path::new(&self.command)));
        }
        if self.search_modified {
            let candidates = executable_paths_in_search_path(
                &self.command,
                &self.context.search_path(),
                self.context.cwd.as_deref(),
            );
            if !candidates.is_empty() {
                return ExecInterpreter::SearchCandidates(candidates);
            }
            return ExecInterpreter::Missing {
                command: self.command.clone(),
            };
        }
        ExecInterpreter::Candidate(PathBuf::from(&self.command))
    }
}

fn env_shebang_command(
    argument: &str,
    context: &ExecContext,
) -> std::result::Result<Option<EnvShebangCommand>, &'static str> {
    let Some(parsed) = env_shebang_argument_fields(argument, context) else {
        return Ok(None);
    };
    let options = EnvShebangOptions {
        ignore_environment: parsed.ignore_environment,
        ..EnvShebangOptions::default()
    };
    env_shebang_command_fields(parsed.fields, options, context)
}

fn env_shebang_argument_fields(argument: &str, context: &ExecContext) -> Option<EnvShebangFields> {
    if let Some(split) = env_split_string(argument) {
        return Some(EnvShebangFields {
            fields: split_env_split_string(split.value, context)?,
            ignore_environment: split.ignore_environment,
        });
    }
    Some(EnvShebangFields {
        fields: vec![argument.to_owned()],
        ignore_environment: false,
    })
}

fn env_split_string(arg: &str) -> Option<EnvSplitString<'_>> {
    if let Some((EnvLongOption::SplitString, Some(split))) = classify_env_long_option(arg) {
        return Some(EnvSplitString {
            value: split,
            ignore_environment: false,
        });
    }
    if !arg.starts_with('-') || arg.starts_with("--") {
        return None;
    }

    let mut idx = 1usize;
    let mut ignore_environment = false;
    while idx < arg.len() {
        let opt = arg[idx..].chars().next()?;
        idx += opt.len_utf8();
        match opt {
            'S' => {
                return Some(EnvSplitString {
                    value: &arg[idx..],
                    ignore_environment,
                });
            }
            'i' => {
                ignore_environment = true;
            }
            'v' => {}
            _ => return None,
        }
    }
    None
}

fn split_env_split_string(raw: &str, context: &ExecContext) -> Option<Vec<String>> {
    // GNU env expands ${VAR} while splitting -S. Environment-mutating options
    // parsed later, such as -i/--ignore-environment and -u/--unset, do not
    // affect this expansion pass.
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_field = false;
    let mut quote = None;
    let mut escaped = false;

    let mut idx = 0usize;
    while idx < raw.len() {
        let ch = raw[idx..].chars().next()?;
        idx += ch.len_utf8();
        if escaped {
            match ch {
                '_' if quote.is_none() => {
                    if in_field {
                        let _ = fields.push_mut(std::mem::take(&mut current));
                        in_field = false;
                    }
                }
                '_' => {
                    current.push(' ');
                    in_field = true;
                }
                'c' if quote.is_none() => {
                    escaped = false;
                    break;
                }
                'n' => {
                    current.push('\n');
                    in_field = true;
                }
                't' => {
                    current.push('\t');
                    in_field = true;
                }
                'r' => {
                    current.push('\r');
                    in_field = true;
                }
                'f' => {
                    current.push('\x0c');
                    in_field = true;
                }
                'v' => {
                    current.push('\x0b');
                    in_field = true;
                }
                '\\' | '\'' | '"' | '$' | '#' => {
                    current.push(ch);
                    in_field = true;
                }
                _ => return None,
            }
            escaped = false;
            continue;
        }
        // GNU env still recognizes escaped quotes and backslashes inside
        // single quotes; its other escape sequences remain literal there.
        if ch == '\\'
            && (quote != Some('\'') || raw[idx..].starts_with('\\') || raw[idx..].starts_with('\''))
        {
            escaped = true;
            continue;
        }
        if quote != Some('\'') && ch == '$' {
            match expand_env_split_variable(raw, &mut idx, context)? {
                EnvSplitExpansion::Value(value) => {
                    current.push_str(&value);
                    in_field = true;
                }
                EnvSplitExpansion::Unset => {}
            }
            continue;
        }
        if let Some(active_quote) = quote {
            if ch == active_quote {
                quote = None;
            } else {
                current.push(ch);
            }
            in_field = true;
            continue;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
            in_field = true;
            continue;
        }
        if ch == '#' && !in_field {
            break;
        }
        if ch.is_ascii_whitespace() {
            if in_field {
                let _ = fields.push_mut(std::mem::take(&mut current));
                in_field = false;
            }
            continue;
        }
        current.push(ch);
        in_field = true;
    }

    if escaped || quote.is_some() {
        return None;
    }
    if in_field {
        let _ = fields.push_mut(current);
    }
    Some(fields)
}

fn expand_env_split_variable(
    raw: &str,
    idx: &mut usize,
    context: &ExecContext,
) -> Option<EnvSplitExpansion> {
    if !raw[*idx..].starts_with('{') {
        return None;
    }
    let name_start = *idx + 1;
    let name_end = name_start + raw[name_start..].find('}')?;
    let name = &raw[name_start..name_end];
    if !is_env_split_variable_name(name) {
        return None;
    }
    *idx = name_end + 1;
    Some(match context.environment.get(std::ffi::OsStr::new(name)) {
        Some(value) => EnvSplitExpansion::Value(value.clone().into_string().ok()?),
        None => EnvSplitExpansion::Unset,
    })
}

fn is_env_split_variable_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && (bytes[0] == b'_' || bytes[0].is_ascii_alphabetic())
        && bytes[1..]
            .iter()
            .all(|byte| *byte == b'_' || byte.is_ascii_alphanumeric())
}

fn env_shebang_command_fields(
    mut fields: Vec<String>,
    mut options: EnvShebangOptions,
    inherited: &ExecContext,
) -> std::result::Result<Option<EnvShebangCommand>, &'static str> {
    let mut idx = 0usize;
    let mut split_steps = 0;

    while idx < fields.len() {
        let arg = fields[idx].as_str();
        idx += 1;
        if matches!(arg, "--" | "-") {
            let operands_start = if arg == "-" { idx - 1 } else { idx };
            return Ok(env_shebang_command_operands(
                &fields[operands_start..],
                options,
                inherited,
            ));
        }
        if arg.starts_with('-') {
            let action = if arg.starts_with("--") {
                env_long_option_action(arg, &fields, &mut idx, &mut options)
            } else {
                env_short_option_action(arg, &fields, &mut idx, &mut options)
            };
            match action {
                EnvOptionAction::Continue => continue,
                EnvOptionAction::Return(command) => return Ok(command),
                EnvOptionAction::Invalid => return Ok(None),
                EnvOptionAction::SplitString(split) => {
                    // Variables can expand back to the same -S argument. Keep
                    // reparsing iterative and bounded, including long options.
                    split_steps += 1;
                    if split_steps > 32 {
                        return Err("env split-string expansion exceeds 32 steps");
                    }
                    let Some(mut expanded) = split_env_split_string(&split, inherited) else {
                        return Ok(None);
                    };
                    expanded.extend(fields.drain(idx..));
                    fields = expanded;
                    idx = 0;
                    continue;
                }
            }
        }
        return Ok(env_shebang_command_operands(
            &fields[idx - 1..],
            options,
            inherited,
        ));
    }
    Ok(None)
}

fn env_long_option_action(
    arg: &str,
    fields: &[String],
    idx: &mut usize,
    options: &mut EnvShebangOptions,
) -> EnvOptionAction {
    let Some((option, value)) = classify_env_long_option(arg) else {
        return EnvOptionAction::Invalid;
    };

    match option {
        EnvLongOption::SplitString => {
            let split = if let Some(split) = value {
                split
            } else {
                let Some(split) = fields.get(*idx) else {
                    return EnvOptionAction::Continue;
                };
                *idx += 1;
                split.as_str()
            };
            EnvOptionAction::SplitString(split.to_owned())
        }
        EnvLongOption::IgnoreEnvironment => {
            if value.is_some() {
                return EnvOptionAction::Invalid;
            }
            options.ignore_environment = true;
            EnvOptionAction::Continue
        }
        EnvLongOption::Unset => {
            let name = if let Some(name) = value {
                name
            } else {
                let Some(name) = fields.get(*idx) else {
                    return EnvOptionAction::Continue;
                };
                *idx += 1;
                name.as_str()
            };
            options.unset_names.push(name.to_owned());
            EnvOptionAction::Continue
        }
        EnvLongOption::Chdir => {
            let dir = if let Some(dir) = value {
                dir
            } else {
                let Some(dir) = fields.get(*idx) else {
                    return EnvOptionAction::Invalid;
                };
                *idx += 1;
                dir.as_str()
            };
            options.chdir = Some(dir.to_owned());
            EnvOptionAction::Continue
        }
        EnvLongOption::Argv0 => {
            if value.is_none() {
                *idx = idx.saturating_add(1).min(fields.len());
            }
            EnvOptionAction::Continue
        }
        EnvLongOption::BlockSignal => validate_env_signal_option(value, true, options),
        EnvLongOption::DefaultSignal | EnvLongOption::IgnoreSignal => {
            validate_env_signal_option(value, false, options)
        }
        EnvLongOption::Help | EnvLongOption::Null | EnvLongOption::Version => {
            if value.is_some() {
                EnvOptionAction::Invalid
            } else {
                EnvOptionAction::Return(None)
            }
        }
        EnvLongOption::Debug | EnvLongOption::ListSignalHandling => {
            if value.is_some() {
                EnvOptionAction::Invalid
            } else {
                EnvOptionAction::Continue
            }
        }
    }
}

fn env_short_option_action(
    arg: &str,
    fields: &[String],
    idx: &mut usize,
    options: &mut EnvShebangOptions,
) -> EnvOptionAction {
    let mut chars = arg.char_indices();
    let _ = chars.next();
    for (offset, opt) in chars {
        let value_start = offset + opt.len_utf8();
        match opt {
            'i' => {
                options.ignore_environment = true;
            }
            'v' => {}
            '0' => return EnvOptionAction::Return(None),
            'u' => {
                let name = if value_start == arg.len() {
                    let Some(name) = fields.get(*idx) else {
                        return EnvOptionAction::Continue;
                    };
                    *idx += 1;
                    name.as_str()
                } else {
                    &arg[value_start..]
                };
                options.unset_names.push(name.to_owned());
                return EnvOptionAction::Continue;
            }
            'a' => {
                if value_start == arg.len() {
                    *idx = idx.saturating_add(1).min(fields.len());
                }
                return EnvOptionAction::Continue;
            }
            'C' => {
                if value_start < arg.len() {
                    options.chdir = Some(arg[value_start..].to_owned());
                } else if let Some(dir) = fields.get(*idx) {
                    options.chdir = Some(dir.to_owned());
                    *idx += 1;
                } else {
                    return EnvOptionAction::Invalid;
                }
                return EnvOptionAction::Continue;
            }
            'S' => {
                let split = if value_start < arg.len() {
                    &arg[value_start..]
                } else if let Some(split) = fields.get(*idx) {
                    *idx += 1;
                    split
                } else {
                    return EnvOptionAction::Continue;
                };
                return EnvOptionAction::SplitString(split.to_owned());
            }
            _ => return EnvOptionAction::Invalid,
        }
    }
    EnvOptionAction::Continue
}

fn env_shebang_command_operands(
    fields: &[String],
    mut options: EnvShebangOptions,
    inherited: &ExecContext,
) -> Option<EnvShebangCommand> {
    if options.invalid_signal_disposition {
        return None;
    }
    // GNU env accepts one leading '-' operand to clear the environment,
    // including after '--'. It also ends option parsing, unlike '-i'.
    let fields = if fields.first().is_some_and(|arg| arg == "-") {
        options.ignore_environment = true;
        &fields[1..]
    } else {
        fields
    };
    let mut context = inherited.clone();
    if options.ignore_environment {
        // GNU env skips unsets entirely when clearing the environment, even
        // names that would otherwise make unsetenv fail.
        context.environment.clear();
    } else {
        for name in &options.unset_names {
            if !valid_env_unset_name(name) {
                return None;
            }
            context.environment.remove(std::ffi::OsStr::new(name));
        }
    }
    for arg in fields.iter().map(String::as_str) {
        if let Some((name, value)) = arg.split_once('=') {
            context.environment.insert(name.into(), value.into());
            continue;
        }
        return finish_env_shebang_command(arg, context, inherited, options.chdir.as_deref());
    }
    None
}

fn finish_env_shebang_command(
    command: &str,
    mut options: ExecContext,
    inherited: &ExecContext,
    chdir: Option<&str>,
) -> Option<EnvShebangCommand> {
    // GNU env applies only the final -C/--chdir, relative to the inherited
    // working directory. Earlier directory arguments need not be accessible.
    if let Some(dir) = chdir {
        options.cwd = Some(env_chdir(dir, inherited)?);
    }
    Some(EnvShebangCommand::new(command, options, inherited))
}

fn classify_env_long_option(arg: &str) -> Option<(EnvLongOption, Option<&str>)> {
    let body = arg.strip_prefix("--")?;
    let (name, value) = body
        .split_once('=')
        .map_or((body, None), |(name, value)| (name, Some(value)));
    if name.is_empty() {
        return None;
    }

    let mut matches = ENV_LONG_OPTIONS
        .iter()
        .filter(|(_, canonical)| canonical.starts_with(name));
    let &(option, _) = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some((option, value))
}

fn valid_env_unset_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('=')
}

fn env_chdir(dir: &str, inherited: &ExecContext) -> Option<PathBuf> {
    if dir.is_empty() {
        return None;
    }
    let dir = inherited.path(Path::new(dir)).canonicalize().ok()?;
    dir.is_dir().then_some(dir)
}

fn validate_env_signal_option(
    value: Option<&str>,
    block_signal: bool,
    options: &mut EnvShebangOptions,
) -> EnvOptionAction {
    let Some(signals) = value else {
        if !block_signal {
            // Without a list, GNU env replaces all dispositions and ignores
            // errors for unchangeable signals, overriding earlier requests.
            options.invalid_signal_disposition = false;
        }
        return EnvOptionAction::Continue;
    };
    for signal in signals.split(',').filter(|signal| !signal.is_empty()) {
        let Some(number) = env_signal_number(signal) else {
            return EnvOptionAction::Invalid;
        };
        // As with RTMIN name parsing, this boundary comes from tino's linked
        // libc; an env binary linked against another libc can differ.
        let reserved = (32..libc::SIGRTMIN()).contains(&number);
        if block_signal {
            // Blocking KILL/STOP is tolerated, but libc's reserved signals
            // fail independently of later disposition options.
            if reserved {
                return EnvOptionAction::Invalid;
            }
        } else if reserved || number == libc::SIGKILL || number == libc::SIGSTOP {
            options.invalid_signal_disposition = true;
        }
    }
    EnvOptionAction::Continue
}

fn env_signal_number(raw: &str) -> Option<libc::c_int> {
    let signal = match raw.get(..3) {
        Some(prefix) if prefix.eq_ignore_ascii_case("SIG") => &raw[3..],
        _ => raw,
    };
    if let Some(number) = env_named_signal_number(signal) {
        return Some(number);
    }
    if let Some(number) = env_realtime_signal_number(signal) {
        return Some(number);
    }
    parse_env_unsigned_c_int(signal).filter(|number| valid_env_signal_number(*number))
}

fn env_named_signal_number(signal: &str) -> Option<libc::c_int> {
    let number = match signal.to_ascii_uppercase().as_str() {
        "HUP" => libc::SIGHUP,
        "INT" => libc::SIGINT,
        "QUIT" => libc::SIGQUIT,
        "ILL" => libc::SIGILL,
        "TRAP" => libc::SIGTRAP,
        "ABRT" | "IOT" => libc::SIGABRT,
        "BUS" => libc::SIGBUS,
        "FPE" => libc::SIGFPE,
        "KILL" => libc::SIGKILL,
        "USR1" => libc::SIGUSR1,
        "SEGV" => libc::SIGSEGV,
        "USR2" => libc::SIGUSR2,
        "PIPE" => libc::SIGPIPE,
        "ALRM" => libc::SIGALRM,
        "TERM" => libc::SIGTERM,
        "STKFLT" => libc::SIGSTKFLT,
        "CHLD" | "CLD" => libc::SIGCHLD,
        "CONT" => libc::SIGCONT,
        "STOP" => libc::SIGSTOP,
        "TSTP" => libc::SIGTSTP,
        "TTIN" => libc::SIGTTIN,
        "TTOU" => libc::SIGTTOU,
        "URG" => libc::SIGURG,
        "XCPU" => libc::SIGXCPU,
        "XFSZ" => libc::SIGXFSZ,
        "VTALRM" => libc::SIGVTALRM,
        "PROF" => libc::SIGPROF,
        "WINCH" => libc::SIGWINCH,
        "IO" | "POLL" => libc::SIGPOLL,
        "PWR" => libc::SIGPWR,
        "SYS" => libc::SIGSYS,
        _ => return None,
    };
    Some(number)
}

fn valid_env_signal_number(number: libc::c_int) -> bool {
    (1..=libc::SIGRTMAX()).contains(&number)
}

fn env_realtime_signal_number(signal: &str) -> Option<libc::c_int> {
    let rtmin = libc::SIGRTMIN();
    let rtmax = libc::SIGRTMAX();

    let signal = signal.to_ascii_uppercase();
    if signal == "RTMIN" {
        return Some(rtmin);
    }
    if signal == "RTMAX" {
        return Some(rtmax);
    }
    if let Some(offset) = signal
        .strip_prefix("RTMIN+")
        .and_then(parse_env_realtime_offset)
    {
        return rtmin
            .checked_add(offset)
            .filter(|number| (rtmin..=rtmax).contains(number));
    }
    if let Some(offset) = signal
        .strip_prefix("RTMAX-")
        .and_then(parse_env_realtime_offset)
    {
        return rtmax
            .checked_sub(offset)
            .filter(|number| (rtmin..=rtmax).contains(number));
    }
    None
}

fn parse_env_realtime_offset(raw: &str) -> Option<libc::c_int> {
    parse_env_unsigned_c_int(raw)
}

fn parse_env_unsigned_c_int(raw: &str) -> Option<libc::c_int> {
    if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

const fn executable_elf_machines() -> &'static [u16] {
    #[cfg(target_arch = "x86")]
    {
        &[3]
    }
    #[cfg(target_arch = "x86_64")]
    {
        &[62, 3]
    }
    #[cfg(target_arch = "arm")]
    {
        &[40]
    }
    #[cfg(target_arch = "aarch64")]
    {
        &[183, 40]
    }
    #[cfg(target_arch = "riscv64")]
    {
        &[243]
    }
    #[cfg(target_arch = "loongarch64")]
    {
        &[258]
    }
    #[cfg(target_arch = "powerpc")]
    {
        &[20]
    }
    #[cfg(target_arch = "powerpc64")]
    {
        &[21, 20]
    }
    #[cfg(target_arch = "s390x")]
    {
        &[22]
    }
    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x",
    )))]
    {
        &[]
    }
}

fn elf_machine_may_execute(machine: u16) -> bool {
    let machines = executable_elf_machines();
    machines.is_empty() || machines.contains(&machine)
}

const fn elf_data_may_execute(little_endian: bool) -> bool {
    cfg_select! {
        target_endian = "little" => {
            little_endian
        }
        target_endian = "big" => {
            !little_endian
        }
    }
}

fn read_elf_interpreter_from_file(file: &File, path: &Path) -> Result<ElfInterpreter> {
    const EI_CLASS: usize = 4;
    const EI_DATA: usize = 5;
    const E_ENTRY: usize = 24;
    const E_TYPE: usize = 16;
    const E_MACHINE: usize = 18;
    const ET_EXEC: u16 = 2;
    const ET_DYN: u16 = 3;
    const ELFCLASS32: u8 = 1;
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const ELFDATA2MSB: u8 = 2;
    const PT_LOAD: u32 = 1;
    const PT_INTERP: u32 = 3;

    let header = read_file_prefix_from(file, 64)
        .with_context(|| format!("read ELF header '{}'", escape_path(path)))?;
    if header.len() < 0x34 || &header[..4] != ELF_MAGIC {
        return Ok(ElfInterpreter::Invalid);
    }

    let little_endian = match header[EI_DATA] {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        _ => return Ok(ElfInterpreter::Invalid),
    };
    if !elf_data_may_execute(little_endian) {
        return Ok(ElfInterpreter::Invalid);
    }

    let e_type = read_u16(&header, E_TYPE, little_endian)?;
    if !matches!(e_type, ET_EXEC | ET_DYN) {
        return Ok(ElfInterpreter::Invalid);
    }
    let e_machine = read_u16(&header, E_MACHINE, little_endian)?;
    if !elf_machine_may_execute(e_machine) {
        return Ok(ElfInterpreter::Invalid);
    }

    let class = header[EI_CLASS];
    let min_header_len = match class {
        ELFCLASS32 => 0x34,
        ELFCLASS64 => 0x40,
        _ => return Ok(ElfInterpreter::Invalid),
    };
    if header.len() < min_header_len {
        return Ok(ElfInterpreter::Invalid);
    }

    let (phoff, phentsize, phnum, expected_phentsize, entry) = match class {
        ELFCLASS32 => (
            match read_u32(&header, 28, little_endian) {
                Ok(value) => value as usize,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
            match read_u16(&header, 42, little_endian) {
                Ok(value) => value as usize,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
            match read_u16(&header, 44, little_endian) {
                Ok(value) => value as usize,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
            32usize,
            match read_u32(&header, E_ENTRY, little_endian) {
                Ok(value) => u64::from(value),
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
        ),
        ELFCLASS64 => (
            match read_u64_usize(&header, 32, little_endian, "ELF program header offset") {
                Ok(value) => value,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
            match read_u16(&header, 54, little_endian) {
                Ok(value) => value as usize,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
            match read_u16(&header, 56, little_endian) {
                Ok(value) => value as usize,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
            56usize,
            match read_u64(&header, E_ENTRY, little_endian) {
                Ok(value) => value,
                Err(_) => return Ok(ElfInterpreter::Invalid),
            },
        ),
        _ => return Ok(ElfInterpreter::Invalid),
    };
    // Linux requires the native ELF program-header size, not an extensible
    // stride. Rejected files need execvp's shell fallback grant.
    if phentsize != expected_phentsize {
        return Ok(ElfInterpreter::Invalid);
    }

    let Some(phdr_len) = phentsize.checked_mul(phnum) else {
        return Ok(ElfInterpreter::Invalid);
    };
    if phdr_len > ELF_PROGRAM_HEADER_TABLE_MAX_LEN {
        return Ok(ElfInterpreter::Invalid);
    }
    let mut phdrs = vec![0u8; phdr_len];
    if let Err(err) = read_exact_file_at(file, &mut phdrs, phoff as u64) {
        return if elf_read_error_is_invalid(&err) {
            Ok(ElfInterpreter::Invalid)
        } else {
            Err(err).with_context(|| format!("read ELF program headers '{}'", escape_path(path)))
        };
    }

    let file_len = file
        .metadata()
        .with_context(|| format!("inspect ELF file '{}'", escape_path(path)))?
        .len();
    let mut has_load_segment = false;
    let mut has_executable_entry_load_segment = false;
    let mut detected_interpreter = None;
    for idx in 0..phnum {
        let Some(start) = idx.checked_mul(phentsize) else {
            return Ok(ElfInterpreter::Invalid);
        };
        let Ok(p_type) = read_u32(&phdrs, start, little_endian) else {
            return Ok(ElfInterpreter::Invalid);
        };
        if p_type != PT_LOAD && p_type != PT_INTERP {
            continue;
        }
        // Linux uses the first PT_INTERP. Later entries are ignored, including
        // invalid ranges, and must not replace or broaden the loader grant.
        if p_type == PT_INTERP && detected_interpreter.is_some() {
            continue;
        }

        let (offset, filesz, vaddr, memsz, flags) = if class == ELFCLASS32 {
            (
                match read_u32(&phdrs, start + 4, little_endian) {
                    Ok(value) => value as usize,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u32(&phdrs, start + 16, little_endian) {
                    Ok(value) => value as usize,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u32(&phdrs, start + 8, little_endian) {
                    Ok(value) => u64::from(value),
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u32(&phdrs, start + 20, little_endian) {
                    Ok(value) => u64::from(value),
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u32(&phdrs, start + 24, little_endian) {
                    Ok(value) => value,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
            )
        } else {
            (
                match read_u64_usize(&phdrs, start + 8, little_endian, "ELF segment offset") {
                    Ok(value) => value,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u64_usize(&phdrs, start + 32, little_endian, "ELF segment size") {
                    Ok(value) => value,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u64(&phdrs, start + 16, little_endian) {
                    Ok(value) => value,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u64(&phdrs, start + 40, little_endian) {
                    Ok(value) => value,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
                match read_u32(&phdrs, start + 4, little_endian) {
                    Ok(value) => value,
                    Err(_) => return Ok(ElfInterpreter::Invalid),
                },
            )
        };
        if p_type == PT_LOAD {
            // File-backed mappings may extend past EOF. The executable can
            // still run if it never accesses those pages; only PT_INTERP must
            // be fully readable here to discover the loader.
            has_load_segment = true;
            if !elf_load_segment_is_valid(filesz, vaddr, memsz) {
                return Ok(ElfInterpreter::Invalid);
            }
            if elf_entry_is_in_executable_load_segment(entry, vaddr, memsz, flags) {
                has_executable_entry_load_segment = true;
            }
            continue;
        }
        if filesz == 0
            || filesz > ELF_INTERPRETER_MAX_LEN
            || !elf_file_range_is_valid(offset, filesz, file_len)
        {
            return Ok(ElfInterpreter::Invalid);
        }
        let mut interp = vec![0u8; filesz];
        if let Err(err) = read_exact_file_at(file, &mut interp, offset as u64) {
            return if elf_read_error_is_invalid(&err) {
                Ok(ElfInterpreter::Invalid)
            } else {
                Err(err).with_context(|| format!("read ELF interpreter '{}'", escape_path(path)))
            };
        }
        let Some(interpreter_path) = elf_interpreter_path(&interp) else {
            return Ok(ElfInterpreter::Invalid);
        };
        if interpreter_path.is_empty() {
            return Ok(ElfInterpreter::Invalid);
        }
        detected_interpreter = Some(PathBuf::from(OsString::from_vec(interpreter_path.to_vec())));
    }

    if !has_load_segment || (detected_interpreter.is_none() && !has_executable_entry_load_segment) {
        return Ok(ElfInterpreter::Invalid);
    }
    Ok(detected_interpreter.map_or(ElfInterpreter::NoInterpreter, ElfInterpreter::Interpreter))
}

fn elf_load_segment_is_valid(filesz: usize, vaddr: u64, memsz: u64) -> bool {
    u64::try_from(filesz).is_ok_and(|filesz| filesz <= memsz) && vaddr.checked_add(memsz).is_some()
}

fn elf_entry_is_in_executable_load_segment(entry: u64, vaddr: u64, memsz: u64, flags: u32) -> bool {
    const PF_X: u32 = 1;

    flags & PF_X != 0
        && memsz > 0
        && vaddr
            .checked_add(memsz)
            .is_some_and(|end| (vaddr..end).contains(&entry))
}

fn elf_read_error_is_invalid(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::InvalidInput | io::ErrorKind::UnexpectedEof
    )
}

fn elf_file_range_is_valid(offset: usize, filesz: usize, file_len: u64) -> bool {
    let Ok(offset) = u64::try_from(offset) else {
        return false;
    };
    let Ok(filesz) = u64::try_from(filesz) else {
        return false;
    };
    offset
        .checked_add(filesz)
        .is_some_and(|end| end <= file_len)
}

fn read_exact_file_at(file: &File, buf: &mut [u8], offset: u64) -> io::Result<()> {
    let mut len = 0usize;
    while len < buf.len() {
        let read_offset = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "file offset overflow"))?;
        match file.read_at(&mut buf[len..], read_offset) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "unexpected EOF",
                ));
            }
            Ok(read) => len += read,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        }
    }
    Ok(())
}

fn parse_elf_interpreter(bytes: &[u8]) -> Result<Option<String>> {
    const EI_CLASS: usize = 4;
    const EI_DATA: usize = 5;
    const ELFCLASS32: u8 = 1;
    const ELFCLASS64: u8 = 2;
    const ELFDATA2LSB: u8 = 1;
    const ELFDATA2MSB: u8 = 2;
    const PT_INTERP: u32 = 3;

    if bytes.len() < 0x34 || &bytes[..4] != ELF_MAGIC {
        return Ok(None);
    }

    let little_endian = match bytes[EI_DATA] {
        ELFDATA2LSB => true,
        ELFDATA2MSB => false,
        _ => return Ok(None),
    };

    let (phoff, phentsize, phnum, min_phentsize) = match bytes[EI_CLASS] {
        ELFCLASS32 => (
            read_u32(bytes, 28, little_endian)? as usize,
            read_u16(bytes, 42, little_endian)? as usize,
            read_u16(bytes, 44, little_endian)? as usize,
            32usize,
        ),
        ELFCLASS64 => (
            read_u64_usize(bytes, 32, little_endian, "ELF program header offset")?,
            read_u16(bytes, 54, little_endian)? as usize,
            read_u16(bytes, 56, little_endian)? as usize,
            56usize,
        ),
        _ => return Ok(None),
    };
    if phentsize < min_phentsize {
        bail!("ELF program header entry too small");
    }

    for idx in 0..phnum {
        let start = idx
            .checked_mul(phentsize)
            .and_then(|offset| phoff.checked_add(offset))
            .context("ELF program header offset overflow")?;
        let end = start
            .checked_add(phentsize)
            .context("ELF program header offset overflow")?;
        if end > bytes.len() {
            bail!("ELF program header exceeds file size");
        }
        let p_type = read_u32(bytes, start, little_endian)?;
        if p_type != PT_INTERP {
            continue;
        }

        let (offset, filesz) = if bytes[EI_CLASS] == ELFCLASS32 {
            (
                read_u32(bytes, start + 4, little_endian)? as usize,
                read_u32(bytes, start + 16, little_endian)? as usize,
            )
        } else {
            (
                read_u64_usize(
                    bytes,
                    start + 8,
                    little_endian,
                    "ELF interpreter segment offset",
                )?,
                read_u64_usize(
                    bytes,
                    start + 32,
                    little_endian,
                    "ELF interpreter segment size",
                )?,
            )
        };
        let end = offset
            .checked_add(filesz)
            .context("ELF interpreter segment offset overflow")?;
        if end > bytes.len() {
            bail!("ELF interpreter segment exceeds file size");
        }
        let interp = &bytes[offset..end];
        let interpreter_path =
            elf_interpreter_path(interp).context("ELF interpreter path is not NUL-terminated")?;
        let interpreter = std::str::from_utf8(interpreter_path)
            .context("ELF interpreter path is not valid UTF-8")?
            .to_string();
        if interpreter.is_empty() {
            return Ok(None);
        }
        return Ok(Some(interpreter));
    }

    Ok(None)
}

fn elf_interpreter_path(interp: &[u8]) -> Option<&[u8]> {
    let nul = interp.iter().position(|byte| *byte == 0)?;
    Some(&interp[..nul])
}

fn read_u16(bytes: &[u8], offset: usize, little_endian: bool) -> Result<u16> {
    let slice = read_elf_bytes(bytes, offset, 2, "ELF header")?;
    let mut raw = [0u8; 2];
    raw.copy_from_slice(slice);
    Ok(if little_endian {
        u16::from_le_bytes(raw)
    } else {
        u16::from_be_bytes(raw)
    })
}

fn read_u32(bytes: &[u8], offset: usize, little_endian: bool) -> Result<u32> {
    let slice = read_elf_bytes(bytes, offset, 4, "ELF header")?;
    let mut raw = [0u8; 4];
    raw.copy_from_slice(slice);
    Ok(if little_endian {
        u32::from_le_bytes(raw)
    } else {
        u32::from_be_bytes(raw)
    })
}

fn read_u64(bytes: &[u8], offset: usize, little_endian: bool) -> Result<u64> {
    let slice = read_elf_bytes(bytes, offset, 8, "ELF header")?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(slice);
    Ok(if little_endian {
        u64::from_le_bytes(raw)
    } else {
        u64::from_be_bytes(raw)
    })
}

fn read_u64_usize(
    bytes: &[u8],
    offset: usize,
    little_endian: bool,
    context: &str,
) -> Result<usize> {
    usize::try_from(read_u64(bytes, offset, little_endian)?)
        .with_context(|| format!("{context} exceeds addressable size"))
}

fn read_elf_bytes<'a>(
    bytes: &'a [u8],
    offset: usize,
    len: usize,
    context: &str,
) -> Result<&'a [u8]> {
    let end = offset
        .checked_add(len)
        .with_context(|| format!("{context} offset overflow"))?;
    bytes
        .get(offset..end)
        .with_context(|| format!("{context} read out of bounds"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownDeadline {
    At(Instant),
    Never,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WaitLoop {
    Continue,
    Break,
}

impl ShutdownDeadline {
    fn after(now: Instant, millis: u64) -> Self {
        now.checked_add(Duration::from_millis(millis))
            .map_or(Self::Never, Self::At)
    }

    fn remaining(self, now: Instant) -> Duration {
        match self {
            Self::At(deadline) => deadline.saturating_duration_since(now),
            Self::Never => Duration::MAX,
        }
    }

    fn poll_timeout(self) -> PollTimeout {
        PollTimeout::try_from(self.remaining(Instant::now())).unwrap_or(PollTimeout::MAX)
    }

    fn expired(self) -> bool {
        self.remaining(Instant::now()).is_zero()
    }
}

const SIGNAL_BATCH_LIMIT: usize = 64;

fn supervise_child(
    cli: &Cli,
    expect_zero: &ExitCodeRemap,
    child_pid: Pid,
    use_pgroup: bool,
    signal_fd: &mut SignalFd,
    foreground_tty: Option<&ForegroundTtyRestore>,
) -> Result<i32> {
    let mut main_exit: Option<i32> = None;
    let result = supervise_child_inner(
        cli,
        expect_zero,
        child_pid,
        use_pgroup,
        signal_fd,
        &mut main_exit,
        foreground_tty,
    );
    if result.is_err() {
        if main_exit.is_none() {
            // Until reaped, the child reserves its PID and initial group ID.
            cleanup_failed_supervision(child_pid, use_pgroup);
        }
        if use_pgroup {
            cleanup_failed_process_group(child_pid, cli.grace_ms);
        }
    }
    result
}

fn cleanup_failed_supervision(child_pid: Pid, use_pgroup: bool) {
    if use_pgroup {
        send_signal(true, child_pid, SIGKILL as libc::c_int);
    }
    // The main child may have left its original group since startup.
    if let Err(err) = send_process_signal(child_pid, SIGKILL as libc::c_int)
        && err != Errno::ESRCH
    {
        logging::warn(format_args!(
            "terminate child after supervision failure: {err}"
        ));
        return;
    }
    // Do not depend on the failed poll/signalfd path, or reap the caller's
    // unrelated children with waitpid(-1).
    loop {
        match waitpid_child(child_pid) {
            Ok(WaitStatus::Exited(..) | WaitStatus::Signaled(..)) | Err(Errno::ECHILD) => break,
            Ok(_) | Err(Errno::EINTR) => continue,
            Err(err) => {
                logging::warn(format_args!("reap child after supervision failure: {err}"));
                break;
            }
        }
    }
}

fn cleanup_failed_process_group(child_pgid: Pid, grace_ms: u64) {
    let deadline = ShutdownDeadline::after(Instant::now(), grace_ms);
    let mut killed = false;
    loop {
        match waitpid_group_nohang(child_pgid) {
            Ok(WaitStatus::StillAlive) => {}
            Ok(_) | Err(Errno::EINTR) => continue,
            Err(Errno::ECHILD) => return,
            Err(err) => {
                logging::warn(format_args!(
                    "reap child group after supervision failure: {err}"
                ));
                return;
            }
        }
        if !killed {
            // A live, waitable child proves this group is still ours. Merely
            // retaining the reaped main child's numeric PGID would not: it may
            // have been reused by an unrelated process after the group exited.
            if let Err(err) = send_process_group_signal(child_pgid, SIGKILL as libc::c_int) {
                logging::warn(format_args!(
                    "terminate child group after supervision failure: {err}"
                ));
                return;
            }
            killed = true;
            continue;
        }
        let remaining = deadline.remaining(Instant::now());
        if remaining.is_zero() {
            logging::warn(format_args!(
                "child group still waitable after supervision failure cleanup"
            ));
            return;
        }
        // The ordinary poll/signalfd path has failed. Keep this final reap
        // bounded, including when group signaling could reach only some members.
        std::thread::sleep(remaining.min(Duration::from_millis(10)));
    }
}

fn supervise_child_inner(
    cli: &Cli,
    expect_zero: &ExitCodeRemap,
    child_pid: Pid,
    use_pgroup: bool,
    signal_fd: &mut SignalFd,
    main_exit: &mut Option<i32>,
    foreground_tty: Option<&ForegroundTtyRestore>,
) -> Result<i32> {
    let mut shutdown_deadline: Option<ShutdownDeadline> = None;
    let mut sigkill_sent = false;
    let mut fds = [PollFd::new(signal_fd.as_fd(), PollFlags::POLLIN)];

    loop {
        let poll_timeout = match (shutdown_deadline, sigkill_sent, main_exit.is_some()) {
            (Some(deadline), false, false) => deadline.poll_timeout(),
            _ => PollTimeout::BLOCK,
        };
        match poll_fds(&mut fds, poll_timeout) {
            Ok(()) => {}
            Err(err) => {
                if err == Errno::EINTR {
                    continue;
                }
                return Err(err).context("poll");
            }
        }
        let events = fds[0].revents().unwrap_or_else(PollFlags::empty);
        if signal_fd_poll_failed(events) {
            bail!("signal fd poll failed with events {:?}", events);
        }
        let mut suspend_requested = false;
        if events.contains(PollFlags::POLLIN) {
            let mut budget = SIGNAL_BATCH_LIMIT;
            while let Some(info) = read_forwardable_signal(signal_fd, &mut budget)? {
                let sig = info.ssi_signo.cast_signed();
                if sig == SIGCHLD as libc::c_int {
                    if let Some(stopped) = handle_sigchld(cli, child_pid, main_exit)? {
                        suspend_requested = stopped;
                    }
                } else if sig == SIGTTIN as libc::c_int || sig == SIGTTOU as libc::c_int {
                    logging::debug(format_args!("ignoring signal {}", sig));
                } else {
                    if sig == libc::SIGCONT {
                        suspend_requested = false;
                        if let Some(tty) = foreground_tty {
                            tty.resume_job();
                        }
                    }
                    forward_to_main_child(use_pgroup, child_pid, sig);
                    if is_termination_signal(sig) && main_exit.is_none() && !sigkill_sent {
                        let now = Instant::now();
                        shutdown_deadline = Some(match shutdown_deadline {
                            None => ShutdownDeadline::after(now, cli.grace_ms),
                            Some(_) => ShutdownDeadline::At(now),
                        });
                    }
                }
                if main_exit.is_some()
                    || (!sigkill_sent && shutdown_deadline.is_some_and(ShutdownDeadline::expired))
                {
                    break;
                }
            }
        }
        if let Some(ShutdownDeadline::At(deadline)) = shutdown_deadline
            && !sigkill_sent
            && main_exit.is_none()
            && Instant::now() >= deadline
        {
            logging::info(format_args!("grace period expired; sending SIGKILL"));
            forward_to_main_child(use_pgroup, child_pid, SIGKILL as libc::c_int);
            sigkill_sent = true;
        }
        if main_exit.is_some() {
            break;
        }
        if suspend_requested
            && shutdown_deadline.is_none()
            && let Some(tty) = foreground_tty
            && tty.suspend_job()
            && !signal_fd.accepts(libc::SIGCONT)
        {
            // A caller-owned pending CONT excludes this signal from the
            // signalfd. Returning from our stop still proves continuation,
            // so resume the job without consuming the caller's signal.
            tty.resume_job();
            forward_to_main_child(use_pgroup, child_pid, libc::SIGCONT);
        }
    }

    let main_exit = main_exit.context("main child exit status was not observed")?;
    let final_exit = compute_exit_code(main_exit, expect_zero);
    // Descendants share the shutdown deadline started by the first termination
    // signal. Only a natural main-child exit starts a fresh cleanup grace period.
    let cleanup_deadline =
        shutdown_deadline.unwrap_or_else(|| ShutdownDeadline::after(Instant::now(), cli.grace_ms));

    if use_pgroup {
        logging::info(format_args!("sending SIGTERM to PGID"));
        send_signal(true, child_pid, SIGTERM as libc::c_int);
        if !wait_for_cleanup(child_pid, true, cli, signal_fd, cleanup_deadline, true)? {
            logging::info(format_args!("process group still alive; sending SIGKILL"));
            send_signal(true, child_pid, SIGKILL as libc::c_int);
            // Allow reaping after SIGKILL without delaying when SIGKILL is sent.
            let reap_deadline = ShutdownDeadline::after(Instant::now(), cli.grace_ms);
            let group_gone =
                wait_for_cleanup(child_pid, true, cli, signal_fd, reap_deadline, false)?;
            if !group_gone {
                logging::warn(format_args!(
                    "process group still alive after SIGKILL wait of {} ms",
                    cli.grace_ms
                ));
            }
        }
    } else {
        let _ = wait_for_cleanup(child_pid, false, cli, signal_fd, cleanup_deadline, true)?;
    }

    logging::info(format_args!("exiting with {}", final_exit));
    Ok(final_exit)
}

fn forward_to_main_child(use_pgroup: bool, child_pid: Pid, sig: libc::c_int) {
    // The main command can join another group after startup. Keep forwarding
    // to the original workload group, and also reach the moved main command.
    // This helper is only used before reaping, while its PID is still reserved.
    send_signal(use_pgroup, child_pid, sig);
    if use_pgroup {
        match process_group_of(child_pid) {
            Ok(group) if group == child_pid => {}
            Err(Errno::ESRCH) => {}
            Ok(_) => send_signal(false, child_pid, sig),
            Err(err) => {
                logging::warn(format_args!(
                    "query main child process group before direct forwarding: {err}"
                ));
                send_signal(false, child_pid, sig);
            }
        }
    }
}

const fn signal_fd_poll_failed(events: PollFlags) -> bool {
    events.intersects(PollFlags::POLLERR)
        || events.intersects(PollFlags::POLLHUP)
        || events.intersects(PollFlags::POLLNVAL)
}

const fn is_termination_signal(sig: libc::c_int) -> bool {
    sig == SIGTERM as libc::c_int || sig == SIGINT as libc::c_int || sig == SIGQUIT as libc::c_int
}

fn log_reaped_secondary(pid: Pid, warn_on_reap: bool) {
    if warn_on_reap {
        logging::warn(format_args!("reaped secondary PID {}", pid));
    } else {
        logging::debug(format_args!("reaped secondary PID {}", pid));
    }
}

fn log_stopped_child(pid: Pid, sig: i32, warn_on_reap: bool) {
    if warn_on_reap {
        logging::warn(format_args!("child PID {} stopped by signal {}", pid, sig));
    } else {
        logging::debug(format_args!("child PID {} stopped by signal {}", pid, sig));
    }
}

fn handle_sigchld(cli: &Cli, child_pid: Pid, main_exit: &mut Option<i32>) -> Result<Option<bool>> {
    let mut main_stopped = None;
    loop {
        match waitpid_any_nohang() {
            Ok(status) => {
                match status {
                    WaitStatus::Stopped(pid, _) if pid == child_pid => main_stopped = Some(true),
                    WaitStatus::Continued(pid) if pid == child_pid => main_stopped = Some(false),
                    _ => {}
                }
                match handle_wait_status(status, cli, child_pid, main_exit) {
                    WaitLoop::Continue => continue,
                    WaitLoop::Break => break,
                }
            }
            Err(Errno::ECHILD) if main_exit.is_some() => break,
            Err(Errno::ECHILD) => {
                bail!("main child is no longer waitable before its exit status was observed")
            }
            Err(Errno::EINTR) => continue,
            Err(e) => bail!("waitpid: {e}"),
        }
    }
    Ok(if main_exit.is_some() {
        Some(false)
    } else {
        main_stopped
    })
}

fn handle_wait_status(
    status: WaitStatus,
    cli: &Cli,
    child_pid: Pid,
    main_exit: &mut Option<i32>,
) -> WaitLoop {
    let action = wait_status_drain_action(status);
    match status {
        WaitStatus::Exited(pid, code) if pid == child_pid => {
            *main_exit = Some(code);
        }
        WaitStatus::Signaled(pid, sig, _) if pid == child_pid => {
            *main_exit = Some(128 + sig);
        }
        status => log_wait_status(status, cli.warn_on_reap),
    }
    action
}

fn log_wait_status(status: WaitStatus, warn_on_reap: bool) {
    match status {
        WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
            log_reaped_secondary(pid, warn_on_reap);
        }
        WaitStatus::Stopped(pid, sig) => {
            log_stopped_child(pid, sig, warn_on_reap);
        }
        WaitStatus::Continued(_) | WaitStatus::StillAlive => {}
    }
}

const fn wait_status_drain_action(status: WaitStatus) -> WaitLoop {
    match status {
        WaitStatus::StillAlive => WaitLoop::Break,
        WaitStatus::Exited(..)
        | WaitStatus::Signaled(..)
        | WaitStatus::Stopped(..)
        | WaitStatus::Continued(..) => WaitLoop::Continue,
    }
}

fn compute_exit_code(code: i32, expect_zero: &ExitCodeRemap) -> i32 {
    if u8::try_from(code).is_ok_and(|candidate| expect_zero[candidate as usize]) {
        0
    } else {
        code
    }
}

fn wait_for_cleanup(
    child_pid: Pid,
    use_pgroup: bool,
    cli: &Cli,
    signal_fd: &mut SignalFd,
    deadline: ShutdownDeadline,
    interruptible: bool,
) -> Result<bool> {
    loop {
        let mut terminate = false;
        // Bound each batch so a continuous stream cannot postpone cleanup.
        let mut budget = SIGNAL_BATCH_LIMIT;
        while let Some(info) = read_forwardable_signal(signal_fd, &mut budget)? {
            let sig = info.ssi_signo.cast_signed();
            if sig == SIGCHLD as libc::c_int
                || sig == SIGTTIN as libc::c_int
                || sig == SIGTTOU as libc::c_int
            {
                continue;
            }
            if use_pgroup {
                send_signal(true, child_pid, sig);
            }
            terminate |= is_termination_signal(sig);
            if (interruptible && terminate) || deadline.expired() {
                break;
            }
        }
        let children_gone = reap_available_children(cli.warn_on_reap)?;
        let done = if use_pgroup {
            !process_group_exists(child_pid)
                .with_context(|| format!("query process group {child_pid}"))?
        } else {
            children_gone
        };
        if done {
            return Ok(true);
        }
        let remaining = deadline.remaining(Instant::now());
        if (interruptible && terminate) || remaining.is_zero() {
            return Ok(false);
        }
        // A group can contain processes we cannot waitpid, so periodically
        // check its existence even when no SIGCHLD arrives.
        let poll_timeout = PollTimeout::try_from(remaining.min(Duration::from_millis(10)))
            .unwrap_or(PollTimeout::MAX);
        let mut fds = [PollFd::new(signal_fd.as_fd(), PollFlags::POLLIN)];
        match poll_fds(&mut fds, poll_timeout) {
            Ok(()) => {}
            Err(Errno::EINTR) => continue,
            Err(err) => return Err(err).context("poll during child cleanup"),
        }
        if signal_fd_poll_failed(fds[0].revents().unwrap_or_else(PollFlags::empty)) {
            bail!("signal fd poll failed during child cleanup");
        }
    }
}

fn reap_available_children(warn_on_reap: bool) -> Result<bool> {
    loop {
        match waitpid_any_nohang() {
            Ok(status) => {
                log_wait_status(status, warn_on_reap);
                match wait_status_drain_action(status) {
                    WaitLoop::Continue => continue,
                    WaitLoop::Break => return Ok(false),
                }
            }
            Err(Errno::ECHILD) => return Ok(true),
            Err(Errno::EINTR) => continue,
            Err(e) => bail!("waitpid: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform;
    use std::sync::{
        Mutex, MutexGuard, OnceLock,
        atomic::{AtomicU64, Ordering},
    };

    struct EnvVarGuard {
        name: String,
        original: Option<OsString>,
        _lock: MutexGuard<'static, ()>,
    }

    impl EnvVarGuard {
        fn set(name: impl Into<String>, value: OsString) -> Self {
            Self::replace(name, Some(value))
        }

        fn unset(name: impl Into<String>) -> Self {
            Self::replace(name, None)
        }

        fn replace(name: impl Into<String>, value: Option<OsString>) -> Self {
            static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            let lock = ENV_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .expect("environment lock poisoned");
            let name = name.into();
            let original = std::env::var_os(&name);
            match value {
                Some(value) => unsafe {
                    std::env::set_var(&name, value);
                },
                None => unsafe {
                    std::env::remove_var(&name);
                },
            }
            Self {
                name,
                original,
                _lock: lock,
            }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            match self.original.take() {
                Some(value) => unsafe {
                    std::env::set_var(&self.name, value);
                },
                None => unsafe {
                    std::env::remove_var(&self.name);
                },
            }
        }
    }

    struct PathEnvGuard {
        original: ExecSearchPathOverride,
    }

    impl PathEnvGuard {
        fn set(value: OsString) -> Self {
            Self::replace(ExecSearchPathOverride::Value(value))
        }

        fn unset() -> Self {
            Self::replace(ExecSearchPathOverride::Default)
        }

        fn replace(value: ExecSearchPathOverride) -> Self {
            let original = TEST_EXEC_SEARCH_PATH.with(|path| path.replace(value));
            Self { original }
        }
    }

    impl Drop for PathEnvGuard {
        fn drop(&mut self) {
            let original = std::mem::replace(&mut self.original, ExecSearchPathOverride::Inherit);
            TEST_EXEC_SEARCH_PATH.with(|path| {
                let _ = path.replace(original);
            });
        }
    }

    pub(super) fn unique_env_name(prefix: &str) -> String {
        static NEXT_ENV_ID: AtomicU64 = AtomicU64::new(0);

        let id = NEXT_ENV_ID.fetch_add(1, Ordering::Relaxed);
        format!("TINO_TEST_{prefix}_{}_{id}", std::process::id())
    }

    #[test]
    fn signal_lookup_accepts_variants_with_or_without_prefix() {
        assert_eq!(
            super::signals::signal_by_name("TERM"),
            Some(Signal::SIGTERM)
        );
        assert_eq!(
            super::signals::signal_by_name("SIGTERM"),
            Some(Signal::SIGTERM)
        );
        assert_eq!(
            super::signals::signal_by_name("TSTP"),
            Some(Signal::SIGTSTP)
        );
    }

    #[test]
    fn signal_lookup_rejects_unknown_signal() {
        assert!(super::signals::signal_by_name("NOPE").is_none());
    }

    #[test]
    fn init_logging_is_idempotent() {
        let _lock = crate::logging::test_lock();

        platform::init_logging(0);
        platform::init_logging(1);
        crate::logging::reset_for_test();
    }

    #[test]
    fn reaping_without_children_succeeds() {
        let _lock = CHILD_TEST_LOCK.lock().unwrap();
        assert!(reap_available_children(false).unwrap());
    }

    #[test]
    fn sigchld_without_waitable_main_child_errors() {
        let _lock = CHILD_TEST_LOCK.lock().unwrap();
        let mut main_exit = None;
        let err = handle_sigchld(&Cli::default(), Pid::from_raw(i32::MAX), &mut main_exit)
            .expect_err("missing main child status must be explicit");

        assert!(
            format!("{err:#}").contains("main child is no longer waitable"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn write_no_dev_alone_does_not_request_write_restriction() {
        let cli = Cli {
            write_no_dev: true,
            ..Cli::default()
        };

        assert!(build_landlock_config(&cli).unwrap().is_none());
    }

    #[test]
    fn write_no_dev_modifies_write_restriction_when_requested() {
        let cli = Cli {
            write_restrict: true,
            write_no_dev: true,
            ..Cli::default()
        };

        let config = build_landlock_config(&cli)
            .unwrap()
            .expect("write restriction config");
        assert!(config.write_requested);
        assert!(config.no_dev);
    }

    #[test]
    fn build_landlock_config_rejects_manual_zero_tcp_ports() {
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
            let Err(err) = build_landlock_config(&cli) else {
                panic!("zero TCP port must fail");
            };
            let message = format!("{err:#}");

            assert!(
                message.contains("expected 1-65535"),
                "unexpected zero-port error: {message}"
            );
        }
    }

    #[test]
    fn build_landlock_config_rejects_paths_with_surrounding_whitespace() {
        let cases = [
            (
                Cli {
                    write_allow: vec![" /tmp".into()],
                    ..Cli::default()
                },
                "--write-allow PATH cannot have surrounding whitespace",
            ),
            (
                Cli {
                    exec_allow: vec!["/bin/sh ".into()],
                    ..Cli::default()
                },
                "--exec-allow PATH cannot have surrounding whitespace",
            ),
            (
                Cli {
                    device_ioctl_allow: vec![" /dev/null ".into()],
                    ..Cli::default()
                },
                "--device-ioctl-allow PATH cannot have surrounding whitespace",
            ),
        ];

        for (cli, expected) in cases {
            let Err(err) = build_landlock_config(&cli) else {
                panic!("path with surrounding whitespace must fail");
            };
            let message = format!("{err:#}");

            assert!(
                message.contains(expected),
                "unexpected path whitespace error: {message}"
            );
        }
    }

    #[test]
    fn build_landlock_config_rejects_relative_allow_paths() {
        let cases = [
            (
                Cli {
                    write_allow: vec!["logs".into()],
                    ..Cli::default()
                },
                "--write-allow PATH must be absolute",
            ),
            (
                Cli {
                    exec_allow: vec!["./service".into()],
                    ..Cli::default()
                },
                "--exec-allow PATH must be absolute when it contains '/'",
            ),
            (
                Cli {
                    device_ioctl_allow: vec!["dev/null".into()],
                    ..Cli::default()
                },
                "--device-ioctl-allow PATH must be absolute",
            ),
        ];

        for (cli, expected) in cases {
            let Err(err) = build_landlock_config(&cli) else {
                panic!("relative landlock allow path must fail");
            };
            let message = format!("{err:#}");

            assert!(
                message.contains(expected),
                "unexpected relative allow path error: {message}"
            );
        }
    }

    #[test]
    fn exec_allow_symlink_stores_only_canonical_target() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-exec-allow-symlink-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create symlink test dir");
        let target = root.join("target");
        let link = root.join("link");
        std::fs::write(&target, b"not-an-elf\n").expect("write target");
        symlink(&target, &link).expect("create symlink");

        let cli = Cli {
            exec_allow: vec![link.to_string_lossy().into_owned()],
            ..Cli::default()
        };
        let config = build_landlock_config(&cli)
            .expect("build config")
            .expect("exec allow config");
        let allowed = config
            .exec_allow_paths
            .iter()
            .map(|path| path.as_c_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            allowed,
            vec![target.canonicalize().unwrap().display().to_string()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn landlock_explain_preserves_non_utf8_canonical_paths() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-landlock-explain-nonutf8-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create non-UTF-8 explain root");
        let target = root.join(OsString::from_vec(vec![b't', b'a', 0xff]));
        let link = root.join("link");
        std::fs::create_dir_all(&target).expect("create non-UTF-8 target");
        symlink(&target, &link).expect("create symlink");

        let cli = Cli {
            write_allow: vec![link.to_str().expect("link path is UTF-8").into()],
            ..Cli::default()
        };
        let explain = explain_landlock_config(&cli, &[])
            .expect("explain landlock config")
            .expect("landlock config");

        assert_eq!(explain.writable_dirs.len(), 1);
        assert!(
            explain.writable_dirs[0].contains(r"\xff"),
            "non-UTF-8 byte should be preserved as an escape: {:?}",
            explain.writable_dirs
        );
        assert!(
            !explain.writable_dirs[0].contains('\u{fffd}'),
            "explain output must not use lossy replacement characters: {:?}",
            explain.writable_dirs
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exec_allow_non_executable_file_skips_interpreter_probe() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-exec-allow-nonexec-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create non-exec test dir");
        let path = root.join("not-executable");
        let mut bytes = minimal_elf64();
        bytes[54..56].copy_from_slice(&1u16.to_le_bytes());
        std::fs::write(&path, bytes).expect("write invalid non-exec elf");
        let mut perms = std::fs::metadata(&path)
            .expect("stat invalid non-exec elf")
            .permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&path, perms).expect("chmod invalid non-exec elf");

        let cli = Cli {
            exec_allow: vec![path.to_string_lossy().into_owned()],
            ..Cli::default()
        };
        let config = build_landlock_config(&cli)
            .expect("non-executable exec allow path should not be probed as ELF")
            .expect("exec allow config");
        assert_eq!(config.exec_allow_paths.len(), 1);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_skips_missing_program() {
        let mut unique = PinnedPaths::new();

        insert_landlock_main_exec_path(&mut unique, "/definitely/missing/tino-test-binary")
            .expect("missing main program should be left to execvp");

        assert!(unique.is_empty());
    }

    #[test]
    fn main_exec_auto_allow_skips_non_executable_program_paths() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-nonexec-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create non-exec main test dir");
        let directory = root.join("directory");
        let file = root.join("file");
        let fifo = root.join("fifo");
        std::fs::create_dir_all(&directory).expect("create main command directory");
        std::fs::write(&file, b"not executable\n").expect("write non-executable main file");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o700) }, 0);
        let mut perms = std::fs::metadata(&file)
            .expect("stat non-executable main file")
            .permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&file, perms).expect("chmod non-executable main file");

        for path in [&directory, &file, &fifo] {
            let mut unique = PinnedPaths::new();
            insert_landlock_main_exec_path(&mut unique, &path.to_string_lossy())
                .expect("non-executable main path should be left to execvp");

            assert!(
                unique.is_empty(),
                "auto main exec allowlist must not broaden for {path:?}: {unique:?}"
            );
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_exec_allow_still_accepts_directory_paths() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-exec-dir-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create explicit exec directory");

        let cli = Cli {
            exec_allow: vec![root.to_string_lossy().into_owned()],
            ..Cli::default()
        };
        let config = build_landlock_config(&cli)
            .expect("explicit directory exec allow should build")
            .expect("exec allow config");
        let allowed = config
            .exec_allow_paths
            .iter()
            .map(|path| path.as_c_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert_eq!(
            allowed,
            vec![root.canonicalize().unwrap().display().to_string()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn landlock_config_reuses_resolved_command_for_auto_exec_allow() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir()
            .join(format!("tino-resolved-exec-{}-{nanos}", std::process::id(),));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create resolved exec test dir");
        let program = root.join("program");
        let helper = root.join("helper");
        for path in [&program, &helper] {
            std::fs::write(path, b"#!/bin/sh\n").expect("write executable fixture");
            let mut perms = std::fs::metadata(path)
                .expect("stat executable fixture")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(path, perms).expect("chmod executable fixture");
        }

        let cli = Cli {
            cmd: vec!["${BROKEN".into()],
            expand_env: true,
            exec_allow: vec![helper.to_string_lossy().into_owned()],
            ..Cli::default()
        };
        let effective_cmd = vec![program.to_string_lossy().into_owned()];

        let config = build_landlock_config_for_args(&cli, &effective_cmd)
            .expect("config builder must not re-expand the original command")
            .expect("exec restriction config");
        let allowed = config
            .exec_allow_paths
            .iter()
            .map(|path| path.as_c_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>();

        assert!(
            allowed.contains(&program.canonicalize().unwrap().display().to_string()),
            "resolved main command should be auto-allowed: {allowed:?}"
        );
        assert!(
            allowed.contains(&helper.canonicalize().unwrap().display().to_string()),
            "explicit helper should still be allowed: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_skips_missing_env_shebang_command() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let missing = format!(
            "definitely-missing-tino-interpreter-{}-{nanos}",
            std::process::id()
        );
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-missing-env-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create env shebang test dir");
        let script = root.join("script");
        std::fs::write(&script, format!("#!/usr/bin/env {missing}\n"))
            .expect("write env shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat env shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod env shebang script");

        let mut unique = PinnedPaths::new();
        insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
            .expect("missing shebang command should be left to child execution");
        let allowed = unique
            .keys()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>();

        assert!(
            allowed.contains(&script.canonicalize().unwrap().display().to_string()),
            "script itself must still be auto-allowed: {allowed:?}"
        );
        assert!(
            allowed.iter().all(|path| !path.contains(&missing)),
            "missing env shebang command must not be resolved from an unrelated path: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_skips_invalid_utf8_env_shebang_argument() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-invalid-env-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create invalid env shebang test dir");
        let script = root.join("script");
        std::fs::write(&script, b"#!/usr/bin/env python\xff\n")
            .expect("write invalid env shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat invalid env shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod invalid env shebang script");

        let mut unique = PinnedPaths::new();
        insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
            .expect("invalid env shebang argument should be left to child execution");
        let allowed = unique
            .keys()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>();

        assert!(
            allowed.contains(&script.canonicalize().unwrap().display().to_string()),
            "script itself must still be auto-allowed: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_respects_env_shebang_path_assignment() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-env-path-{}-{nanos}",
            std::process::id(),
        ));
        let parent_path_dir = root.join("parent-path");
        let shebang_path_dir = root.join("shebang-path");
        std::fs::create_dir_all(&parent_path_dir).expect("create parent PATH dir");
        std::fs::create_dir_all(&shebang_path_dir).expect("create shebang PATH dir");
        let parent_tool = parent_path_dir.join("python3");
        std::fs::write(&parent_tool, b"parent python\n").expect("write parent python");
        let mut perms = std::fs::metadata(&parent_tool)
            .expect("stat parent python")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&parent_tool, perms).expect("chmod parent python");

        let script = root.join("script");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env -S -i PATH={} python3\n",
                shebang_path_dir.display()
            ),
        )
        .expect("write env PATH shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat env PATH shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod env PATH shebang script");

        let _path = PathEnvGuard::set(parent_path_dir.as_os_str().to_os_string());
        let mut unique = PinnedPaths::new();
        insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
            .expect("missing shebang PATH command should not fall back to parent PATH");
        let allowed = unique
            .keys()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>();

        assert!(
            !allowed.contains(&parent_tool.canonicalize().unwrap().display().to_string()),
            "shebang PATH must not fall back to parent PATH: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_respects_env_unset_path() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-env-unset-path-{}-{nanos}",
            std::process::id(),
        ));
        let parent_path_dir = root.join("parent-path");
        std::fs::create_dir_all(&parent_path_dir).expect("create parent PATH dir");
        let parent_tool = parent_path_dir.join("python3");
        std::fs::write(&parent_tool, b"parent python\n").expect("write parent python");
        let mut perms = std::fs::metadata(&parent_tool)
            .expect("stat parent python")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&parent_tool, perms).expect("chmod parent python");
        let parent_tool = parent_tool
            .canonicalize()
            .expect("canonicalize parent python")
            .display()
            .to_string();

        let _path = PathEnvGuard::set(parent_path_dir.as_os_str().to_os_string());
        for (idx, shebang) in [
            "#!/usr/bin/env -S -u PATH python3\n",
            "#!/usr/bin/env -S -uPATH python3\n",
            "#!/usr/bin/env -S --unset PATH python3\n",
            "#!/usr/bin/env -S --unset=PATH python3\n",
        ]
        .into_iter()
        .enumerate()
        {
            let script = root.join(format!("script-{idx}"));
            std::fs::write(&script, shebang).expect("write env unset PATH shebang script");
            let mut perms = std::fs::metadata(&script)
                .expect("stat env unset PATH shebang script")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script, perms).expect("chmod env unset PATH shebang script");

            let mut unique = PinnedPaths::new();
            insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
                .expect("unset PATH shebang should not use parent PATH");
            let allowed = unique
                .keys()
                .map(|path| String::from_utf8_lossy(path).into_owned())
                .collect::<Vec<_>>();

            assert!(
                !allowed.contains(&parent_tool),
                "env -u PATH must not fall back to parent PATH: {allowed:?}"
            );
        }

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_respects_env_ignore_before_split() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let command = format!("tino-parent-only-tool-{}-{nanos}", std::process::id());
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-env-ignore-split-{}-{nanos}",
            std::process::id(),
        ));
        let parent_path_dir = root.join("parent-path");
        std::fs::create_dir_all(&parent_path_dir).expect("create parent PATH dir");
        let parent_tool = parent_path_dir.join(&command);
        std::fs::write(&parent_tool, b"parent-only tool\n").expect("write parent-only tool");
        let mut perms = std::fs::metadata(&parent_tool)
            .expect("stat parent-only tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&parent_tool, perms).expect("chmod parent-only tool");
        let parent_tool = parent_tool
            .canonicalize()
            .expect("canonicalize parent-only tool")
            .display()
            .to_string();

        let script = root.join("script");
        std::fs::write(&script, format!("#!/usr/bin/env -iS {command}\n"))
            .expect("write env -iS shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat env -iS shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod env -iS shebang script");

        let _path = PathEnvGuard::set(parent_path_dir.as_os_str().to_os_string());
        let mut unique = PinnedPaths::new();
        insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
            .expect("env -iS shebang should not use parent PATH");
        let allowed = unique
            .keys()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>();

        assert!(
            !allowed.contains(&parent_tool),
            "env -i before -S must not fall back to parent PATH: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_respects_env_chdir_for_relative_path() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-env-chdir-{}-{nanos}",
            std::process::id(),
        ));
        let app_dir = root.join("app");
        let app_bin = app_dir.join("bin");
        let other_bin = root.join("bin");
        std::fs::create_dir_all(&app_bin).expect("create app bin dir");
        std::fs::create_dir_all(&other_bin).expect("create other bin dir");
        let expected_tool = app_bin.join("tool");
        let wrong_tool = other_bin.join("tool");
        for tool in [&expected_tool, &wrong_tool] {
            std::fs::write(tool, b"fake tool\n").expect("write chdir candidate");
            let mut perms = std::fs::metadata(tool)
                .expect("stat chdir candidate")
                .permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(tool, perms).expect("chmod chdir candidate");
        }
        let script = root.join("script");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env -S --chdir {} PATH=bin tool\n",
                app_dir.display()
            ),
        )
        .expect("write chdir shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat chdir shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod chdir shebang script");

        let mut unique = PinnedPaths::new();
        insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
            .expect("relative shebang PATH should resolve after env --chdir");
        let allowed = unique
            .keys()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>();

        assert!(
            allowed.contains(&expected_tool.canonicalize().unwrap().display().to_string()),
            "expected env --chdir target to be allowed: {allowed:?}"
        );
        assert!(
            !allowed.contains(&wrong_tool.canonicalize().unwrap().display().to_string()),
            "relative shebang PATH must be resolved after chdir: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_skips_directory_shebang_interpreter() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-dir-shebang-{}-{nanos}",
            std::process::id(),
        ));
        let interpreter_dir = root.join("interpreter-dir");
        std::fs::create_dir_all(&interpreter_dir).expect("create interpreter directory");
        let script = root.join("script");
        std::fs::write(
            &script,
            format!("#!{}\necho should-not-run\n", interpreter_dir.display()),
        )
        .expect("write directory shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat directory shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod directory shebang script");

        let mut unique = PinnedPaths::new();
        insert_landlock_main_exec_path(&mut unique, &script.to_string_lossy())
            .expect("directory shebang interpreter should be left to child execution");
        let allowed = unique
            .keys()
            .map(|path| String::from_utf8_lossy(path).into_owned())
            .collect::<Vec<_>>();

        assert!(
            allowed.contains(&script.canonicalize().unwrap().display().to_string()),
            "script itself must still be auto-allowed: {allowed:?}"
        );
        assert!(
            !allowed.contains(
                &interpreter_dir
                    .canonicalize()
                    .unwrap()
                    .display()
                    .to_string()
            ),
            "directory shebang interpreter must not broaden exec allowlist: {allowed:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn main_exec_auto_allow_prefers_executable_path_candidate() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-main-exec-path-{}-{nanos}",
            std::process::id(),
        ));
        let first_dir = root.join("first");
        let second_dir = root.join("second");
        std::fs::create_dir_all(&first_dir).expect("create first PATH dir");
        std::fs::create_dir_all(&second_dir).expect("create second PATH dir");
        let first_tool = first_dir.join("tool");
        let second_tool = second_dir.join("tool");
        std::fs::write(&first_tool, b"not executable\n").expect("write first tool");
        std::fs::write(&second_tool, b"executable\n").expect("write second tool");
        let mut perms = std::fs::metadata(&first_tool)
            .expect("stat first tool")
            .permissions();
        perms.set_mode(0o644);
        std::fs::set_permissions(&first_tool, perms).expect("chmod first tool");
        let mut perms = std::fs::metadata(&second_tool)
            .expect("stat second tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&second_tool, perms).expect("chmod second tool");
        let path = std::env::join_paths([&first_dir, &second_dir]).expect("join PATH");

        let _path = PathEnvGuard::set(path);
        let resolved =
            resolve_main_exec_allow_path_candidate("tool").expect("resolve main exec candidate");

        assert_eq!(resolved, Some(second_tool));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn path_env_guard_is_thread_local() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let command = format!("tino-thread-local-path-tool-{}-{nanos}", std::process::id());
        let root = std::env::temp_dir().join(format!(
            "tino-thread-local-path-{}-{nanos}",
            std::process::id(),
        ));
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create thread-local PATH dir");
        let tool = bin_dir.join(&command);
        std::fs::write(&tool, b"test tool\n").expect("write thread-local PATH tool");
        let mut perms = std::fs::metadata(&tool)
            .expect("stat thread-local PATH tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool, perms).expect("chmod thread-local PATH tool");

        let _path = PathEnvGuard::set(bin_dir.as_os_str().to_os_string());
        let resolved = resolve_main_exec_allow_path_candidate(&command)
            .expect("resolve command from thread-local PATH");
        let other_thread_resolved = std::thread::spawn({
            move || {
                resolve_main_exec_allow_path_candidate(&command)
                    .expect("resolve command outside thread-local PATH")
            }
        })
        .join()
        .expect("join thread-local PATH test thread");

        assert_eq!(resolved, Some(tool));
        assert_eq!(other_thread_resolved, None);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn exec_path_resolution_uses_default_path_when_path_unset() {
        let _path = PathEnvGuard::unset();

        let auto = resolve_main_exec_allow_path_candidate("sh")
            .expect("resolve main exec candidate")
            .expect("default exec path should find sh");
        let explicit =
            resolve_exec_allow_path_candidate("sh").expect("resolve explicit exec allow");

        assert_eq!(auto.file_name().and_then(|name| name.to_str()), Some("sh"));
        assert_eq!(
            explicit.file_name().and_then(|name| name.to_str()),
            Some("sh")
        );
    }

    #[test]
    fn explicit_exec_allow_still_rejects_missing_program() {
        let mut unique = PinnedPaths::new();

        let err = insert_landlock_exec_path(&mut unique, "/definitely/missing/tino-test-binary")
            .expect_err("explicit missing exec allow path must fail");

        assert!(
            format!("{err:#}").contains("open exec allow path"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn explicit_exec_allow_missing_path_escapes_control_bytes() {
        let mut unique = PinnedPaths::new();

        let err = insert_landlock_exec_path(&mut unique, "/definitely/missing/tino-\u{1b}[31m")
            .expect_err("explicit missing exec allow path must fail");
        let message = format!("{err:#}");

        assert!(message.contains(r"\x1b"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn write_allow_missing_path_escapes_control_bytes() {
        let cli = Cli {
            write_allow: vec!["/definitely/missing/tino-\u{1b}[31m".into()],
            ..Cli::default()
        };

        let Err(err) = build_landlock_config(&cli) else {
            panic!("missing write allow path must fail");
        };
        let message = format!("{err:#}");

        assert!(message.contains(r"\x1b"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn device_ioctl_allow_missing_path_escapes_control_bytes() {
        let cli = Cli {
            device_ioctl_allow: vec!["/definitely/missing/tino-\u{1b}[31m".into()],
            ..Cli::default()
        };

        let Err(err) = build_landlock_config(&cli) else {
            panic!("missing device ioctl allow path must fail");
        };
        let message = format!("{err:#}");

        assert!(message.contains(r"\x1b"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn explicit_exec_allow_missing_path_command_escapes_control_bytes() {
        let mut unique = PinnedPaths::new();

        let err = insert_landlock_exec_path(&mut unique, "missing-\u{1b}[31m")
            .expect_err("explicit missing exec allow command must fail");
        let message = format!("{err:#}");

        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn explicit_exec_allow_rejects_missing_env_shebang_command() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let missing = format!(
            "definitely-missing-tino-interpreter-{}-{nanos}",
            std::process::id()
        );
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-exec-missing-env-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create explicit env shebang test dir");
        let script = root.join("script");
        std::fs::write(&script, format!("#!/usr/bin/env {missing}\n"))
            .expect("write explicit env shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat explicit env shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod explicit env shebang script");

        let mut unique = PinnedPaths::new();
        let err = insert_landlock_exec_path(&mut unique, &script.to_string_lossy())
            .expect_err("explicit exec allow should strictly validate shebang dependencies");

        assert!(
            format!("{err:#}").contains(&missing),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_exec_allow_rejects_invalid_utf8_env_shebang_argument() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-exec-invalid-env-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create explicit invalid env shebang test dir");
        let script = root.join("script");
        std::fs::write(&script, b"#!/usr/bin/env python\xff\n")
            .expect("write explicit invalid env shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat explicit invalid env shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms)
            .expect("chmod explicit invalid env shebang script");

        let mut unique = PinnedPaths::new();
        let err = insert_landlock_exec_path(&mut unique, &script.to_string_lossy())
            .expect_err("explicit exec allow should reject unresolved shebang dependency");

        assert!(
            format!("{err:#}").contains("env shebang argument is not valid UTF-8"),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_exec_allow_missing_env_shebang_command_escapes_control_bytes() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let missing = format!("missing-\u{1b}[31m-{nanos}");
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-exec-missing-env-escape-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create explicit env shebang escaping test dir");
        let script = root.join("script");
        std::fs::write(&script, format!("#!/usr/bin/env {missing}\n"))
            .expect("write explicit env shebang escaping script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat explicit env shebang escaping script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms)
            .expect("chmod explicit env shebang escaping script");

        let mut unique = PinnedPaths::new();
        let err = insert_landlock_exec_path(&mut unique, &script.to_string_lossy())
            .expect_err("explicit exec allow should reject missing shebang dependency");
        let message = format!("{err:#}");

        assert!(
            message.contains(r"\u{1b}"),
            "expected escaped control byte in error: {message}"
        );
        assert!(
            !message.contains('\u{1b}'),
            "error must not emit raw terminal control bytes: {message}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_exec_allow_rejects_missing_env_path_assignment_command() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-exec-env-path-{}-{nanos}",
            std::process::id(),
        ));
        let shebang_path_dir = root.join("shebang-path");
        std::fs::create_dir_all(&shebang_path_dir).expect("create explicit shebang PATH dir");
        let script = root.join("script");
        std::fs::write(
            &script,
            format!(
                "#!/usr/bin/env -S -i PATH={} python3\n",
                shebang_path_dir.display()
            ),
        )
        .expect("write explicit env PATH shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat explicit env PATH shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod explicit env PATH shebang script");

        let mut unique = PinnedPaths::new();
        let err = insert_landlock_exec_path(&mut unique, &script.to_string_lossy())
            .expect_err("explicit exec allow should reject missing shebang PATH command");

        assert!(
            format!("{err:#}").contains("from shebang PATH"),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_exec_allow_respects_env_ignore_before_split() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let command = format!("tino-parent-only-tool-{}-{nanos}", std::process::id());
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-exec-env-ignore-split-{}-{nanos}",
            std::process::id(),
        ));
        let parent_path_dir = root.join("parent-path");
        std::fs::create_dir_all(&parent_path_dir).expect("create parent PATH dir");
        let parent_tool = parent_path_dir.join(&command);
        std::fs::write(&parent_tool, b"parent-only tool\n").expect("write parent-only tool");
        let mut perms = std::fs::metadata(&parent_tool)
            .expect("stat parent-only tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&parent_tool, perms).expect("chmod parent-only tool");

        let script = root.join("script");
        std::fs::write(&script, format!("#!/usr/bin/env -iS {command}\n"))
            .expect("write env -iS shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat env -iS shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod env -iS shebang script");

        let _path = PathEnvGuard::set(parent_path_dir.as_os_str().to_os_string());
        let mut unique = PinnedPaths::new();
        let err = insert_landlock_exec_path(&mut unique, &script.to_string_lossy())
            .expect_err("explicit env -iS shebang must not use parent PATH");

        assert!(
            format!("{err:#}").contains("from shebang PATH"),
            "unexpected error: {err:#}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn explicit_exec_allow_rejects_directory_shebang_interpreter() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-explicit-dir-shebang-{}-{nanos}",
            std::process::id(),
        ));
        let interpreter_dir = root.join("interpreter-dir");
        std::fs::create_dir_all(&interpreter_dir).expect("create interpreter directory");
        let script = root.join("script");
        std::fs::write(
            &script,
            format!("#!{}\necho should-not-run\n", interpreter_dir.display()),
        )
        .expect("write directory shebang script");
        let mut perms = std::fs::metadata(&script)
            .expect("stat directory shebang script")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&script, perms).expect("chmod directory shebang script");

        let mut unique = PinnedPaths::new();
        let err = insert_landlock_exec_path(&mut unique, &script.to_string_lossy())
            .expect_err("explicit exec allow should reject directory shebang dependency");
        let message = format!("{err:#}");

        assert!(
            message.contains("not an executable file"),
            "unexpected directory shebang error: {message}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn compute_exit_code_remaps_expected_values() {
        let mut expect_zero = [false; 256];
        expect_zero[3] = true;
        assert_eq!(compute_exit_code(3, &expect_zero), 0);
        assert_eq!(compute_exit_code(5, &expect_zero), 5);
    }

    #[test]
    fn signal_fd_poll_failed_rejects_error_states() {
        assert!(!signal_fd_poll_failed(PollFlags::empty()));
        assert!(!signal_fd_poll_failed(PollFlags::POLLIN));
        assert!(signal_fd_poll_failed(PollFlags::POLLERR));
        assert!(signal_fd_poll_failed(PollFlags::POLLHUP));
        assert!(signal_fd_poll_failed(PollFlags::POLLNVAL));
    }

    #[test]
    fn wait_status_drain_continues_after_non_terminal_child_statuses() {
        assert_eq!(
            wait_status_drain_action(WaitStatus::Stopped(Pid::from_raw(11), SIGTERM as i32)),
            WaitLoop::Continue
        );
        assert_eq!(
            wait_status_drain_action(WaitStatus::Continued(Pid::from_raw(11))),
            WaitLoop::Continue
        );
        assert_eq!(
            wait_status_drain_action(WaitStatus::StillAlive),
            WaitLoop::Break
        );
    }

    #[test]
    fn huge_grace_period_does_not_panic() {
        let _deadline = ShutdownDeadline::after(Instant::now(), u64::MAX);
    }

    #[test]
    fn never_shutdown_deadline_uses_max_poll_timeout() {
        assert_eq!(ShutdownDeadline::Never.poll_timeout(), PollTimeout::MAX);
    }

    #[test]
    fn parse_elf_interpreter_rejects_overflowing_program_header_offset() {
        let mut bytes = minimal_elf64();
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());

        let err = parse_elf_interpreter(&bytes).expect_err("overflowing program header offset");
        let message = format!("{err:#}");
        assert!(
            message.contains("ELF program header offset overflow"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn parse_elf_interpreter_rejects_tiny_program_header_entries() {
        let mut bytes = minimal_elf64();
        bytes[54..56].copy_from_slice(&1u16.to_le_bytes());

        let err = parse_elf_interpreter(&bytes).expect_err("tiny program header entry");
        let message = format!("{err:#}");
        assert!(
            message.contains("ELF program header entry too small"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn parse_elf_interpreter_rejects_overflowing_interpreter_segment() {
        let mut bytes = minimal_elf64();
        let ph = 64;
        bytes[ph..ph + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[ph + 8..ph + 16].copy_from_slice(&u64::MAX.to_le_bytes());
        bytes[ph + 32..ph + 40].copy_from_slice(&16u64.to_le_bytes());

        let err = parse_elf_interpreter(&bytes).expect_err("overflowing interpreter segment");
        let message = format!("{err:#}");
        assert!(
            message.contains("ELF interpreter segment offset overflow"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn parse_elf_interpreter_rejects_unterminated_interpreter_path() {
        let interpreter = b"/lib64/ld-linux-x86-64.so.2";
        let mut bytes = minimal_elf64_with_interpreter(256, interpreter);
        let interp_ph = 64 + 56;
        bytes[interp_ph + 32..interp_ph + 40]
            .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());

        let err = parse_elf_interpreter(&bytes).expect_err("unterminated interpreter must fail");
        let message = format!("{err:#}");

        assert!(
            message.contains("ELF interpreter path is not NUL-terminated"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn detect_exec_interpreters_reads_elf_interpreter_segment_directly() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-elf-interpreter-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create ELF interpreter test dir");
        let path = root.join("program");
        let interpreter = "/lib64/ld-linux-x86-64.so.2";
        let bytes =
            minimal_elf64_with_interpreter(EXEC_PROBE_PREFIX_LEN * 2, interpreter.as_bytes());
        std::fs::write(&path, bytes).expect("write ELF interpreter fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat ELF interpreter fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod ELF interpreter fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect ELF interpreter directly");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(interpreter.into())]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_preserves_non_utf8_elf_interpreter_path() {
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-non-utf8-elf-interpreter-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create non-UTF-8 ELF interpreter test dir");
        let path = root.join("program");
        let interpreter = b"/tmp/tino-ld-\xff";
        let bytes = minimal_elf64_with_interpreter(EXEC_PROBE_PREFIX_LEN * 2, interpreter);
        std::fs::write(&path, bytes).expect("write non-UTF-8 ELF interpreter fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat non-UTF-8 ELF interpreter fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod non-UTF-8 ELF interpreter fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect non-UTF-8 ELF interpreter directly");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                OsString::from_vec(interpreter.to_vec())
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_rejects_unterminated_elf_interpreter_path() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-unterminated-elf-interpreter-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create unterminated ELF interpreter test dir");
        let path = root.join("program");
        let interpreter = b"/lib64/ld-linux-x86-64.so.2";
        let mut bytes = minimal_elf64_with_interpreter(EXEC_PROBE_PREFIX_LEN * 2, interpreter);
        let interp_ph = 64 + 56;
        bytes[interp_ph + 32..interp_ph + 40]
            .copy_from_slice(&(interpreter.len() as u64).to_le_bytes());
        std::fs::write(&path, bytes).expect("write unterminated ELF interpreter fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat unterminated ELF interpreter fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod unterminated ELF interpreter fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect unterminated ELF fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_malformed_elf() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-malformed-elf-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create malformed ELF test dir");
        let path = root.join("program");
        std::fs::write(&path, b"\x7FELFnot really elf\n").expect("write malformed ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat malformed ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod malformed ELF fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect malformed ELF fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_accepts_load_mappings_past_eof() {
        let mut bytes = minimal_elf64_with_interpreter(256, b"/lib/ld-test.so");
        bytes[56..58].copy_from_slice(&3u16.to_le_bytes());
        let ph = 64 + 2 * 56;
        bytes[ph..ph + 56].fill(0);
        bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        bytes[ph + 4..ph + 8].copy_from_slice(&6u32.to_le_bytes()); // PF_R | PF_W
        bytes[ph + 8..ph + 16].copy_from_slice(&0x10_0000u64.to_le_bytes());
        bytes[ph + 16..ph + 24].copy_from_slice(&0x50_0000u64.to_le_bytes());
        bytes[ph + 40..ph + 48].copy_from_slice(&4096u64.to_le_bytes());
        bytes[ph + 48..ph + 56].copy_from_slice(&4096u64.to_le_bytes());
        let path = std::env::temp_dir().join(format!("tino-load-past-eof-{}", std::process::id()));
        for filesz in [0u64, 1, 4096] {
            bytes[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
            std::fs::write(&path, &bytes).expect("write ELF fixture");
            assert_eq!(
                detect_exec_interpreters(&path).expect("inspect load segment past EOF"),
                vec![ExecInterpreter::Candidate(PathBuf::from("/lib/ld-test.so"))],
                "filesz={filesz}"
            );
        }
        std::fs::remove_file(&path).expect("remove ELF fixture");
    }

    #[test]
    fn detect_exec_interpreters_rejects_oversized_program_header_entries() {
        let mut bytes = minimal_elf64_with_interpreter(256, b"/lib/ld-test.so");
        // Keep all original segments valid, but move the program-header table
        // and pad each entry. Linux rejects this stride before using PT_INTERP.
        let table = bytes[64..64 + 2 * 56].to_vec();
        let phoff = bytes.len() as u64;
        for entry in table.as_chunks::<56>().0 {
            bytes.extend_from_slice(entry);
            bytes.extend_from_slice(&[0; 8]);
        }
        bytes[32..40].copy_from_slice(&phoff.to_le_bytes());
        bytes[54..56].copy_from_slice(&64u16.to_le_bytes());

        let path = std::env::temp_dir().join(format!(
            "tino-oversized-elf-phentsize-{}",
            std::process::id()
        ));
        std::fs::write(&path, bytes).expect("write oversized ELF entry fixture");
        let interpreters = detect_exec_interpreters(&path).expect("inspect oversized ELF entries");
        let _ = std::fs::remove_file(&path);
        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_elf_without_load_segment() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-elf-without-load-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create no-load ELF test dir");
        let path = root.join("program");
        std::fs::write(&path, minimal_elf64()).expect("write no-load ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat no-load ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod no-load ELF fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect no-load ELF fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_static_elf_without_executable_entry() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-elf-without-exec-entry-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create invalid static ELF test dir");
        let path = root.join("program");
        let mut bytes = minimal_elf64();
        set_minimal_elf64_load_segment(&mut bytes, 0x0040_0000, 1, 1, 0);
        std::fs::write(&path, bytes).expect("write invalid static ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat invalid static ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod invalid static ELF fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect invalid static ELF fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_overflowing_load_segment() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-elf-overflowing-load-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create overflowing load ELF test dir");
        let path = root.join("program");
        let mut bytes = minimal_elf64();
        set_minimal_elf64_load_segment(&mut bytes, u64::MAX, 0, 1, 1);
        std::fs::write(&path, bytes).expect("write overflowing load ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat overflowing load ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod overflowing load ELF fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect overflowing load ELF fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_keeps_valid_static_elf_without_shell_fallback() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-valid-static-elf-no-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create valid static ELF test dir");
        let path = root.join("program");
        let mut bytes = minimal_elf64();
        set_minimal_elf64_executable_load_segment(&mut bytes);
        std::fs::write(&path, bytes).expect("write valid-looking static ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat valid-looking static ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod valid-looking static ELF fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect static ELF");

        assert_eq!(interpreters, Vec::<ExecInterpreter>::new());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "arm",
        target_arch = "aarch64",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "s390x",
    ))]
    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_non_native_elf_machine() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-elf-non-native-machine-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create non-native ELF test dir");
        let path = root.join("program");
        let mut bytes = minimal_elf64();
        bytes[18..20].copy_from_slice(&0u16.to_le_bytes());
        let load_ph = 64;
        bytes[load_ph..load_ph + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[load_ph + 32..load_ph + 40].copy_from_slice(&1u64.to_le_bytes());
        std::fs::write(&path, bytes).expect("write non-native ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat non-native ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod non-native ELF fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect non-native ELF fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_elf_with_invalid_program_header_offset() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-elf-invalid-phoff-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create invalid phoff ELF test dir");
        let path = root.join("program");
        let mut bytes = minimal_elf64();
        bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        std::fs::write(&path, bytes).expect("write invalid phoff ELF fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat invalid phoff ELF fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod invalid phoff ELF fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect invalid phoff fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_text_without_shebang() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-execvp-shell-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create execvp fallback test dir");
        let path = root.join("script");
        std::fs::write(&path, b"echo ok\n").expect("write text executable fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat text executable fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod text executable fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect execvp shell fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_empty_shebang() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-empty-shebang-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create empty shebang test dir");
        let path = root.join("script");
        std::fs::write(&path, b"#!\necho ok\n").expect("write empty shebang fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat empty shebang fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod empty shebang fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect empty shebang fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_adds_execvp_shell_for_unterminated_long_shebang() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-long-shebang-fallback-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create long shebang test dir");
        let path = root.join("script");
        let mut bytes = b"#!/bin/sh".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', LINUX_BINPRM_BUF_SIZE));
        bytes.extend_from_slice(b"\necho ok\n");
        std::fs::write(&path, bytes).expect("write long shebang fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat long shebang fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod long shebang fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect unterminated long shebang fallback");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from(
                EXECVP_FALLBACK_SHELL
            ))]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_limits_shebang_argument_to_kernel_buffer() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-kernel-buffer-shebang-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create kernel buffer shebang test dir");
        let path = root.join("script");
        let mut bytes = b"#!/bin/sh ".to_vec();
        bytes.extend(std::iter::repeat_n(b'x', LINUX_BINPRM_BUF_SIZE));
        bytes.extend_from_slice(b"\necho ok\n");
        std::fs::write(&path, bytes).expect("write kernel buffer shebang fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat kernel buffer shebang fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod kernel buffer shebang fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect kernel-buffer-limited shebang");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::ShebangCandidate {
                path: "/bin/sh".into(),
                argument: OwnedShebangArgument::Utf8("x".repeat(245)),
            }]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_shebang_exec_paths_uses_last_kernel_visible_terminator() {
        let path = format!("/{}", "x".repeat(252));
        let mut bytes = format!("#!{path} ").into_bytes();
        bytes.extend_from_slice(b"ignored\n");

        assert_eq!(bytes[LINUX_BINPRM_BUF_SIZE - 1], b' ');
        assert_eq!(parse_shebang_exec_paths(&bytes), vec![path]);
    }

    #[test]
    fn parse_shebang_exec_paths_falls_back_after_kernel_buffer() {
        let path = format!("/{}", "x".repeat(253));
        let mut bytes = format!("#!{path} ").into_bytes();
        bytes.extend_from_slice(b"ignored\n");

        assert_eq!(bytes[LINUX_BINPRM_BUF_SIZE], b' ');
        assert_eq!(
            parse_shebang_exec_paths(&bytes),
            vec![EXECVP_FALLBACK_SHELL]
        );
    }

    #[test]
    fn detect_exec_interpreters_keeps_relative_shebang_interpreter_without_shell_fallback() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-relative-shebang-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create relative shebang test dir");
        let path = root.join("script");
        std::fs::write(&path, b"#!bad\necho should-not-run\n")
            .expect("write relative shebang fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat relative shebang fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod relative shebang fixture");

        let interpreters =
            detect_exec_interpreters(&path).expect("detect relative shebang interpreter");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from("./bad"))],
            "relative shebang must not imply /bin/sh fallback"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn detect_exec_interpreters_does_not_trim_carriage_return_from_shebang() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("tino-crlf-shebang-{}-{nanos}", std::process::id(),));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create CRLF shebang test dir");
        let path = root.join("script");
        std::fs::write(&path, b"#!/bin/sh\r\necho should-not-run\n")
            .expect("write CRLF shebang fixture");
        let mut perms = std::fs::metadata(&path)
            .expect("stat CRLF shebang fixture")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod CRLF shebang fixture");

        let interpreters = detect_exec_interpreters(&path).expect("detect CRLF shebang");

        assert_eq!(
            interpreters,
            vec![ExecInterpreter::Candidate(PathBuf::from("/bin/sh\r"))],
            "CR must remain part of the kernel interpreter path"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_exact_file_at_rejects_offset_overflow() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-read-offset-overflow-{}-{nanos}",
            std::process::id(),
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).expect("create offset overflow test dir");
        let path = root.join("file");
        std::fs::write(&path, b"abc").expect("write offset overflow fixture");
        let file = File::open(&path).expect("open offset overflow fixture");
        let mut buf = [0u8; 2];

        let err = read_exact_file_at(&file, &mut buf, u64::MAX).expect_err("offset must not wrap");

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_shebang_exec_paths_detects_direct_interpreter() {
        assert_eq!(
            parse_shebang_exec_paths(b"#!/bin/sh -e\necho ok\n"),
            vec!["/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!interp -e\necho ok\n"),
            vec!["./interp"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!./interp -e\necho ok\n"),
            vec!["./interp"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/bin/sh \xff\n"),
            vec!["/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/bin/sh\r\n"),
            vec!["/bin/sh\r"]
        );
        assert_eq!(parse_shebang_exec_paths(b"#! \t\r\n"), vec!["./\r"]);
    }

    #[test]
    fn parse_shebang_truncates_full_buffer_arguments_before_last_byte() {
        let prefix = b"#!/usr/bin/env -S ";
        let mut bytes = prefix.to_vec();
        bytes.resize(LINUX_BINPRM_BUF_SIZE - b"/bin/shX".len(), b' ');
        bytes.extend_from_slice(b"/bin/shX");
        bytes.push(b'\n');
        assert_eq!(
            parse_shebang_exec_paths(&bytes),
            vec!["/usr/bin/env", "/bin/sh"]
        );

        // A newline in the last buffer byte retains the preceding character.
        bytes[LINUX_BINPRM_BUF_SIZE - 1] = b'\n';
        assert_eq!(
            parse_shebang_exec_paths(&bytes),
            vec!["/usr/bin/env", "/bin/sh"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_detects_env_command() {
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env python3\nprint('ok')\n"),
            vec!["/usr/bin/env", "python3"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env python\xff\nprint('ok')\n"),
            vec!["/usr/bin/env", "env shebang argument is not valid UTF-8"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/bin/env python3\nprint('ok')\n"),
            vec!["/bin/env", "python3"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/opt/app/env python3\nprint('ok')\n"),
            vec!["/opt/app/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!env python3\nprint('ok')\n"),
            vec!["./env"]
        );
    }

    #[test]
    fn env_shebang_detection_is_conservative() {
        assert!(is_env_interpreter(b"/usr/bin/env"));
        assert!(is_env_interpreter(b"/bin/env"));
        assert!(!is_env_interpreter(b"/opt/app/env"));
        assert!(!is_env_interpreter(b"env"));
        assert!(!is_env_interpreter(b"./env"));
    }

    #[test]
    fn env_alias_discovery_does_not_grant_multicall_applet_arguments() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        struct IdentityGuard;
        impl Drop for IdentityGuard {
            fn drop(&mut self) {
                TEST_ENV_IDENTITY_PATHS.with(|paths| paths.replace(None));
            }
        }
        let _guard = IdentityGuard;
        let root = std::env::temp_dir().join(unique_env_name("ENV_MULTICALL"));
        std::fs::create_dir(&root).unwrap();
        let main = root.join("main");
        let helper = root.join("helper");
        std::fs::copy("/bin/false", &helper).unwrap();
        for layout in ["standalone", "symlink", "hardlink"] {
            let dir = root.join(layout);
            std::fs::create_dir(&dir).unwrap();
            let env = dir.join("env");
            let shell = dir.join("sh");
            let alias = dir.join("alias");
            if layout == "standalone" {
                std::fs::copy("/usr/bin/env", &env).unwrap();
                std::fs::copy("/bin/sh", &shell).unwrap();
                symlink(&env, &alias).unwrap();
            } else {
                let multicall = dir.join("multicall");
                std::fs::copy("/bin/sh", &multicall).unwrap();
                if layout == "symlink" {
                    symlink(&multicall, &env).unwrap();
                    // A distinct shell ensures this case exercises the reference
                    // target check independently of the shared-inode check.
                    std::fs::copy("/bin/sh", &shell).unwrap();
                } else {
                    std::fs::hard_link(&multicall, &env).unwrap();
                    std::fs::hard_link(&multicall, &shell).unwrap();
                }
                symlink(&multicall, &alias).unwrap();
            }
            TEST_ENV_IDENTITY_PATHS.with(|paths| paths.replace(Some((env, shell))));
            std::fs::write(
                &main,
                format!("#!{} {}\n", alias.display(), helper.display()),
            )
            .unwrap();
            std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o755)).unwrap();
            let config = build_landlock_config(&Cli {
                exec_allow: vec![main.to_str().unwrap().into()],
                ..Cli::default()
            })
            .unwrap()
            .unwrap();
            assert_eq!(
                config
                    .exec_allow_paths
                    .iter()
                    .any(|path| path.path() == helper),
                layout == "standalone",
                "unexpected executable grant for {layout} env layout"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn parse_shebang_exec_paths_detects_env_split_command() {
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S python3 -u\nprint('ok')\n"),
            vec!["/usr/bin/env", "python3"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -vS python3 -u\nprint('ok')\n"),
            vec!["/usr/bin/env", "python3"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -iS /bin/sh\nexit 0\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -viS /bin/sh\nexit 0\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -ivS /bin/sh\nexit 0\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
    }

    #[test]
    fn env_shebang_dash_ends_options_and_clears_environment() {
        let mut context = ExecContext::inherited();
        context
            .environment
            .insert("TINO_INHERITED".into(), "present".into());
        for (argument, expected, assigned) in [
            ("-S -- - NAME=value /bin/sh", "/bin/sh", true),
            ("-S - NAME=value /bin/sh", "/bin/sh", true),
            ("-S - -u PATH /bin/true", "-u", false),
            ("-S - -- /bin/true", "--", false),
            ("-S -- - - /bin/true", "-", false),
        ] {
            let command = env_shebang_command(argument, &context)
                .expect("parse env arguments")
                .expect("find command after env dash");
            assert_eq!(command.command, expected, "{argument}");
            let expected_environment = if assigned {
                BTreeMap::from([("NAME".into(), "value".into())])
            } else {
                BTreeMap::new()
            };
            assert_eq!(
                command.context.environment, expected_environment,
                "{argument}"
            );
        }
    }

    #[test]
    fn parse_shebang_exec_paths_detects_env_options_and_assignments() {
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S -u OLD SERVICE_ENV=test python3 -u\nprint('ok')\n"
            ),
            vec!["/usr/bin/env", "python3"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S SERVICE_ENV=test -u OLD python3 -u\nprint('ok')\n"
            ),
            vec!["/usr/bin/env", "-u"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env --split-string=--chdir /tmp /bin/sh\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env --spl=/bin/sh\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --spl=/bin/sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --spl /bin/sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --chd / PATH=bin sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --un PATH /bin/sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --deb --lis /bin/sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S -- NAME=value -tool --flag\n"),
            vec!["/usr/bin/env", "-tool"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S -iu OLD /bin/sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S -ia NAME /bin/sh -c true\n"),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S --block-signal=TERM,15,015,SIG15 /bin/sh -c true\n"
            ),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S --block-signal=STOP --default-signal=TERM /bin/sh\n"
            ),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S --block-signal=CHLD,XCPU,RTMIN+1,RTMAX-1 /bin/sh\n"
            ),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S --default-signal=CHLD --ignore-signal=URG /bin/sh\n"
            ),
            vec!["/usr/bin/env", "/bin/sh"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_ignores_invalid_env_options() {
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --not-an-env-option /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --ignore /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --d /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --debug=value /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --ver /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S -q /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --help /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S -0 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --unset= /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --unset = /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S -u= /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S --chdir '' /bin/sh
"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S -C '' /bin/sh
"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S --chdir /definitely/missing/tino-env-chdir /bin/sh\n"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                b"#!/usr/bin/env -S -C /definitely/missing/tino-env-chdir /bin/sh\n"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=NOPE /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --default-signal=0 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=+15 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=SIG+15 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=32 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --default-signal=33 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --ignore-signal=KILL /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --default-signal=STOP /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=RTMIN+99 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=RTMAX-99 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=RTMIN+-1 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=RTMIN++1 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=RTMAX--1 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S --block-signal=RTMAX-+1 /bin/sh\n"),
            vec!["/usr/bin/env"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_keeps_env_argument_without_split() {
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env python3 -u\nprint('ok')\n"),
            vec!["/usr/bin/env", "python3 -u"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_handles_env_split_quotes() {
        assert_eq!(
            parse_shebang_exec_paths(
                br#"#!/usr/bin/env -S --argv0 "shell alias" /bin/sh -e
"#
            ),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S python3\_-u
"
            ),
            vec!["/usr/bin/env", "python3"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br#"#!/usr/bin/env -S "/bin/with\_space" -e
"#
            ),
            vec!["/usr/bin/env", "/bin/with space"]
        );
    }

    #[test]
    fn env_split_string_matches_gnu_quote_escapes() {
        let context = ExecContext::inherited();
        for (raw, expected) in [
            (r"'/bin/with\'quote'", "/bin/with'quote"),
            (r"'/bin/with\\slash'", r"/bin/with\slash"),
            (r"'/bin/with\_space'", r"/bin/with\_space"),
            (r"'/bin/with\cvalue'", r"/bin/with\cvalue"),
            (r#""/bin/with\\slash""#, r"/bin/with\slash"),
        ] {
            assert_eq!(
                split_env_split_string(raw, &context),
                Some(vec![expected.to_owned()]),
                "{raw:?}"
            );
        }
        for raw in [r"/bin/with\avalue", r"/bin/with\bvalue", r#""/bin/sh\c""#] {
            assert_eq!(split_env_split_string(raw, &context), None, "{raw:?}");
        }
    }

    #[test]
    fn parse_shebang_exec_paths_handles_env_split_variables() {
        let name = unique_env_name("ENV_SHEBANG_COMMAND");
        let _env = EnvVarGuard::set(name.clone(), OsString::from("/bin/sh"));
        let shebang = format!("#!/usr/bin/env -S ${{{name}}} -c true\n");
        let single_quoted = format!("#!/usr/bin/env -S '${{{name}}}' -c true\n");

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(single_quoted.as_bytes()),
            vec!["/usr/bin/env", &format!("${{{name}}}")]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_expands_env_split_variables_before_environment_changes() {
        let name = unique_env_name("ENV_SHEBANG_EARLY_EXPANDED_COMMAND");
        let _env = EnvVarGuard::set(name.clone(), OsString::from("/bin/sh"));
        let ignored = format!("#!/usr/bin/env -iS ${{{name}}} /bin/echo\n");
        let unset_before_nested = format!("#!/usr/bin/env -S -u {name} -S ${{{name}}} /bin/echo\n");

        // GNU env expands ${VAR} while parsing -S, before options such as -i and -u
        // mutate the child environment.
        assert_eq!(
            parse_shebang_exec_paths(ignored.as_bytes()),
            vec!["/usr/bin/env", "/bin/sh"]
        );
        assert_eq!(
            parse_shebang_exec_paths(unset_before_nested.as_bytes()),
            vec!["/usr/bin/env", "/bin/sh"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_omits_unset_env_split_variables() {
        let name = unique_env_name("ENV_SHEBANG_COMMAND");
        let _env = EnvVarGuard::unset(name.clone());
        let shebang = format!("#!/usr/bin/env -S ${{{name}}} /bin/sh\n");

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env", "/bin/sh"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_preserves_empty_env_split_variables() {
        let name = unique_env_name("ENV_SHEBANG_COMMAND");
        let _env = EnvVarGuard::set(name.clone(), OsString::new());
        let shebang = format!("#!/usr/bin/env -S ${{{name}}} /bin/sh\n");

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env", ""]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_keeps_env_split_variable_values_atomic() {
        let name = unique_env_name("ENV_SHEBANG_COMMAND");
        let _env = EnvVarGuard::set(name.clone(), OsString::from("/bin/sh -c"));
        let shebang = format!("#!/usr/bin/env -S ${{{name}}} true\n");

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env", "/bin/sh -c"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_rejects_non_utf8_env_split_variables() {
        use std::os::unix::ffi::OsStringExt;

        let name = unique_env_name("ENV_SHEBANG_COMMAND");
        let _env = EnvVarGuard::set(name.clone(), OsString::from_vec(vec![0xff]));
        let shebang = format!("#!/usr/bin/env -S ${{{name}}} /bin/sh\n");

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_ignores_invalid_env_split_string() {
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S /bin/sh\ x
"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br#"#!/usr/bin/env -S "/bin/sh -e
"#
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S # /bin/sh
"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S $TINO_TEST_ENV_SHEBANG_COMMAND /bin/sh
"
            ),
            vec!["/usr/bin/env"]
        );
        assert_eq!(
            parse_shebang_exec_paths(
                br"#!/usr/bin/env -S ${TINO_TEST_ENV_SHEBANG_COMMAND:-/bin/sh}
"
            ),
            vec!["/usr/bin/env"]
        );
    }

    #[test]
    fn env_split_string_cycles_are_bounded() {
        let mut context = ExecContext::inherited();
        for value in ["-S ${TINO_SPLIT_LOOP}", "--split-string=${TINO_SPLIT_LOOP}"] {
            context
                .environment
                .insert("TINO_SPLIT_LOOP".into(), value.into());
            assert_eq!(
                env_shebang_command("-S ${TINO_SPLIT_LOOP}", &context),
                Err("env split-string expansion exceeds 32 steps")
            );
        }
    }

    #[test]
    fn nested_env_split_strings_keep_options_and_inherited_expansion_context() {
        let mut context = ExecContext::inherited();
        context
            .environment
            .insert("TINO_SPLIT_FIRST".into(), "-S ${TINO_SPLIT_SECOND}".into());
        context
            .environment
            .insert("TINO_SPLIT_SECOND".into(), "/bin/sh".into());
        let command = env_shebang_command("-S -i -C /tmp ${TINO_SPLIT_FIRST} -e", &context)
            .expect("bounded split expansion")
            .expect("resolved command");
        assert_eq!(command.command, "/bin/sh");
        assert_eq!(command.context.cwd.as_deref(), Some(Path::new("/tmp")));
        assert!(command.context.environment.is_empty());
    }

    #[test]
    fn env_chdir_applies_final_option_relative_to_inherited_directory() {
        let context = ExecContext {
            environment: BTreeMap::new(),
            cwd: Some(PathBuf::from("/")),
        };
        let command = env_shebang_command("-S -C missing -C tmp /bin/sh", &context)
            .unwrap()
            .unwrap();
        assert_eq!(command.context.cwd, Some(PathBuf::from("/tmp")));
        assert!(
            env_shebang_command("-S -C tmp -C '' /bin/sh", &context)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn parse_shebang_exec_paths_uses_env_path_assignment() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-env-shebang-path-{}-{nanos}",
            std::process::id(),
        ));
        let bin_dir = root.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create env PATH dir");
        let tool = bin_dir.join("python3");
        std::fs::write(&tool, b"fake python\n").expect("write fake python");
        let mut perms = std::fs::metadata(&tool)
            .expect("stat fake python")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool, perms).expect("chmod fake python");
        let shebang = format!(
            "#!/usr/bin/env -S -i PATH={} python3 -u\nprint('ok')\n",
            bin_dir.display()
        );

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env".to_string(), tool.display().to_string()]
        );

        let after_double_dash = format!(
            "#!/usr/bin/env -S -- PATH={} python3 -u\nprint('ok')\n",
            bin_dir.display()
        );
        assert_eq!(
            parse_shebang_exec_paths(after_double_dash.as_bytes()),
            vec!["/usr/bin/env".to_string(), tool.display().to_string()]
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn parse_shebang_exec_paths_stops_env_option_parsing_after_assignment() {
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S FOO=bar -i tool\n"),
            vec!["/usr/bin/env", "-i"]
        );
        assert_eq!(
            parse_shebang_exec_paths(b"#!/usr/bin/env -S PATH=/tmp --chdir / tool\n"),
            vec!["/usr/bin/env", "--chdir"]
        );
    }

    #[test]
    fn parse_shebang_exec_paths_uses_env_chdir_for_relative_path() {
        use std::os::unix::fs::PermissionsExt;
        use std::time::{SystemTime, UNIX_EPOCH};

        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "tino-env-shebang-chdir-{}-{nanos}",
            std::process::id(),
        ));
        let app_dir = root.join("app");
        let bin_dir = app_dir.join("bin");
        std::fs::create_dir_all(&bin_dir).expect("create chdir PATH dir");
        let tool = bin_dir.join("tool");
        std::fs::write(&tool, b"fake tool\n").expect("write chdir tool");
        let mut perms = std::fs::metadata(&tool)
            .expect("stat chdir tool")
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool, perms).expect("chmod chdir tool");
        let shebang = format!(
            "#!/usr/bin/env -S --chdir {} PATH=bin tool\n",
            app_dir.display()
        );

        assert_eq!(
            parse_shebang_exec_paths(shebang.as_bytes()),
            vec!["/usr/bin/env".to_string(), tool.display().to_string()]
        );

        let inline_short = format!(
            "#!/usr/bin/env -S--chdir {} PATH=bin tool\n",
            app_dir.display()
        );
        assert_eq!(
            parse_shebang_exec_paths(inline_short.as_bytes()),
            vec!["/usr/bin/env".to_string(), tool.display().to_string()]
        );

        let inline_long = format!(
            "#!/usr/bin/env --split-string=--chdir {} PATH=bin tool\n",
            app_dir.display()
        );
        assert_eq!(
            parse_shebang_exec_paths(inline_long.as_bytes()),
            vec!["/usr/bin/env".to_string(), tool.display().to_string()]
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    fn minimal_elf64() -> Vec<u8> {
        let mut bytes = vec![0u8; 120];
        bytes[0..4].copy_from_slice(b"\x7FELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        let machine = executable_elf_machines().first().copied().unwrap_or(62);
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
        bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
        bytes
    }

    fn minimal_elf64_with_interpreter(interpreter_offset: usize, interpreter: &[u8]) -> Vec<u8> {
        let filesz = interpreter.len() + 1;
        let mut bytes = minimal_elf64();
        let interp_ph = 64 + 56;
        bytes.resize((interp_ph + 56).max(interpreter_offset + filesz), 0);
        bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        set_minimal_elf64_executable_load_segment(&mut bytes);
        bytes[interp_ph..interp_ph + 4].copy_from_slice(&3u32.to_le_bytes());
        bytes[interp_ph + 8..interp_ph + 16]
            .copy_from_slice(&(interpreter_offset as u64).to_le_bytes());
        bytes[interp_ph + 32..interp_ph + 40].copy_from_slice(&(filesz as u64).to_le_bytes());
        bytes[interpreter_offset..interpreter_offset + interpreter.len()]
            .copy_from_slice(interpreter);
        bytes
    }

    fn set_minimal_elf64_executable_load_segment(bytes: &mut [u8]) {
        set_minimal_elf64_load_segment(bytes, 0x0040_0000, 1, 1, 1);
    }

    fn set_minimal_elf64_load_segment(
        bytes: &mut [u8],
        vaddr: u64,
        filesz: u64,
        memsz: u64,
        flags: u32,
    ) {
        let load_ph = 64;
        bytes[24..32].copy_from_slice(&vaddr.to_le_bytes());
        bytes[load_ph..load_ph + 4].copy_from_slice(&1u32.to_le_bytes());
        bytes[load_ph + 4..load_ph + 8].copy_from_slice(&flags.to_le_bytes());
        bytes[load_ph + 16..load_ph + 24].copy_from_slice(&vaddr.to_le_bytes());
        bytes[load_ph + 32..load_ph + 40].copy_from_slice(&filesz.to_le_bytes());
        bytes[load_ph + 40..load_ph + 48].copy_from_slice(&memsz.to_le_bytes());
    }
}
