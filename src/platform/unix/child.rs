use crate::{Context, Error, Result, bail, cli::Cli, diagnostic::escape_str, logging};
use libc::{_exit, PR_GET_CHILD_SUBREAPER, PR_SET_CHILD_SUBREAPER, PR_SET_PDEATHSIG};
use std::{env, ffi::CString};

use super::landlock;
use super::signals;
use super::sys::{
    Errno, ForkResult, Pid, SIGPIPE, SigSet, SignalAction, current_process_id, exec_program,
    fork_process, parent_process_id, process_group_exists, process_group_of, set_process_group,
};

#[derive(Default)]
pub(super) struct ParentPrctlOutcome {
    pub subreaper_enabled: bool,
    subreaper_restore: Option<SubreaperRestore>,
}

struct SubreaperRestore {
    previous: libc::c_int,
}

impl Drop for SubreaperRestore {
    fn drop(&mut self) {
        // SAFETY: restoring the previously captured child-subreaper flag for this process.
        let ret = unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, self.previous) };
        if ret == -1 {
            logging::warn(format_args!(
                "restore child subreaper state failed: {}",
                Errno::last()
            ));
        }
    }
}

pub(super) fn pdeath_signal(cli: &Cli) -> Result<Option<libc::c_int>> {
    let Some(sig_name) = &cli.pdeath else {
        return Ok(None);
    };
    let signal = signals::signal_by_name(sig_name).ok_or_else(|| {
        Error::msg(format!(
            "invalid signal '{}'; supported values align with `tino --help`",
            escape_str(sig_name)
        ))
    })?;
    Ok(Some(signal as libc::c_int))
}

pub(super) fn configure_parent_prctl(cli: &Cli) -> Result<ParentPrctlOutcome> {
    let mut outcome = ParentPrctlOutcome::default();
    if cli.subreaper {
        let previous_subreaper = current_child_subreaper_state();
        // SAFETY: enabling the child subreaper flag is safe for the current process.
        unsafe {
            if libc::prctl(PR_SET_CHILD_SUBREAPER, 1) == -1 {
                let err = Errno::last();
                if err == Errno::EPERM {
                    logging::warn(format_args!(
                        "subreaper capability rejected; continuing without subreaper: {}",
                        err
                    ));
                } else {
                    bail!("prctl SUBREAPER: {}", err);
                }
            } else {
                outcome.subreaper_enabled = true;
                match previous_subreaper {
                    Ok(previous) => {
                        outcome.subreaper_restore = Some(SubreaperRestore { previous });
                    }
                    Err(err) => {
                        logging::warn(format_args!(
                            "capture child subreaper state failed; restore disabled: {}",
                            err
                        ));
                    }
                }
            }
        }
    }
    Ok(outcome)
}

fn current_child_subreaper_state() -> std::result::Result<libc::c_int, Errno> {
    let mut value = 0;
    // SAFETY: value points to writable storage for PR_GET_CHILD_SUBREAPER.
    let ret = unsafe { libc::prctl(PR_GET_CHILD_SUBREAPER, &raw mut value) };
    if ret == -1 {
        Err(Errno::last())
    } else {
        Ok(value)
    }
}

fn set_child_pdeath_signal(sig: libc::c_int) -> std::result::Result<(), Errno> {
    // SAFETY: `sig` was resolved from the supported signal table before fork.
    let ret = unsafe { libc::prctl(PR_SET_PDEATHSIG, sig) };
    if ret == -1 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

fn self_signal(sig: libc::c_int) -> std::result::Result<(), Errno> {
    // SAFETY: signal number was resolved before fork and targets the current process.
    let ret = unsafe { libc::kill(current_process_id().as_raw(), sig) };
    if ret == -1 {
        Err(Errno::last())
    } else {
        Ok(())
    }
}

const MAX_ENV_EXPANSION_DEPTH: usize = 32;

pub(super) fn resolve_command_args(cmd: &[String], expand_env: bool) -> Result<Vec<String>> {
    let args = if expand_env {
        expand_command_args(cmd)
    } else {
        Ok(cmd.to_vec())
    }?;
    validate_program_name(&args)?;
    Ok(args)
}

pub(super) fn prepare_resolved_command(args: &[String]) -> Result<(CString, Vec<CString>)> {
    if args.is_empty() {
        bail!("missing CMD (use --help)");
    }

    let program = CString::new(args[0].as_str())
        .map_err(|_| Error::msg("command argument contains embedded NUL byte"))?;
    let argv = args
        .iter()
        .map(|s| {
            CString::new(s.as_str())
                .map_err(|_| Error::msg("command argument contains embedded NUL byte"))
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok((program, argv))
}

fn validate_program_name(args: &[String]) -> Result<()> {
    if args.first().is_some_and(String::is_empty) {
        bail!("command program cannot be empty");
    }
    Ok(())
}

fn expand_command_args(cmd: &[String]) -> Result<Vec<String>> {
    cmd.iter().map(|arg| expand_command_arg(arg)).collect()
}

fn expand_command_arg(arg: &str) -> Result<String> {
    expand_command_arg_with_depth(arg, 0).context("expand environment references in child argument")
}

fn expand_command_arg_with_depth(arg: &str, depth: usize) -> Result<String> {
    if depth > MAX_ENV_EXPANSION_DEPTH {
        bail!(
            "environment expansion nesting exceeds {} levels",
            MAX_ENV_EXPANSION_DEPTH
        );
    }

    let mut expanded = String::with_capacity(arg.len());
    let mut idx = 0;
    let bytes = arg.as_bytes();

    while idx < arg.len() {
        let Some(offset) = arg[idx..].find('$') else {
            expanded.push_str(&arg[idx..]);
            break;
        };
        let dollar = idx + offset;
        expanded.push_str(&arg[idx..dollar]);

        if dollar + 1 >= arg.len() {
            expanded.push('$');
            break;
        }

        match bytes[dollar + 1] {
            b'$' => {
                expanded.push('$');
                idx = dollar + 2;
            }
            b'{' => {
                let closing = find_matching_brace(arg, dollar + 2)?;
                let body = &arg[dollar + 2..closing];
                expanded.push_str(&expand_braced_env(body, depth + 1)?);
                idx = closing + 1;
            }
            _ => {
                expanded.push('$');
                idx = dollar + 1;
            }
        }
    }

    Ok(expanded)
}

fn expand_braced_env(body: &str, depth: usize) -> Result<String> {
    if let Some((name, default)) = split_braced_default(body) {
        if !is_valid_env_name(name) {
            bail!("invalid environment variable name '{}'", escape_str(name));
        }
        resolve_env_value(name, Some(default), depth)
    } else if is_valid_env_name(body) {
        resolve_env_value(body, None, depth)
    } else {
        bail!(
            "unsupported braced environment expansion '${{{}}}'",
            escape_str(body)
        );
    }
}

fn resolve_env_value(name: &str, default: Option<&str>, depth: usize) -> Result<String> {
    match env::var(name) {
        Ok(value) if default.is_none() || !value.is_empty() => Ok(value),
        Ok(_) | Err(env::VarError::NotPresent) if let Some(fallback) = default => {
            expand_command_arg_with_depth(fallback, depth)
        }
        Ok(_) | Err(env::VarError::NotPresent) => Ok(String::new()),
        Err(env::VarError::NotUnicode(_)) => {
            bail!("environment variable '{name}' contains non-Unicode data")
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EnvBraceFrame {
    Expansion,
    Literal,
}

fn find_matching_brace(arg: &str, mut idx: usize) -> Result<usize> {
    let bytes = arg.as_bytes();
    let mut stack = vec![EnvBraceFrame::Expansion];

    while idx < arg.len() {
        if bytes[idx] == b'$' && idx + 1 < arg.len() {
            match bytes[idx + 1] {
                b'$' => {
                    if idx + 2 < arg.len() && bytes[idx + 2] == b'{' {
                        stack.push(EnvBraceFrame::Literal);
                        idx += 3;
                    } else {
                        idx += 2;
                    }
                    continue;
                }
                b'{' => {
                    stack.push(EnvBraceFrame::Expansion);
                    idx += 2;
                    continue;
                }
                _ => {}
            }
        }
        if stack.last() == Some(&EnvBraceFrame::Literal) && bytes[idx] == b'{' {
            stack.push(EnvBraceFrame::Literal);
            idx += 1;
            continue;
        }
        if bytes[idx] == b'}' {
            let _ = stack.pop();
            if stack.is_empty() {
                return Ok(idx);
            }
            idx += 1;
            continue;
        }
        idx += 1;
    }

    bail!("missing closing '}}'")
}

fn split_braced_default(body: &str) -> Option<(&str, &str)> {
    let bytes = body.as_bytes();
    let mut idx = 0;
    let mut stack = Vec::new();

    while idx < body.len() {
        if bytes[idx] == b'$' && idx + 1 < body.len() {
            match bytes[idx + 1] {
                b'$' => {
                    if idx + 2 < body.len() && bytes[idx + 2] == b'{' {
                        stack.push(EnvBraceFrame::Literal);
                        idx += 3;
                    } else {
                        idx += 2;
                    }
                    continue;
                }
                b'{' => {
                    stack.push(EnvBraceFrame::Expansion);
                    idx += 2;
                    continue;
                }
                _ => {}
            }
        }
        if stack.last() == Some(&EnvBraceFrame::Literal) && bytes[idx] == b'{' {
            stack.push(EnvBraceFrame::Literal);
            idx += 1;
            continue;
        }
        if bytes[idx] == b'}' && !stack.is_empty() {
            let _ = stack.pop();
            idx += 1;
            continue;
        }
        if stack.is_empty() && bytes[idx] == b':' && idx + 1 < body.len() && bytes[idx + 1] == b'-'
        {
            return Some((&body[..idx], &body[idx + 2..]));
        }
        idx += 1;
    }

    None
}

fn is_valid_env_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    !bytes.is_empty()
        && is_env_name_start(bytes[0])
        && bytes[1..].iter().all(|byte| is_env_name_continue(*byte))
}

const fn is_env_name_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

const fn is_env_name_continue(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn child_write(bytes: &[u8]) {
    let mut remaining = bytes;
    while !remaining.is_empty() {
        // SAFETY: `remaining` points to a valid byte slice and STDERR_FILENO is a libc fd
        // constant. This path runs after fork, so keep diagnostics to write(2).
        let written = unsafe {
            libc::write(
                libc::STDERR_FILENO,
                remaining.as_ptr().cast::<libc::c_void>(),
                remaining.len(),
            )
        };
        if written > 0 {
            let Ok(written) = usize::try_from(written) else {
                break;
            };
            let Some(rest) = remaining.get(written..) else {
                break;
            };
            remaining = rest;
            continue;
        }
        if written == -1 {
            let errno = Errno::last();
            if errno == Errno::EINTR {
                continue;
            }
        }
        break;
    }
}

fn child_write_escaped(bytes: &[u8]) {
    for &byte in bytes {
        match byte {
            b'\n' => child_write(b"\\n"),
            b'\r' => child_write(b"\\r"),
            b'\t' => child_write(b"\\t"),
            b'\\' => child_write(b"\\\\"),
            b'\'' => child_write(b"\\'"),
            b'"' => child_write(b"\\\""),
            0x20..=0x7e => child_write_byte(byte),
            _ => {
                child_write(b"\\x");
                child_write_hex_byte(byte);
            }
        }
    }
}

fn child_write_byte(byte: u8) {
    child_write(&[byte]);
}

fn child_write_hex_byte(byte: u8) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    child_write(&[HEX[(byte >> 4) as usize], HEX[(byte & 0x0f) as usize]]);
}

fn child_write_errno(errno: Errno) {
    child_write_u32(errno.raw().cast_unsigned());
}

fn child_write_u32(mut value: u32) {
    let mut buf = [0u8; 12];
    let mut idx = buf.len();
    if value == 0 {
        idx -= 1;
        buf[idx] = b'0';
    } else {
        while value > 0 {
            let digit = (value % 10) as u8;
            idx -= 1;
            buf[idx] = b'0' + digit;
            value /= 10;
        }
    }
    child_write(&buf[idx..]);
}

fn child_write_exec_failure_hint(errno: Errno) {
    match errno {
        Errno::ENOENT => {
            child_write(b": file not found; check the path or PATH lookup");
        }
        Errno::EACCES => {
            child_write(b": permission denied or file is not executable");
        }
        Errno::ENOEXEC => {
            child_write(b": file is not a recognized executable format");
        }
        Errno::ENOTDIR => {
            child_write(b": a path component is not a directory");
        }
        Errno::E2BIG => {
            child_write(b": argument list or environment is too large");
        }
        _ => {}
    }
}

fn report_exec_failure(program: &CString, errno: Errno) -> ! {
    std::hint::cold_path();
    child_write(b"tino: execvp failed for '");
    child_write_escaped(program.as_bytes());
    child_write(b"'");
    child_write_exec_failure_hint(errno);
    child_write(b" (errno ");
    child_write_errno(errno);
    child_write(b")\n");
    unsafe { _exit(exec_failure_exit_code(errno)) }
}

const fn exec_failure_exit_code(errno: Errno) -> libc::c_int {
    match errno {
        Errno::ENOENT | Errno::ENOTDIR => 127,
        _ => 126,
    }
}

fn claim_foreground_tty() {
    // SAFETY: `STDIN_FILENO` is a valid file descriptor constant and the libc calls are used
    // exactly as documented for best-effort tty foreground management.
    unsafe {
        let pgid = libc::getpgrp();
        let _ = libc::tcsetpgrp(libc::STDIN_FILENO, pgid);
    }
}

pub(super) fn spawn_child(
    child_mask: &SigSet,
    child_pdeath: Option<libc::c_int>,
    landlock_config: Option<&landlock::LandlockConfig>,
    pgroup_kill: bool,
    cmd_c: &CString,
    argv_c: &[CString],
) -> Result<Pid> {
    let mut argv_ptrs = argv_c.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(std::ptr::null());
    let expected_parent = current_process_id();

    // SAFETY: the forked child only performs async-signal-safe operations before exec or exit.
    match unsafe { fork_process()? } {
        ForkResult::Child => {
            // Rust ignores SIGPIPE in the supervisor. Do not pass that runtime
            // policy to the managed program; reset it while signals are blocked.
            if SignalAction::set_default(SIGPIPE).is_err() {
                child_write(b"tino: failed to reset SIGPIPE in child\n");
                unsafe { _exit(1) }
            }
            if let Some(sig) = child_pdeath
                && let Err(errno) = set_child_pdeath_signal(sig)
            {
                child_write(b"tino: failed to set child parent-death signal (errno ");
                child_write_errno(errno);
                child_write(b")\n");
                unsafe { _exit(1) }
            }
            if let Some(sig) = child_pdeath
                && parent_process_id() != expected_parent
            {
                let _ = self_signal(sig);
            }
            if pgroup_kill {
                if set_process_group(Pid::from_raw(0), Pid::from_raw(0)).is_ok() {
                    claim_foreground_tty();
                } else {
                    child_write(b"tino: failed to establish child process group\n");
                }
            }
            if child_mask.thread_set_mask().is_err() {
                child_write(b"tino: failed to restore signal mask in child\n");
                unsafe { _exit(1) }
            }
            if let Some(config) = landlock_config
                && let Err(err) = landlock::apply(config)
            {
                report_landlock_failure(config.warn_only, err);
                if !config.warn_only {
                    unsafe { _exit(1) }
                }
            }
            match exec_program(cmd_c, &argv_ptrs) {
                Ok(_) => unsafe { _exit(127) },
                Err(err) => report_exec_failure(cmd_c, err),
            }
        }
        ForkResult::Parent { child } => Ok(child),
    }
}

fn report_landlock_failure(warn_only: bool, err: landlock::LandlockError<'_>) {
    std::hint::cold_path();
    if warn_only {
        child_write(b"tino: access restriction unavailable; continuing (backend landlock: ");
    } else {
        child_write(b"tino: access restriction failed (backend landlock: ");
    }
    match err {
        landlock::LandlockError::NotSupported => {
            child_write(b"not supported (kernel/LSM)");
        }
        landlock::LandlockError::AbiTooOld {
            feature,
            required_abi,
            current_abi,
        } => {
            child_write(feature.as_bytes());
            child_write(b" requires ABI ");
            child_write_u32(required_abi);
            child_write(b" but kernel reports ABI ");
            child_write_u32(current_abi);
        }
        landlock::LandlockError::QueryAbi(errno) => {
            child_write(b"query ABI errno ");
            child_write_errno(errno);
            child_write_seccomp_hint(errno);
        }
        landlock::LandlockError::CreateRuleset(errno) => {
            child_write(b"create ruleset errno ");
            child_write_errno(errno);
            child_write_seccomp_hint(errno);
        }
        landlock::LandlockError::OpenPath { path, errno } => {
            child_write(b"open ");
            child_write_escaped(path.to_bytes());
            child_write(b" errno ");
            child_write_errno(errno);
        }
        landlock::LandlockError::AddRule { path, errno } => {
            child_write(b"add rule ");
            child_write_escaped(path.to_bytes());
            child_write(b" errno ");
            child_write_errno(errno);
            child_write_seccomp_hint(errno);
        }
        landlock::LandlockError::AddNetPortRule {
            port,
            action,
            errno,
        } => {
            child_write(b"add ");
            child_write(action.as_bytes());
            child_write(b" rule for port ");
            child_write_u32(u32::from(port));
            child_write(b" errno ");
            child_write_errno(errno);
            child_write_seccomp_hint(errno);
        }
        landlock::LandlockError::SetNoNewPrivs(errno) => {
            child_write(b"PR_SET_NO_NEW_PRIVS errno ");
            child_write_errno(errno);
        }
        landlock::LandlockError::RestrictSelf(errno) => {
            child_write(b"restrict self errno ");
            child_write_errno(errno);
            child_write_seccomp_hint(errno);
        }
    }
    child_write(b")\n");
}

fn child_write_seccomp_hint(errno: Errno) {
    if errno == Errno::EPERM || errno == Errno::EACCES {
        child_write(b"; blocked by seccomp?");
    }
}

pub(super) fn manage_process_group(requested: bool, child_pid: Pid) -> bool {
    if !requested {
        return false;
    }
    match set_process_group(child_pid, child_pid) {
        Ok(()) => true,
        Err(Errno::EACCES) => match process_group_of(child_pid) {
            Ok(pgid) if pgid == child_pid => true,
            Ok(pgid) => {
                logging::warn(format_args!(
                    "child PID {} is in PGID {} (disabling --pgroup-kill)",
                    child_pid, pgid
                ));
                false
            }
            Err(Errno::ESRCH) => process_group_exists_after_child_exit(child_pid),
            Err(err) => {
                logging::warn(format_args!(
                    "cannot query child process group (disabling --pgroup-kill): {}",
                    err
                ));
                false
            }
        },
        Err(Errno::ESRCH) => process_group_exists_after_child_exit(child_pid),
        Err(err) => {
            logging::warn(format_args!(
                "cannot manage process group (disabling --pgroup-kill): {}",
                err
            ));
            false
        }
    }
}

fn process_group_exists_after_child_exit(child_pid: Pid) -> bool {
    match process_group_exists(child_pid) {
        Ok(exists) => exists,
        Err(err) => {
            logging::warn(format_args!(
                "cannot query process group after child exit (disabling --pgroup-kill): {}",
                err
            ));
            false
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::io;
    use std::mem::size_of;
    use std::sync::{Mutex, MutexGuard, OnceLock};

    struct PrctlStateGuard {
        subreaper: libc::c_int,
        pdeath: libc::c_int,
        _lock: MutexGuard<'static, ()>,
    }

    impl PrctlStateGuard {
        fn capture() -> Self {
            static PRCTL_STATE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

            let lock = PRCTL_STATE_LOCK
                .get_or_init(|| Mutex::new(()))
                .lock()
                .expect("prctl state lock poisoned");
            let mut subreaper = 0;
            let mut pdeath = 0;
            // SAFETY: we pass valid pointers to store the current prctl state.
            let ret = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut subreaper) };
            assert_eq!(
                ret,
                0,
                "PR_GET_CHILD_SUBREAPER failed: {}",
                io::Error::last_os_error()
            );
            // SAFETY: pointer references a valid mutable integer on our stack.
            let ret = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut pdeath) };
            assert_eq!(
                ret,
                0,
                "PR_GET_PDEATHSIG failed: {}",
                io::Error::last_os_error()
            );
            Self {
                subreaper,
                pdeath,
                _lock: lock,
            }
        }
    }

    impl Drop for PrctlStateGuard {
        fn drop(&mut self) {
            // SAFETY: we restore the previously captured values; best-effort errors are ignored.
            unsafe {
                libc::prctl(libc::PR_SET_CHILD_SUBREAPER, self.subreaper);
                libc::prctl(libc::PR_SET_PDEATHSIG, self.pdeath);
            }
        }
    }

    fn base_cli() -> Cli {
        Cli {
            cmd: vec!["/bin/true".into()],
            ..Cli::default()
        }
    }

    #[test]
    fn pdeath_signal_resolves_without_mutating_parent() {
        let guard = PrctlStateGuard::capture();
        let mut cli = base_cli();
        cli.pdeath = Some("SIGUSR1".into());

        let signal = pdeath_signal(&cli).expect("resolve pdeath signal");
        assert_eq!(signal, Some(libc::SIGUSR1));

        let mut current = guard.pdeath;
        // SAFETY: pointer references a valid mutable integer for prctl output.
        let ret = unsafe { libc::prctl(libc::PR_GET_PDEATHSIG, &raw mut current) };
        assert_eq!(
            ret,
            0,
            "PR_GET_PDEATHSIG failed: {}",
            io::Error::last_os_error()
        );
        assert_eq!(current, guard.pdeath);
    }

    #[test]
    fn pdeath_signal_rejects_invalid_signal_without_raw_control_bytes() {
        let mut cli = base_cli();
        cli.pdeath = Some("\u{1b}[31m".into());

        let err = pdeath_signal(&cli).expect_err("invalid pdeath signal must fail");
        let message = format!("{err:#}");

        assert!(message.contains(r"\u{1b}"));
        assert!(!message.contains('\u{1b}'));
    }

    #[test]
    fn configure_parent_prctl_handles_subreaper_capability() {
        let guard = PrctlStateGuard::capture();
        let mut cli = base_cli();
        cli.subreaper = true;

        let outcome =
            configure_parent_prctl(&cli).expect("configure parent prctl with subreaper flag");

        let mut current = guard.subreaper;
        // SAFETY: pointer references a valid mutable integer for prctl output.
        let ret = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut current) };
        assert_eq!(
            ret,
            0,
            "PR_GET_CHILD_SUBREAPER failed: {}",
            io::Error::last_os_error()
        );
        if outcome.subreaper_enabled {
            assert_eq!(current, 1, "subreaper flag expected to be enabled");
        } else {
            assert_eq!(
                current, guard.subreaper,
                "subreaper state should be unchanged when capability is denied"
            );
        }
    }

    #[test]
    fn configure_parent_prctl_restores_subreaper_state_on_drop() {
        let guard = PrctlStateGuard::capture();
        let mut cli = base_cli();
        cli.subreaper = true;

        {
            let outcome =
                configure_parent_prctl(&cli).expect("configure parent prctl with subreaper flag");
            if !outcome.subreaper_enabled {
                return;
            }
            let mut current = guard.subreaper;
            // SAFETY: pointer references a valid mutable integer for prctl output.
            let ret = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut current) };
            assert_eq!(
                ret,
                0,
                "PR_GET_CHILD_SUBREAPER failed: {}",
                io::Error::last_os_error()
            );
            assert_eq!(current, 1, "subreaper flag expected to be enabled");
        }

        let mut current = 1;
        // SAFETY: pointer references a valid mutable integer for prctl output.
        let ret = unsafe { libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut current) };
        assert_eq!(
            ret,
            0,
            "PR_GET_CHILD_SUBREAPER failed: {}",
            io::Error::last_os_error()
        );
        assert_eq!(
            current, guard.subreaper,
            "subreaper state should be restored when the outcome is dropped"
        );
    }

    #[test]
    fn manage_process_group_detects_group_after_leader_exit() {
        let guard = PrctlStateGuard::capture();
        // SAFETY: the test temporarily enables subreaper mode so the forked
        // grandchild remains waitable by this process after the leader exits.
        let ret = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) };
        assert_eq!(
            ret,
            0,
            "PR_SET_CHILD_SUBREAPER failed: {}",
            io::Error::last_os_error()
        );

        let mut pipe_fds = [0; 2];
        // SAFETY: pipe_fds points to two valid integers for pipe2 to initialize.
        let ret = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) };
        assert_eq!(ret, 0, "pipe2 failed: {}", io::Error::last_os_error());

        // SAFETY: this test controls both fork branches and only performs
        // async-signal-safe libc calls before exiting in forked children.
        let leader = unsafe { libc::fork() };
        assert_ne!(
            leader,
            -1,
            "fork leader failed: {}",
            io::Error::last_os_error()
        );
        if leader == 0 {
            // SAFETY: child owns these inherited fds after fork.
            unsafe {
                libc::close(pipe_fds[0]);
                if libc::setpgid(0, 0) == -1 {
                    libc::_exit(101);
                }
                let grandchild = libc::fork();
                if grandchild == -1 {
                    libc::_exit(102);
                }
                if grandchild == 0 {
                    libc::close(pipe_fds[1]);
                    loop {
                        libc::pause();
                    }
                }
                let bytes = (&raw const grandchild).cast::<libc::c_void>();
                let written = libc::write(pipe_fds[1], bytes, size_of::<libc::pid_t>());
                libc::close(pipe_fds[1]);
                if written == size_of::<libc::pid_t>().cast_signed() {
                    libc::_exit(0);
                }
                libc::_exit(103);
            }
        }

        // SAFETY: parent no longer writes to this pipe end.
        unsafe {
            libc::close(pipe_fds[1]);
        }

        let grandchild = read_pid_from_pipe(pipe_fds[0]);
        // SAFETY: parent owns the read end.
        unsafe {
            libc::close(pipe_fds[0]);
        }
        wait_for_pid(leader);

        let detected = manage_process_group(true, Pid::from_raw(leader));

        // SAFETY: leader was the process-group id created by the forked child.
        let _ = unsafe { libc::kill(-leader, libc::SIGKILL) };
        wait_for_pid(grandchild);
        drop(guard);

        assert!(
            detected,
            "process group should remain manageable after the leader exits"
        );
    }

    fn read_pid_from_pipe(fd: libc::c_int) -> libc::pid_t {
        let mut pid: libc::pid_t = 0;
        let mut read_len = 0usize;
        while read_len < size_of::<libc::pid_t>() {
            let offset = read_len;
            // SAFETY: the destination points inside pid's byte representation.
            let rc = unsafe {
                libc::read(
                    fd,
                    (&raw mut pid)
                        .cast::<u8>()
                        .add(offset)
                        .cast::<libc::c_void>(),
                    size_of::<libc::pid_t>() - read_len,
                )
            };
            if rc == -1 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EINTR) {
                    continue;
                }
                panic!("read grandchild pid failed: {err}");
            }
            assert_ne!(rc, 0, "grandchild pid pipe closed before pid was written");
            read_len += usize::try_from(rc).expect("positive read size must fit usize");
        }
        pid
    }

    fn wait_for_pid(pid: libc::pid_t) {
        loop {
            let mut status = 0;
            // SAFETY: pid is a child or subreaper-adopted descendant created by this test.
            let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            if rc == pid {
                return;
            }
            if rc == -1 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            panic!("waitpid({pid}) failed: {}", io::Error::last_os_error());
        }
    }

    #[test]
    fn expand_command_arg_supports_defaults_and_escapes() {
        let suffix = std::process::id();
        let missing_port = format!("__TINO_TEST_MISSING_PORT_{suffix}__");
        let missing_value = format!("__TINO_TEST_MISSING_VALUE_{suffix}__");
        let arg = format!(
            "port=${{{missing_port}:-8900}},literal=$${{HOME}},missing=${{{missing_value}}}"
        );

        let expanded = expand_command_arg(&arg).expect("expand env with defaults and escapes");

        assert_eq!(expanded, "port=8900,literal=${HOME},missing=");
    }

    #[test]
    fn expand_command_arg_supports_escaped_braces_inside_defaults() {
        let missing = format!(
            "__TINO_TEST_MISSING_LITERAL_DEFAULT_{}__",
            std::process::id()
        );
        let arg = format!("${{{missing}:-x$${{HOME}}y}}");

        let expanded = expand_command_arg(&arg).expect("expand escaped default literal");

        assert_eq!(expanded, "x${HOME}y");
    }

    #[test]
    fn expand_command_arg_ignores_default_operator_inside_escaped_literal() {
        let missing = format!(
            "__TINO_TEST_MISSING_LITERAL_OPERATOR_{}__",
            std::process::id()
        );
        let arg = format!("${{{missing}:-x$${{HOME:-fallback}}y}}");

        let expanded = expand_command_arg(&arg).expect("expand escaped operator literal");

        assert_eq!(expanded, "x${HOME:-fallback}y");
    }

    #[test]
    fn expand_command_arg_supports_nested_defaults() {
        let suffix = std::process::id();
        let primary = format!("__TINO_TEST_MISSING_PRIMARY_{suffix}__");
        let fallback = format!("__TINO_TEST_MISSING_FALLBACK_{suffix}__");
        let arg = ["${", &primary, ":-${", &fallback, ":-8900}}"].concat();

        let expanded = expand_command_arg(&arg).expect("expand nested default");

        assert_eq!(expanded, "8900");
    }

    #[test]
    fn expand_command_arg_rejects_invalid_syntax() {
        let err =
            expand_command_arg("${__TINO_TEST_MISSING_PORT_123456__").expect_err("missing brace");
        let message = format!("{err:#}");
        assert!(
            message.contains("missing closing '}'"),
            "unexpected error: {message}"
        );

        let err = expand_command_arg("${NAME:+value}").expect_err("unsupported operator");
        let message = format!("{err:#}");
        assert!(
            message.contains("unsupported braced environment expansion"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn expand_command_arg_leaves_unbraced_dollar_names_unchanged() {
        let missing = format!("__TINO_TEST_MISSING_SERVICE_PORT_{}__", std::process::id());
        let arg = format!("${missing} ${{{missing}:-8900}}");

        let expanded = expand_command_arg(&arg).expect("expand env with unbraced name");

        assert_eq!(expanded, format!("${missing} 8900"));
    }

    #[test]
    fn resolve_command_rejects_empty_program_after_expansion() {
        let missing = format!("__TINO_TEST_MISSING_PROGRAM_{}__", std::process::id());
        let err = resolve_command_args(&[format!("${{{missing}}}")], true)
            .expect_err("expanded empty command must fail");

        assert!(
            format!("{err:#}").contains("command program cannot be empty"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn exec_failure_exit_codes_follow_shell_conventions() {
        assert_eq!(exec_failure_exit_code(Errno::ENOENT), 127);
        assert_eq!(exec_failure_exit_code(Errno::EACCES), 126);
        assert_eq!(exec_failure_exit_code(Errno::ENOEXEC), 126);
        assert_eq!(exec_failure_exit_code(Errno::ENOTDIR), 127);
        assert_eq!(exec_failure_exit_code(Errno::E2BIG), 126);
    }
}
