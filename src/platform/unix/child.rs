use crate::{Context, Error, Result, bail, cli::Cli, logging};
use libc::{_exit, PR_GET_CHILD_SUBREAPER, PR_SET_CHILD_SUBREAPER, PR_SET_PDEATHSIG};
use std::{
    env,
    ffi::CString,
    fs::OpenOptions,
    io,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    os::unix::fs::OpenOptionsExt,
    ptr::NonNull,
    sync::atomic::{AtomicBool, Ordering},
};

use super::landlock;
use super::signals;
use super::sys::{
    Errno, ForkResult, Pid, SIGCHLD, SIGPIPE, SigSet, SignalAction, current_process_id,
    exec_program, fork_process, parent_process_id, process_group_exists, process_group_of,
    send_process_group_signal, send_process_signal, set_process_group,
};

#[derive(Default)]
pub(super) struct SubreaperRestore {
    active: bool,
}

impl SubreaperRestore {
    fn restore() -> Result<()> {
        // SAFETY: this guard only undoes its own activation.
        if unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 0) } == -1 {
            return Err(Errno::last()).context("restore child subreaper state");
        }
        Ok(())
    }

    pub(super) fn finish(mut self) -> Result<()> {
        if self.active {
            self.active = false;
            Self::restore()?;
        }
        Ok(())
    }
}

impl Drop for SubreaperRestore {
    fn drop(&mut self) {
        if self.active
            && let Err(err) = Self::restore()
        {
            logging::warn(format_args!(
                "restore child subreaper state failed: {err:#}"
            ));
        }
    }
}

pub(super) fn pdeath_signal(cli: &Cli) -> Result<Option<libc::c_int>> {
    cli.parent_death_signal()
        .map(|signal| signal.map(|signal| signal.number as libc::c_int))
        .map_err(Error::usage)
}

pub(super) fn configure_parent_prctl(cli: &Cli) -> Result<SubreaperRestore> {
    // The namespace init already adopts orphans without the subreaper flag.
    if !cli.subreaper
        || current_process_id().as_raw() == 1
        || current_child_subreaper_state().context("capture child subreaper state")? != 0
    {
        return Ok(SubreaperRestore::default());
    }
    // SAFETY: enabling the child-subreaper flag affects only this process.
    if unsafe { libc::prctl(PR_SET_CHILD_SUBREAPER, 1) } == -1 {
        let err = Errno::last();
        if err != Errno::EPERM {
            bail!("prctl SUBREAPER: {}", err);
        }
        logging::warn(format_args!(
            "subreaper capability rejected; continuing without subreaper: {err}"
        ));
        return Ok(SubreaperRestore::default());
    }
    Ok(SubreaperRestore { active: true })
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

const MAX_ENV_EXPANSION_DEPTH: usize = 32;

pub(super) fn resolve_command_args(mut args: Vec<String>, expand_env: bool) -> Result<Vec<String>> {
    if expand_env {
        for (index, arg) in args.iter_mut().enumerate() {
            if arg.contains('$') {
                *arg = expand_command_arg(arg)
                    .with_context(|| format!("expand environment references in argv[{index}]"))?;
            }
        }
    }
    validate_command_args(&args)?;
    Ok(args)
}

fn validate_command_args(args: &[String]) -> Result<()> {
    if args.first().is_some_and(String::is_empty) {
        return Err(Error::usage("command program cannot be empty"));
    }
    if args.iter().any(|arg| arg.contains('\0')) {
        return Err(Error::usage("command argument contains embedded NUL byte"));
    }
    Ok(())
}

fn expand_command_arg(arg: &str) -> Result<String> {
    let mut expanded = String::with_capacity(arg.len());
    expand_command_arg_into(arg, 0, &mut expanded)?;
    Ok(expanded)
}

fn expand_command_arg_into(mut arg: &str, depth: usize, expanded: &mut String) -> Result<()> {
    if depth > MAX_ENV_EXPANSION_DEPTH {
        return Err(Error::usage(format!(
            "environment expansion nesting exceeds {} levels",
            MAX_ENV_EXPANSION_DEPTH
        )));
    }

    while let Some((literal, tail)) = arg.split_once('$') {
        expanded.push_str(literal);
        if let Some(rest) = tail.strip_prefix('$') {
            expanded.push('$');
            arg = rest;
        } else if let Some(expression) = tail.strip_prefix('{') {
            let (separator, end) = braced_delimiters(expression)?;
            let body = &expression[..end];
            expand_braced_env(body, separator, depth + 1, expanded)?;
            arg = &expression[end + 1..];
        } else {
            expanded.push('$');
            arg = tail;
        }
    }
    expanded.push_str(arg);
    Ok(())
}

fn expand_braced_env(
    body: &str,
    separator: Option<usize>,
    depth: usize,
    expanded: &mut String,
) -> Result<()> {
    let (name, default) =
        separator.map_or((body, None), |idx| (&body[..idx], Some(&body[idx + 2..])));
    if !super::is_env_variable_name(name) {
        return Err(Error::usage(
            "unsupported braced environment expansion (expected ${VAR} or ${VAR:-default})",
        ));
    }
    match env::var(name) {
        Ok(value) if !value.is_empty() => expanded.push_str(&value),
        Ok(_) | Err(env::VarError::NotPresent) => {
            if let Some(fallback) = default {
                expand_command_arg_into(fallback, depth, expanded)?;
            }
        }
        Err(env::VarError::NotUnicode(_)) => {
            bail!("environment variable '{name}' contains non-Unicode data")
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum EnvBraceFrame {
    Expansion,
    Literal,
}

// Locate the first top-level `:-` and the closing brace in the same pass.
fn braced_delimiters(expression: &str) -> Result<(Option<usize>, usize)> {
    let bytes = expression.as_bytes();
    let mut stack = Vec::new();
    let mut separator = None;
    let mut idx = 0;
    loop {
        match &bytes[idx..] {
            [] => return Err(Error::usage("missing closing '}'")),
            [b'$', b'$', b'{', ..] => {
                stack.push(EnvBraceFrame::Literal);
                idx += 3;
            }
            [b'$', b'$', ..] => idx += 2,
            [b'$', b'{', ..] => {
                stack.push(EnvBraceFrame::Expansion);
                idx += 2;
            }
            [b'{', ..] if stack.last() == Some(&EnvBraceFrame::Literal) => {
                stack.push(EnvBraceFrame::Literal);
                idx += 1;
            }
            [b'}', ..] => {
                if stack.pop().is_none() {
                    return Ok((separator, idx));
                }
                idx += 1;
            }
            [b':', b'-', ..] if stack.is_empty() && separator.is_none() => {
                separator = Some(idx);
                idx += 2;
            }
            _ => idx += 1,
        }
    }
}

fn report_exec_failure(program: &CString, errno: Errno) -> ! {
    std::hint::cold_path();
    let hint = match errno {
        Errno::ENOENT => ": file not found; check the path or PATH lookup",
        Errno::EACCES => ": permission denied or file is not executable",
        Errno::ENOEXEC => ": file is not a recognized executable format",
        Errno::ENOTDIR => ": a path component is not a directory",
        Errno::E2BIG => ": argument list or environment is too large",
        _ => "",
    };
    logging::stderr_line(format_args!(
        "tino: execvp failed for '{}'{} (errno {})",
        program.as_bytes().escape_ascii(),
        hint,
        errno.raw()
    ));
    // SAFETY: terminate the forked child without unwinding or running destructors.
    unsafe { _exit(exec_failure_exit_code(errno)) }
}

const fn exec_failure_exit_code(errno: Errno) -> libc::c_int {
    match errno {
        Errno::ENOENT | Errno::ENOTDIR => 127,
        _ => 126,
    }
}

pub(super) struct ControllingTerminal {
    fd: OwnedFd,
    job_group: Pid,
    foreground_on_launch: bool,
}

impl ControllingTerminal {
    pub(super) fn open() -> Option<Self> {
        let session = unsafe { libc::getsid(0) };
        if session == -1 {
            return None;
        }
        let in_session =
            |fd: &std::os::fd::BorrowedFd<'_>| unsafe { libc::tcgetsid(fd.as_raw_fd()) == session };
        let fd = [
            io::stdin().as_fd(),
            io::stdout().as_fd(),
            io::stderr().as_fd(),
        ]
        .into_iter()
        .find(in_session)
        .and_then(|fd| fd.try_clone_to_owned().ok())
        .or_else(|| {
            let file = OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOCTTY | libc::O_NONBLOCK)
                .open("/dev/tty")
                .ok()?;
            in_session(&file.as_fd()).then(|| file.into())
        })?;
        let job_group = process_group_of(Pid::from_raw(0)).ok()?;
        let supervisor = current_process_id();
        // A shell pipeline shares its foreground group. Leave it there unless
        // the managed command actually needs the terminal (SIGTTIN/SIGTTOU).
        let foreground_on_launch = supervisor == job_group
            && (supervisor.as_raw() == session
                || ![libc::STDIN_FILENO, libc::STDOUT_FILENO]
                    .into_iter()
                    .any(is_pipe));
        Some(Self {
            fd,
            job_group,
            foreground_on_launch,
        })
    }

    // The shell may have assigned the terminal to another job since launch.
    fn transfer(&self, from: Pid, to: Pid) -> std::result::Result<bool, Errno> {
        let fd = self.fd.as_raw_fd();
        let foreground = unsafe { libc::tcgetpgrp(fd) };
        if foreground == -1 {
            return Err(Errno::last());
        }
        if foreground != from.as_raw() || from == to {
            return Ok(false);
        }
        if unsafe { libc::tcsetpgrp(fd, to.as_raw()) } == -1 {
            return Err(Errno::last());
        }
        Ok(true)
    }
}

fn is_pipe(fd: libc::c_int) -> bool {
    let mut stat = std::mem::MaybeUninit::uninit();
    // SAFETY: fstat initializes stat on success.
    unsafe {
        libc::fstat(fd, stat.as_mut_ptr()) == 0
            && stat.assume_init().st_mode & libc::S_IFMT == libc::S_IFIFO
    }
}

pub(super) struct TerminalJob {
    tty: ControllingTerminal,
    child_group: Pid,
    launch_gate: Option<io::PipeWriter>,
}

impl TerminalJob {
    pub(super) fn new(
        tty: ControllingTerminal,
        separate_group: Option<Pid>,
        launch_gate: Option<io::PipeWriter>,
    ) -> Self {
        Self {
            child_group: separate_group.unwrap_or(tty.job_group),
            tty,
            launch_gate,
        }
    }

    pub(super) fn release_child_when_ready(
        &mut self,
        signal_fd: &super::sys::SignalFd,
    ) -> Result<()> {
        if self.launch_gate.is_some() {
            // A terminal event before fork only reached the supervisor. Let the
            // normal signal loop relay queued terminal signals while the child is
            // still blocking them, so any copy it already has coalesces.
            let pending = SigSet::pending().context("query pending terminal signals")?;
            if !Self::FOREGROUND_SIGNALS
                .iter()
                .any(|&sig| signal_fd.accepts(sig) && pending.contains_raw(sig))
            {
                drop(self.launch_gate.take());
            }
        }
        Ok(())
    }

    const FOREGROUND_SIGNALS: [i32; 4] =
        [libc::SIGINT, libc::SIGQUIT, libc::SIGTSTP, libc::SIGWINCH];

    pub(super) fn signaled_foreground_group(&self, info: &libc::signalfd_siginfo) -> Option<Pid> {
        // Linux broadcasts keyboard and window-size signals to the foreground group.
        // A userspace signal sent directly to the supervisor has a different code.
        (self.launch_gate.is_none()
            && info.ssi_code == libc::SI_KERNEL
            && Self::FOREGROUND_SIGNALS.contains(&info.ssi_signo.cast_signed()))
        .then(|| Pid::from_raw(unsafe { libc::getpgrp() }))
    }

    /// Returns true if the supervisor stopped and has since been continued.
    pub(super) fn handle_child_stop(&self, child_pid: Pid, signal: i32) -> bool {
        // A shell can foreground a running background job without sending CONT.
        // Its first terminal I/O then stops the separate child group.
        let terminal_io = matches!(signal, libc::SIGTTIN | libc::SIGTTOU);
        if terminal_io && self.give_terminal_to_child() {
            signals::send_signal(true, self.child_group, libc::SIGCONT);
            return false;
        }
        if process_group_of(child_pid).ok() != Some(self.child_group) {
            return false;
        }
        let supervisor = current_process_id();
        let parent = parent_process_id();
        let parent_group = process_group_of(parent).ok();
        // Only synchronize stops with a parent outside our group in the same
        // session. An orphan group or a caller sharing its parent's group has
        // no established job-control parent to resume a forced SIGSTOP.
        let session = unsafe { libc::getsid(0) };
        if process_group_of(supervisor).ok() != Some(self.tty.job_group)
            || parent_group.is_none_or(|group| group == self.tty.job_group)
            || session == -1
            || unsafe { libc::getsid(parent.as_raw()) } != session
        {
            return false;
        }
        // A background read also stops the shell job. Only return the terminal
        // when it was held by a separate child group.
        let had_terminal = match self.tty.transfer(self.child_group, self.tty.job_group) {
            Ok(transferred) => transferred,
            Err(err) => {
                logging::warn(format_args!(
                    "return foreground terminal before stopping: {err}"
                ));
                return false;
            }
        };
        // While the child held the terminal, Ctrl-Z missed the shell pipeline.
        // Suspend its peers as well, keeping the session leader's group alive.
        let suspended_pipeline =
            had_terminal && signal == libc::SIGTSTP && self.tty.job_group.as_raw() != session;
        let stopped = if supervisor == self.tty.job_group || suspended_pipeline {
            send_process_group_signal(self.tty.job_group, libc::SIGSTOP)
        } else {
            send_process_signal(supervisor, libc::SIGSTOP)
        };
        if let Err(err) = stopped {
            logging::warn(format_args!("stop foreground supervisor: {err}"));
            return false;
        }
        // Upon fg, restore the terminal only to a command that used or
        // requested it. A resumed pipeline otherwise keeps keyboard signals.
        if had_terminal || terminal_io {
            self.give_terminal_to_child();
        }
        true
    }

    fn give_terminal_to_child(&self) -> bool {
        // `fg` hands the terminal to the supervisor before sending CONT; `bg`
        // does not. Only the foreground case should hand it on to the child.
        if self.tty.job_group == self.child_group
            || process_group_of(self.child_group).ok() != Some(self.child_group)
        {
            return false;
        }
        self.tty
            .transfer(self.tty.job_group, self.child_group)
            .unwrap_or_else(|err| {
                logging::warn(format_args!("give foreground terminal to child: {err}"));
                false
            })
    }
}

impl Drop for TerminalJob {
    fn drop(&mut self) {
        // Restore only a terminal still owned by the group we handed it to.
        // Another job may have taken foreground ownership during supervision.
        // SIGTTOU remains blocked until the supervisor's signal guard is dropped.
        if self.tty.job_group != self.child_group {
            let _ = self.tty.transfer(self.child_group, self.tty.job_group);
        }
    }
}

// The supervisor checks this flag after reaping. The mapping is shared across
// fork and discarded in the child on exec, without a handshake or an extra fd.
pub(super) struct ExecStatus(NonNull<AtomicBool>);

impl ExecStatus {
    pub(super) fn new() -> io::Result<Self> {
        let len = size_of::<AtomicBool>();
        // SAFETY: request a fresh, page-aligned mapping shared only across fork.
        let addr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        let Some(flag) = NonNull::<AtomicBool>::new(addr.cast()) else {
            // SAFETY: release the mapping, which cannot hold a Rust reference at zero.
            unsafe { libc::munmap(addr, len) };
            return Err(io::Error::other("child launch flag mapped at address zero"));
        };
        // SAFETY: initialize the new mapping before sharing it with the child.
        unsafe { flag.write(AtomicBool::new(false)) };
        Ok(Self(flag))
    }

    fn flag(&self) -> &AtomicBool {
        // SAFETY: the initialized mapping lives for self's lifetime in each process.
        unsafe { self.0.as_ref() }
    }

    pub(super) fn can_remap(&self) -> bool {
        self.flag().load(Ordering::Acquire)
    }
}

impl Drop for ExecStatus {
    fn drop(&mut self) {
        // SAFETY: unmap exactly the region owned by this process.
        unsafe { libc::munmap(self.0.as_ptr().cast(), size_of::<AtomicBool>()) };
    }
}

pub(super) struct ChildSignals<'a> {
    pub mask: &'a SigSet,
    pub ignore_sigchld: bool,
    pub pdeath: Option<libc::c_int>,
}

pub(super) fn spawn_child(
    child_signals: ChildSignals<'_>,
    landlock_config: Option<&landlock::LandlockConfig>,
    pgroup_kill: bool,
    terminal: Option<&ControllingTerminal>,
    args: Vec<String>,
    exec_status: Option<&ExecStatus>,
) -> Result<(Pid, Option<io::PipeWriter>)> {
    let argv = args
        .into_iter()
        .map(CString::new)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|_| Error::usage("command argument contains embedded NUL byte"))?;
    let program = argv
        .first()
        .ok_or_else(|| Error::usage("missing CMD (use --help)"))?;
    let gate = terminal
        .map(|_| io::pipe())
        .transpose()
        .context("open terminal launch pipe")?;
    let mut argv_ptrs = argv.iter().map(|arg| arg.as_ptr()).collect::<Vec<_>>();
    argv_ptrs.push(std::ptr::null());
    let expected_parent = current_process_id();

    // SAFETY: the forked child only performs async-signal-safe operations before exec or exit.
    match unsafe { fork_process()? } {
        ForkResult::Child => {
            // Match exec's disposition reset before unblocking signals or
            // applying restrictions. A forwarded signal in that window must
            // not execute a library caller's inherited handler in the child.
            if let Err(errno) = SignalAction::reset_caught_handlers() {
                logging::stderr_line(format_args!(
                    "tino: failed to reset child signal handlers (errno {})",
                    errno.raw()
                ));
                unsafe { _exit(1) }
            }
            // Rust ignores SIGPIPE in the supervisor. Do not pass that runtime
            // policy to the managed program; reset it while signals are blocked.
            if SignalAction::set_default(SIGPIPE).is_err() {
                logging::stderr_line(format_args!("tino: failed to reset SIGPIPE in child"));
                unsafe { _exit(1) }
            }
            // Linux exec preserves an explicit SIG_IGN. Only the supervisor
            // needs SIGCHLD at its default disposition to reap the main child.
            if child_signals.ignore_sigchld
                && SignalAction::set_ignored_raw(SIGCHLD as libc::c_int).is_err()
            {
                logging::stderr_line(format_args!("tino: failed to restore SIGCHLD in child"));
                unsafe { _exit(1) }
            }
            if let Some(sig) = child_signals.pdeath
                && let Err(errno) = set_child_pdeath_signal(sig)
            {
                logging::stderr_line(format_args!(
                    "tino: failed to set child parent-death signal (errno {})",
                    errno.raw()
                ));
                unsafe { _exit(1) }
            }
            if let Some(sig) = child_signals.pdeath
                && parent_process_id() != expected_parent
            {
                let _ = send_process_signal(current_process_id(), sig);
            }
            if pgroup_kill {
                if set_process_group(Pid::from_raw(0), Pid::from_raw(0)).is_ok() {
                    if let Some(tty) = terminal
                        && tty.foreground_on_launch
                    {
                        let _ = tty.transfer(tty.job_group, current_process_id());
                    }
                } else {
                    logging::stderr_line(format_args!(
                        "tino: failed to establish child process group"
                    ));
                }
            }
            if let Some((reader, writer)) = gate {
                drop(writer);
                let mut byte = 0u8;
                // EOF releases the child once startup interrupts have been handled.
                while unsafe { libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) } == -1 {
                    if Errno::last() != Errno::EINTR {
                        logging::stderr_line(format_args!(
                            "tino: failed to synchronize terminal launch"
                        ));
                        unsafe { _exit(1) }
                    }
                }
            }
            if child_signals.mask.thread_set_mask().is_err() {
                logging::stderr_line(format_args!("tino: failed to restore signal mask in child"));
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
            // A signal during exec counts as signal termination of the command.
            // If exec returns, restore startup-error handling before reporting it.
            let mark_exec = |started| {
                if let Some(status) = exec_status {
                    status.flag().store(started, Ordering::Release);
                }
            };
            mark_exec(true);
            let Err(err) = exec_program(program, &argv_ptrs);
            mark_exec(false);
            report_exec_failure(program, err)
        }
        ForkResult::Parent { child } => Ok((child, gate.map(|(_, writer)| writer))),
    }
}

fn report_landlock_failure(warn_only: bool, err: landlock::LandlockError<'_>) {
    std::hint::cold_path();
    let outcome = if warn_only {
        "unavailable; continuing"
    } else {
        "failed"
    };
    logging::stderr_line(format_args!(
        "tino: access restriction {outcome} (backend landlock: {err})"
    ));
}

pub(super) fn manage_process_group(requested: bool, child_pid: Pid) -> bool {
    if !requested {
        return false;
    }
    match set_process_group(child_pid, child_pid) {
        Ok(()) => true,
        // After exec or exit the original group may still contain workers,
        // even if its leader has since joined another group.
        Err(Errno::EACCES | Errno::ESRCH) => match process_group_exists(child_pid) {
            Ok(exists) => exists,
            Err(err) => {
                logging::warn(format_args!(
                    "cannot query child process group (disabling --pgroup-kill): {}",
                    err
                ));
                false
            }
        },
        Err(err) => {
            logging::warn(format_args!(
                "cannot manage process group (disabling --pgroup-kill): {}",
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

        let expected = Cli::try_parse_from(["tino", "--parent-death-signal", "\u{1b}[31m"])
            .unwrap_err()
            .to_string();
        assert_eq!(message, expected);
        assert_eq!(crate::run(cli).unwrap_err().to_string(), expected);
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
        if outcome.active {
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
            if !outcome.active {
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
    fn manage_process_group_tracks_workers_after_leader_moves_or_exits() {
        let _lock = super::super::CHILD_TEST_LOCK.lock().unwrap();
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
                if written == size_of::<libc::pid_t>().cast_signed()
                    && libc::setpgid(0, libc::getpgid(libc::getppid())) == 0
                {
                    libc::execl(
                        c"/bin/sleep".as_ptr(),
                        c"sleep".as_ptr(),
                        c"30".as_ptr(),
                        std::ptr::null::<libc::c_char>(),
                    );
                }
                libc::_exit(103);
            }
        }

        // SAFETY: parent no longer writes to this pipe end.
        unsafe {
            libc::close(pipe_fds[1]);
        }

        let grandchild = read_pid_from_pipe(pipe_fds[0]);
        // The close-on-exec pipe reaches EOF after the leader has changed groups
        // and execed. Its worker still belongs to the original group.
        let mut byte = 0u8;
        assert_eq!(
            unsafe { libc::read(pipe_fds[0], (&raw mut byte).cast(), 1) },
            0
        );
        let moved = manage_process_group(true, Pid::from_raw(leader));
        // SAFETY: the parent owns the read end and the leader is its unreaped child.
        unsafe {
            libc::close(pipe_fds[0]);
            libc::kill(leader, libc::SIGKILL);
        }
        let leader_status = wait_for_pid(leader);

        let detected = manage_process_group(true, Pid::from_raw(leader));

        // SAFETY: leader was the process-group id created by the forked child.
        let _ = unsafe { libc::kill(-leader, libc::SIGKILL) };
        wait_for_pid(grandchild);
        drop(guard);

        assert!(libc::WIFSIGNALED(leader_status));
        assert_eq!(libc::WTERMSIG(leader_status), libc::SIGKILL);
        assert!(
            moved,
            "workers should remain managed after the leader changes groups"
        );
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

    fn wait_for_pid(pid: libc::pid_t) -> libc::c_int {
        loop {
            let mut status = 0;
            // SAFETY: pid is a child or subreaper-adopted descendant created by this test.
            let rc = unsafe { libc::waitpid(pid, &raw mut status, 0) };
            if rc == pid {
                return status;
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
        let err = resolve_command_args(vec![format!("${{{missing}}}")], true)
            .expect_err("expanded empty command must fail");

        assert!(
            format!("{err:#}").contains("command program cannot be empty"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn resolve_command_rejects_nul_bytes_in_program_and_arguments() {
        for expand_env in [false, true] {
            for args in [
                vec!["/bin/tr\0ue".into()],
                vec!["/bin/true".into(), "embedded\0argument".into()],
            ] {
                let err = resolve_command_args(args, expand_env)
                    .expect_err("NUL bytes must fail during shared command validation");
                assert_eq!(err.exit_code(), 2);
                assert!(err.to_string().contains("embedded NUL byte"));
            }
            assert!(
                resolve_command_args(vec![], expand_env)
                    .expect("explain may omit a command")
                    .is_empty()
            );
        }
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
