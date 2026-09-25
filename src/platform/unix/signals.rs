use super::sys::{
    Errno, Pid, SIGABRT, SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGPIPE, SIGSEGV, SIGSYS, SIGTRAP,
    SigSet, Signal, SignalAction, SignalFd, current_process_id, new_signal_fd,
    send_process_group_signal, send_process_signal,
};
use crate::{Context, Result, bail, logging};

const SIGNALS_EXCLUDED_FROM_SIGNALFD: &[Signal] =
    &[SIGFPE, SIGILL, SIGSEGV, SIGBUS, SIGABRT, SIGTRAP, SIGSYS];

pub(super) struct ChildReapingRestore(SignalAction);

impl ChildReapingRestore {
    pub(super) fn enable() -> Result<Self> {
        SignalAction::set_default(SIGCHLD)
            .map(Self)
            .context("reset SIGCHLD disposition")
    }
}

impl Drop for ChildReapingRestore {
    fn drop(&mut self) {
        if let Err(err) = self.0.restore(SIGCHLD) {
            logging::warn(format_args!("restore SIGCHLD disposition failed: {err}"));
        }
    }
}

pub(super) fn setup_signal_delivery() -> Result<(SigSet, SignalFd)> {
    // Signal dispositions and child reaping belong to the whole process, while
    // pthread_sigmask only affects this thread. Reject an unsafe host before
    // changing either state or forking a child.
    let tasks = std::fs::read_dir("/proc/self/task")
        .context("inspect process threads (tino requires procfs mounted at /proc)")?;
    for (index, task) in tasks.enumerate() {
        task.context("inspect process thread")?;
        if index != 0 {
            bail!(
                "tino::run requires a single-threaded process; launch the tino binary from a multithreaded host"
            );
        }
    }
    let previous_mask = SigSet::thread_get_mask().context("sigprocmask")?;
    let mut block = SigSet::all();
    for &signal in SIGNALS_EXCLUDED_FROM_SIGNALFD {
        block.remove(signal);
    }
    // Excluded signals must not be consumed by signalfd, but they may already
    // be blocked (and pending) in a library caller or the binary's launcher.
    // Preserve those bits instead of unexpectedly delivering a fatal signal.
    let mut supervisor_mask = block.clone();
    for &signal in SIGNALS_EXCLUDED_FROM_SIGNALFD {
        if previous_mask.contains_raw(signal as libc::c_int) {
            supervisor_mask.add(signal);
        }
    }
    supervisor_mask.thread_set_mask().context("sigprocmask")?;

    let signal_fd = match new_signal_fd(&block).context("signalfd") {
        Ok(signal_fd) => signal_fd,
        Err(err) => {
            let _ = previous_mask.thread_set_mask();
            return Err(err);
        }
    };

    Ok((previous_mask, signal_fd))
}

pub(super) fn signal_by_name(name: &str) -> Option<Signal> {
    crate::signals::signal_from_str(name)
}

struct SignalDispositionRestore {
    signal: libc::c_int,
    action: SignalAction,
}

impl Drop for SignalDispositionRestore {
    fn drop(&mut self) {
        if let Err(err) = self.action.restore_raw(self.signal) {
            logging::warn(format_args!(
                "restore signal {} disposition failed: {err}",
                self.signal
            ));
        }
    }
}

pub(super) fn restore_signal_delivery(previous_mask: &SigSet) -> Result<()> {
    // A bounded final batch can leave queued signals behind. Temporarily
    // ignore signals that supervision blocked but the caller did not: the
    // kernel discards their backlog without another unbounded drain loop.
    // Keep them ignored while unblocking, then restore the caller's actions.
    // Signals the caller already blocked retain both their mask and backlog.
    let current_mask = SigSet::thread_get_mask();
    let mut restore = Vec::new();
    if let Ok(current_mask) = current_mask {
        for signal in 1..=libc::SIGRTMAX() {
            // SIGCHLD is never forwarded. Ignoring it here could discard exit
            // status for children still owned by a library caller.
            if signal != SIGCHLD as libc::c_int
                && current_mask.contains_raw(signal)
                && !previous_mask.contains_raw(signal)
            {
                match SignalAction::set_ignored_raw(signal) {
                    Ok(action) => restore.push(SignalDispositionRestore { signal, action }),
                    Err(err) => logging::warn(format_args!(
                        "discard pending signal {signal} failed: {err}"
                    )),
                }
            }
        }
    }
    let result = previous_mask
        .thread_set_mask()
        .context("restore signal mask");
    drop(restore);
    result
}

pub(super) fn read_forwardable_signal(
    signal_fd: &mut SignalFd,
    budget: &mut usize,
) -> Result<Option<libc::signalfd_siginfo>> {
    while *budget > 0 {
        let Some(info) = signal_fd.read_signal()? else {
            return Ok(None);
        };
        // Ignored signals also consume the budget so filtering cannot prevent
        // the supervisor from checking its shutdown deadline.
        *budget -= 1;
        // Linux attributes pipe-write SIGPIPE to the writing process. Failed
        // supervisor logging must not terminate a healthy managed command.
        // External SIGPIPE still has its sender's PID and must be forwarded.
        if info.ssi_signo == SIGPIPE as u32
            && info.ssi_pid == current_process_id().as_raw().cast_unsigned()
        {
            continue;
        }
        return Ok(Some(info));
    }
    Ok(None)
}

pub(super) fn send_signal(pgid: bool, child: Pid, sig: libc::c_int) {
    let res = if pgid {
        send_process_group_signal(child, sig)
    } else {
        send_process_signal(child, sig)
    };
    if let Err(e) = res
        && e != Errno::ESRCH
    {
        logging::warn(format_args!("forward signal {} failed: {}", sig, e));
    }
}
