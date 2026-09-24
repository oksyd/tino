use super::sys::{
    Errno, Pid, SIGABRT, SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGSEGV, SIGSYS, SIGTRAP, SigSet, Signal,
    SignalAction, SignalFd, new_signal_fd, send_process_group_signal, send_process_signal,
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
    block.thread_set_mask().context("sigprocmask")?;

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
