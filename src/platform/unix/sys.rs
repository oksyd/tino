use std::ffi::{CStr, CString};
use std::fmt;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

pub(super) type Result<T> = std::result::Result<T, Errno>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(crate) struct Errno(i32);

impl Errno {
    pub(super) const E2BIG: Self = Self(libc::E2BIG);
    pub(super) const EACCES: Self = Self(libc::EACCES);
    pub(super) const EAGAIN: Self = Self(libc::EAGAIN);
    pub(super) const ECHILD: Self = Self(libc::ECHILD);
    pub(super) const EINVAL: Self = Self(libc::EINVAL);
    pub(super) const EINTR: Self = Self(libc::EINTR);
    pub(super) const EIO: Self = Self(libc::EIO);
    pub(super) const ENOENT: Self = Self(libc::ENOENT);
    pub(super) const ENOEXEC: Self = Self(libc::ENOEXEC);
    pub(super) const ENOSYS: Self = Self(libc::ENOSYS);
    pub(super) const ENOTDIR: Self = Self(libc::ENOTDIR);
    pub(super) const EOPNOTSUPP: Self = Self(libc::EOPNOTSUPP);
    pub(super) const EPERM: Self = Self(libc::EPERM);
    pub(super) const ESRCH: Self = Self(libc::ESRCH);

    pub(super) fn last() -> Self {
        // SAFETY: Linux exposes thread-local errno via __errno_location().
        // This avoids constructing std::io::Error on fork-child failure paths.
        Self(unsafe { *libc::__errno_location() })
    }

    pub(super) const fn from_raw(code: i32) -> Self {
        Self(code)
    }

    pub(super) const fn raw(self) -> i32 {
        self.0
    }
}

impl fmt::Display for Errno {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", std::io::Error::from_raw_os_error(self.0))
    }
}

impl std::error::Error for Errno {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct Pid(libc::pid_t);

impl Pid {
    pub(super) const fn from_raw(pid: libc::pid_t) -> Self {
        Self(pid)
    }

    pub(super) const fn as_raw(self) -> libc::pid_t {
        self.0
    }
}

impl fmt::Display for Pid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ForkResult {
    Parent { child: Pid },
    Child,
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub(crate) enum Signal {
    SIGHUP = libc::SIGHUP,
    SIGINT = libc::SIGINT,
    SIGQUIT = libc::SIGQUIT,
    SIGILL = libc::SIGILL,
    SIGTRAP = libc::SIGTRAP,
    SIGABRT = libc::SIGABRT,
    SIGBUS = libc::SIGBUS,
    SIGFPE = libc::SIGFPE,
    SIGKILL = libc::SIGKILL,
    SIGUSR1 = libc::SIGUSR1,
    SIGSEGV = libc::SIGSEGV,
    SIGUSR2 = libc::SIGUSR2,
    SIGPIPE = libc::SIGPIPE,
    SIGALRM = libc::SIGALRM,
    SIGTERM = libc::SIGTERM,
    SIGCHLD = libc::SIGCHLD,
    SIGCONT = libc::SIGCONT,
    SIGWINCH = libc::SIGWINCH,
    SIGTSTP = libc::SIGTSTP,
    SIGTTIN = libc::SIGTTIN,
    SIGTTOU = libc::SIGTTOU,
    SIGSYS = libc::SIGSYS,
}

pub(super) use Signal::{
    SIGABRT, SIGBUS, SIGCHLD, SIGFPE, SIGILL, SIGINT, SIGKILL, SIGPIPE, SIGQUIT, SIGSEGV, SIGSYS,
    SIGTERM, SIGTRAP, SIGTTIN, SIGTTOU,
};

pub(crate) struct DiagnosticWriteGuard {
    restore_mask: SigSet,
    pending_before: SigSet,
}

impl DiagnosticWriteGuard {
    // Uses only stack storage and signal-safe calls, including in a forked child.
    pub(crate) fn new() -> Option<Self> {
        let mut blocked = SigSet::empty();
        blocked.add_raw(libc::SIGPIPE);
        blocked.add_raw(libc::SIGXFSZ);
        let mut guard = Self {
            restore_mask: blocked.block_on_thread().ok()?,
            pending_before: SigSet::empty(),
        };
        // Dropping the guard restores the mask if the pending set cannot be read.
        guard.pending_before = SigSet::pending().ok()?;
        Some(guard)
    }

    pub(crate) fn consume_failure(&mut self, errno: libc::c_int) {
        let signal = match errno {
            libc::EPIPE => libc::SIGPIPE,
            libc::EFBIG => libc::SIGXFSZ,
            _ => return,
        };
        if self.pending_before.contains_raw(signal) {
            return;
        }
        let mut consume = SigSet::empty();
        consume.add_raw(signal);
        // The signal remains blocked; consume only a newly pending
        // write-failure signal before restoring the caller's original mask.
        // Count interruptions too so a denied syscall cannot stall cleanup.
        for _ in 0..64 {
            match consume.wait_nohang() {
                Ok(_) => return,
                Err(Errno::EINTR) => {}
                Err(_) => break,
            }
        }
        // Cleanup can be denied by seccomp. Preserve this blocked bit rather
        // than deliver our write-generated signal into the calling process.
        self.restore_mask.add_raw(signal);
    }
}

impl Drop for DiagnosticWriteGuard {
    fn drop(&mut self) {
        let _ = self.restore_mask.thread_set_mask();
    }
}

pub(crate) struct DiagnosticWriter {
    fd: OwnedFd,
    target: DiagnosticTarget,
    remaining_retries: usize,
    signals: DiagnosticWriteGuard,
    buffer: [u8; libc::PIPE_BUF],
    buffered: usize,
}

enum DiagnosticTarget {
    Direct,
    Socket,
    InheritedPipe,
}

impl DiagnosticWriter {
    // Only stack storage and async-signal-safe calls are used so exec failure
    // diagnostics can use the same writer after fork.
    pub(crate) fn stderr() -> Option<Self> {
        let signals = DiagnosticWriteGuard::new()?;
        // Pin the descriptor before classifying it: configuration-only calls
        // can run in hosts whose other threads redirect stderr with dup2.
        let fd = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_DUPFD_CLOEXEC, 3) };
        if fd == -1 {
            return None;
        }
        // SAFETY: fcntl returned a fresh descriptor owned by this writer.
        let pinned = unsafe { OwnedFd::from_raw_fd(fd) };
        let flags = unsafe { libc::fcntl(pinned.as_raw_fd(), libc::F_GETFL) };
        if flags == -1
            || flags & libc::O_PATH != 0
            || !matches!(flags & libc::O_ACCMODE, libc::O_WRONLY | libc::O_RDWR)
        {
            // Reopening must not turn a read-only or path-only stderr
            // descriptor into a writable channel that the caller did not pass.
            return None;
        }
        let mut original = unsafe { zeroed::<libc::stat>() };
        if unsafe { libc::fstat(pinned.as_raw_fd(), &raw mut original) } == -1 {
            return None;
        }
        let kind = original.st_mode & libc::S_IFMT;
        // Opening Linux's /dev/ptmx (5:2) would create a new terminal pair.
        // Leave that descriptor and non-terminal character devices alone.
        let terminal = kind == libc::S_IFCHR
            && original.st_rdev != libc::makedev(5, 2)
            && unsafe { libc::isatty(fd) } == 1;
        let (fd, target) = if kind == libc::S_IFIFO || terminal {
            use std::io::Write as _;

            // Isolate O_NONBLOCK from the managed command. Refer to the pinned
            // fd because a library caller can redirect stderr concurrently.
            let mut path = [0; 32];
            write!(&mut &mut path[..], "/proc/self/fd/{fd}").ok()?;
            let path = CStr::from_bytes_until_nul(&path).ok()?;
            let fd = unsafe {
                libc::open(
                    path.as_ptr(),
                    libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOCTTY,
                )
            };
            if fd >= 0 {
                // SAFETY: open returned a fresh descriptor owned by this writer.
                (
                    unsafe { OwnedFd::from_raw_fd(fd) },
                    DiagnosticTarget::Direct,
                )
            } else if kind == libc::S_IFIFO {
                (pinned, DiagnosticTarget::InheritedPipe)
            } else {
                return None;
            }
        } else if kind == libc::S_IFSOCK {
            (pinned, DiagnosticTarget::Socket)
        } else {
            // Preserve shared offsets and append behavior for regular files.
            (pinned, DiagnosticTarget::Direct)
        };
        Some(Self {
            fd,
            target,
            remaining_retries: 64,
            signals,
            buffer: [0; libc::PIPE_BUF],
            buffered: 0,
        })
    }

    fn flush(&mut self) -> fmt::Result {
        let mut bytes = &self.buffer[..std::mem::take(&mut self.buffered)];
        while !bytes.is_empty() {
            // SAFETY: bytes is valid for this length and the descriptor remains
            // borrowed or owned for the writer's lifetime. Socket flags apply
            // to this send only, leaving the caller's descriptor flags intact.
            let fd = self.fd.as_raw_fd();
            let written = match self.target {
                DiagnosticTarget::Socket => byte_count(unsafe {
                    libc::send(
                        fd,
                        bytes.as_ptr().cast(),
                        bytes.len(),
                        libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL,
                    )
                }),
                DiagnosticTarget::Direct => {
                    byte_count(unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) })
                }
                DiagnosticTarget::InheritedPipe => write_inherited_pipe(fd, bytes),
            };
            match written {
                Ok(count) if count == bytes.len() => break,
                Ok(0) => return Err(fmt::Error),
                Ok(count) => bytes = bytes.get(count..).ok_or(fmt::Error)?,
                Err(Errno::EINTR) => {}
                Err(errno) => {
                    // MSG_NOSIGNAL already suppresses socket write signals.
                    if !matches!(self.target, DiagnosticTarget::Socket) {
                        self.signals.consume_failure(errno.raw());
                    }
                    return Err(fmt::Error);
                }
            }
            self.remaining_retries = self.remaining_retries.checked_sub(1).ok_or(fmt::Error)?;
        }
        Ok(())
    }
}

impl fmt::Write for DiagnosticWriter {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        // Keep a short diagnostic in one pipe write or socket record even when
        // the formatter produces several fragments. Longer messages stream out.
        let mut bytes = value.as_bytes();
        while !bytes.is_empty() {
            let count = bytes.len().min(self.buffer.len() - self.buffered);
            let (part, rest) = bytes.split_at(count);
            self.buffer[self.buffered..self.buffered + count].copy_from_slice(part);
            self.buffered += count;
            if self.buffered == self.buffer.len() {
                self.flush()?;
            }
            bytes = rest;
        }
        Ok(())
    }
}

impl Drop for DiagnosticWriter {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

fn byte_count(result: isize) -> Result<usize> {
    if result < 0 {
        Err(Errno::last())
    } else {
        Ok(result.cast_unsigned())
    }
}

fn write_inherited_pipe(fd: libc::c_int, bytes: &[u8]) -> Result<usize> {
    let iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // SAFETY: the iovec borrows bytes for one write. Both offset words are all
    // ones for offset -1 on 32- and 64-bit Linux. NOWAIT leaves fd flags alone.
    let written = byte_count(unsafe {
        libc::syscall(
            libc::SYS_pwritev2,
            fd,
            &raw const iov,
            1,
            -1 as libc::c_long,
            -1 as libc::c_long,
            libc::RWF_NOWAIT,
        ) as isize
    });
    if !matches!(
        written,
        Err(Errno::ENOSYS | Errno::EOPNOTSUPP | Errno::EPERM | Errno::EACCES)
    ) {
        return written;
    }
    // Older kernels and filtered containers can still relay one bounded chunk
    // into a free pipe slot without changing or blocking the inherited writer.
    let mut fds = [-1; 2];
    errno_unit(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) })?;
    // SAFETY: pipe2 created two independently owned descriptors.
    let [reader, writer] = fds.map(|raw| unsafe { OwnedFd::from_raw_fd(raw) });
    let staged =
        byte_count(unsafe { libc::write(writer.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) })?;
    byte_count(unsafe {
        libc::splice(
            reader.as_raw_fd(),
            std::ptr::null_mut(),
            fd,
            std::ptr::null_mut(),
            staged,
            libc::SPLICE_F_NONBLOCK,
        )
    })
}

pub(super) struct SignalAction {
    pub(super) signal: libc::c_int,
    previous: libc::sigaction,
}

impl SignalAction {
    pub(super) fn is_ignored(&self) -> bool {
        self.previous.sa_sigaction == libc::SIG_IGN
    }

    pub(super) fn reset_caught_handlers() -> Result<()> {
        let realtime_min = libc::SIGRTMIN();
        for signal in 1..=libc::SIGRTMAX() {
            // The libc implementation reserves low realtime signal numbers
            // for its own use. KILL and STOP have no mutable disposition.
            if signal == libc::SIGKILL
                || signal == libc::SIGSTOP
                || (32..realtime_min).contains(&signal)
            {
                continue;
            }
            let mut action = unsafe { zeroed::<libc::sigaction>() };
            // SAFETY: query valid signal state into stack storage. This path
            // runs after fork and must neither allocate nor call host handlers.
            errno_unit(unsafe { libc::sigaction(signal, std::ptr::null(), &raw mut action) })?;
            if action.sa_sigaction != libc::SIG_DFL && action.sa_sigaction != libc::SIG_IGN {
                Self::replace(signal, libc::SIG_DFL)?;
            }
        }
        Ok(())
    }

    pub(super) fn set_default(signal: Signal) -> Result<Self> {
        Self::replace(signal as i32, libc::SIG_DFL)
    }

    pub(super) fn set_ignored_raw(signal: libc::c_int) -> Result<Self> {
        Self::replace(signal, libc::SIG_IGN)
    }

    fn replace(signal: libc::c_int, handler: libc::sighandler_t) -> Result<Self> {
        // SAFETY: sigaction is initialized before use; an empty mask and zero flags
        // also clear SA_NOCLDWAIT/SA_NOCLDSTOP when resetting SIGCHLD.
        let mut action: libc::sigaction = unsafe { zeroed() };
        action.sa_sigaction = handler;
        unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
        let mut previous = unsafe { zeroed() };
        // SAFETY: both pointers refer to valid sigaction storage.
        errno_unit(unsafe { libc::sigaction(signal, &raw const action, &raw mut previous) })?;
        Ok(Self { signal, previous })
    }

    pub(super) fn restore(&self) -> Result<()> {
        // SAFETY: the action was captured by sigaction for this signal.
        errno_unit(unsafe {
            libc::sigaction(self.signal, &raw const self.previous, std::ptr::null_mut())
        })
    }
}

#[derive(Clone)]
pub(super) struct SigSet(libc::sigset_t);

impl SigSet {
    pub(super) fn empty() -> Self {
        let mut set = unsafe { zeroed() };
        // SAFETY: the pointer is valid for writing an initialized signal set.
        unsafe { libc::sigemptyset(&raw mut set) };
        Self(set)
    }

    pub(super) fn add_raw(&mut self, signal: libc::c_int) {
        // SAFETY: self holds an initialized set; invalid numbers leave it unchanged.
        unsafe { libc::sigaddset(&raw mut self.0, signal) };
    }

    pub(super) fn contains_raw(&self, signal: libc::c_int) -> bool {
        // SAFETY: self holds an initialized set; invalid signal numbers return -1.
        unsafe { libc::sigismember(&raw const self.0, signal) == 1 }
    }

    pub(super) fn all() -> Self {
        // SAFETY: sigset_t is plain old data and is immediately initialized by sigfillset.
        let mut set = unsafe { zeroed() };
        // SAFETY: pointer is valid for writes.
        unsafe { libc::sigfillset(&raw mut set) };
        Self(set)
    }

    pub(super) fn remove(&mut self, signal: Signal) {
        self.remove_raw(signal as libc::c_int);
    }

    pub(super) fn remove_raw(&mut self, signal: libc::c_int) {
        // SAFETY: pointer is valid; invalid signal numbers leave the set unchanged.
        unsafe {
            libc::sigdelset(&raw mut self.0, signal);
        }
    }

    pub(super) fn pending() -> Result<Self> {
        // SAFETY: the output points to writable sigset_t storage.
        let mut set = unsafe { zeroed() };
        errno_unit(unsafe { libc::sigpending(&raw mut set) })?;
        Ok(Self(set))
    }

    pub(super) fn wait_nohang(&self) -> Result<Option<libc::c_int>> {
        // musl's sigtimedwait can retry EINTR internally, outside the caller's
        // finite cleanup budget. Ask the kernel once with a zero timeout.
        let timeout = [0_i64; 2];
        let mask_size = libc::SIGRTMAX().cast_unsigned().div_ceil(u8::BITS) as usize;
        // SAFETY: the kernel reads its signal mask prefix and a zero timespec
        // (the buffer fits both 32- and 64-bit time ABIs). No siginfo is requested.
        let result = unsafe {
            libc::syscall(
                libc::SYS_rt_sigtimedwait,
                self.as_ptr(),
                std::ptr::null_mut::<libc::siginfo_t>(),
                timeout.as_ptr(),
                mask_size,
            )
        };
        if result >= 0 {
            Ok(Some(result as libc::c_int))
        } else {
            match Errno::last() {
                Errno::EAGAIN => Ok(None),
                error => Err(error),
            }
        }
    }

    pub(super) fn thread_get_mask() -> Result<Self> {
        Self::capture_thread_mask(None)
    }

    pub(super) fn block_on_thread(&self) -> Result<Self> {
        Self::capture_thread_mask(Some(self))
    }

    fn capture_thread_mask(block: Option<&Self>) -> Result<Self> {
        // SAFETY: sigset_t is plain old data and is immediately written by pthread_sigmask.
        let mut set = unsafe { zeroed() };
        let mask = block.map_or(std::ptr::null(), Self::as_ptr);
        // SAFETY: a null mask queries only. Any supplied set is valid during the call.
        let rc = unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, mask, &raw mut set) };
        if rc == 0 {
            Ok(Self(set))
        } else {
            Err(Errno::from_raw(rc))
        }
    }

    pub(super) fn thread_set_mask(&self) -> Result<()> {
        // SAFETY: set pointer is valid; null oldset means no previous mask capture.
        let rc = unsafe {
            libc::pthread_sigmask(libc::SIG_SETMASK, &raw const self.0, std::ptr::null_mut())
        };
        if rc == 0 {
            Ok(())
        } else {
            Err(Errno::from_raw(rc))
        }
    }

    const fn as_ptr(&self) -> *const libc::sigset_t {
        &raw const self.0
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) struct PollFlags(libc::c_short);

impl PollFlags {
    pub(super) const fn readable(self) -> bool {
        self.0 & libc::POLLIN != 0
    }

    pub(super) const fn failed(self) -> bool {
        self.0 & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(transparent)]
pub(super) struct PollTimeout(i32);

impl PollTimeout {
    pub(super) const BLOCK: Self = Self(-1);
    pub(super) const MAX: Self = Self(i32::MAX);

    pub(super) fn from_duration(duration: Duration) -> Self {
        let millis = duration.as_nanos().div_ceil(1_000_000);
        i32::try_from(millis).map_or(Self::MAX, Self)
    }

    const fn as_millis(self) -> i32 {
        self.0
    }
}

pub(super) struct SignalFd {
    fd: OwnedFd,
    signals: SigSet,
}

impl SignalFd {
    fn with_flags(block: &SigSet, flags: libc::c_int) -> Result<Self> {
        // SAFETY: signalfd receives a valid sigset pointer and returns a new owned fd on success.
        let fd = unsafe { libc::signalfd(-1, block.as_ptr(), flags) };
        if fd == -1 {
            Err(Errno::last())
        } else {
            // SAFETY: fd is freshly returned by signalfd and uniquely owned here.
            let owned = unsafe { OwnedFd::from_raw_fd(fd) };
            Ok(Self {
                fd: owned,
                signals: block.clone(),
            })
        }
    }

    pub(super) fn poll(&self, timeout: PollTimeout) -> Result<PollFlags> {
        let mut fd = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: fd describes the owned signal descriptor and lives through poll.
        if unsafe { libc::poll(&raw mut fd, 1, timeout.as_millis()) } == -1 {
            return Err(Errno::last());
        }
        Ok(PollFlags(fd.revents))
    }

    pub(super) fn accepts(&self, signal: libc::c_int) -> bool {
        self.signals.contains_raw(signal)
    }

    pub(super) fn with_filter<T>(
        &mut self,
        signals: &SigSet,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        let fd = self.fd.as_raw_fd();
        let set_filter = |signals: &SigSet| {
            // SAFETY: signalfd updates this existing descriptor in place.
            errno_unit(unsafe { libc::signalfd(fd, signals.as_ptr(), 0) })
        };
        set_filter(signals)?;
        let result = read(self);
        set_filter(&self.signals)?;
        result
    }

    pub(super) fn read_signal(&mut self) -> Result<Option<libc::signalfd_siginfo>> {
        // SAFETY: POD zero-init is fine for signalfd_siginfo before read(2) fills it.
        let mut info = unsafe { zeroed::<libc::signalfd_siginfo>() };
        // SAFETY: buffer is valid for writes of the exact struct size.
        let rc = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                (&raw mut info).cast::<libc::c_void>(),
                size_of::<libc::signalfd_siginfo>(),
            )
        };
        if rc == -1 {
            let err = Errno::last();
            if err == Errno::EAGAIN || err == Errno::EINTR {
                Ok(None)
            } else {
                Err(err)
            }
        } else if rc == 0 {
            Ok(None)
        } else if rc.cast_unsigned() == size_of::<libc::signalfd_siginfo>() {
            Ok(Some(info))
        } else {
            Err(Errno::EIO)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WaitStatus {
    Exited(Pid, i32),
    Signaled(Pid, i32),
    Stopped(Pid, i32),
    Continued(Pid),
    StillAlive,
}

impl WaitStatus {
    const fn from_raw(pid: Pid, status: i32) -> Result<Self> {
        if libc::WIFEXITED(status) {
            Ok(Self::Exited(pid, libc::WEXITSTATUS(status)))
        } else if libc::WIFSIGNALED(status) {
            Ok(Self::Signaled(pid, libc::WTERMSIG(status)))
        } else if libc::WIFSTOPPED(status) {
            Ok(Self::Stopped(pid, libc::WSTOPSIG(status)))
        } else if libc::WIFCONTINUED(status) {
            Ok(Self::Continued(pid))
        } else {
            Err(Errno::EINVAL)
        }
    }
}

// Single boundary for Unix process, signal, and poll primitives used by tino.
// Future syscall migration should happen here instead of being scattered across
// child/signal/supervision modules.

pub(super) unsafe fn fork_process() -> Result<ForkResult> {
    // SAFETY: caller is responsible for fork-safety constraints.
    match unsafe { libc::fork() } {
        -1 => Err(Errno::last()),
        0 => Ok(ForkResult::Child),
        pid => Ok(ForkResult::Parent {
            child: Pid::from_raw(pid),
        }),
    }
}

pub(super) fn exec_program(program: &CString, argv_ptrs: &[*const libc::c_char]) -> Result<!> {
    // SAFETY: program and argv are valid NUL-terminated strings; argv_ptrs is
    // terminated with a trailing null pointer as required by execvp(3).
    let rc = unsafe { libc::execvp(program.as_ptr(), argv_ptrs.as_ptr()) };
    debug_assert_eq!(rc, -1, "execvp only returns on error");
    Err(Errno::last())
}

pub(super) fn may_execute_at(fd: libc::c_int, path: &CStr) -> Result<bool> {
    let mut flags = libc::AT_EACCESS;
    if path.is_empty() {
        flags |= libc::AT_EMPTY_PATH;
    }
    // SAFETY: path is NUL-terminated. An empty path refers to the pinned fd.
    let result = errno_unit(unsafe {
        libc::syscall(libc::SYS_faccessat2, fd, path.as_ptr(), libc::X_OK, flags) as libc::c_int
    });
    let result = match result {
        Err(Errno::ENOSYS | Errno::EINVAL | Errno::EPERM) if access_uses_exec_credentials() => {
            let fd_path;
            let path = if path.is_empty() {
                fd_path = CString::new(format!("/proc/self/fd/{fd}")).map_err(|_| Errno::EINVAL)?;
                &fd_path
            } else {
                path
            };
            // SAFETY: the pathname refers to the same candidate as the original probe.
            errno_unit(unsafe { libc::access(path.as_ptr(), libc::X_OK) })
        }
        result => result,
    };
    match result {
        Err(Errno::EACCES) => Ok(false),
        result => result.map(|()| true),
    }
}

fn access_uses_exec_credentials() -> bool {
    let mut header = [0x2008_0522u32, 0]; // Linux capability ABI v3, current thread.
    let mut data = [[0u32; 3]; 2]; // Effective, permitted, inheritable.
    // access(2) uses the real IDs and either root's permitted capabilities or none.
    // SAFETY: the invalid -1 ID queries the filesystem IDs without changing them.
    // capget receives the header and two writable capability triples required by v3.
    unsafe {
        let uid = libc::getuid();
        libc::setfsuid(libc::uid_t::MAX).cast_unsigned() == uid
            && libc::setfsgid(libc::gid_t::MAX).cast_unsigned() == libc::getgid()
            && libc::syscall(libc::SYS_capget, header.as_mut_ptr(), data.as_mut_ptr()) == 0
            && data
                .into_iter()
                .all(|[effective, permitted, _]| effective == if uid == 0 { permitted } else { 0 })
    }
}

pub(super) fn set_process_group(pid: Pid, pgid: Pid) -> Result<()> {
    // SAFETY: arguments are plain process identifiers forwarded directly to libc.
    errno_unit(unsafe { libc::setpgid(pid.as_raw(), pgid.as_raw()) })
}

pub(super) fn process_group_of(pid: Pid) -> Result<Pid> {
    // SAFETY: argument is a valid process identifier for getpgid(2).
    errno_pid(unsafe { libc::getpgid(pid.as_raw()) })
}

pub(super) fn current_process_id() -> Pid {
    // SAFETY: getpid(2) has no preconditions.
    Pid::from_raw(unsafe { libc::getpid() })
}

pub(super) fn parent_process_id() -> Pid {
    // SAFETY: getppid(2) has no preconditions.
    Pid::from_raw(unsafe { libc::getppid() })
}

pub(super) fn waitpid_any_nohang() -> Result<WaitStatus> {
    waitpid(-1, libc::WNOHANG | libc::WUNTRACED | libc::WCONTINUED)
}

pub(super) fn waitpid_child(pid: Pid) -> Result<WaitStatus> {
    waitpid(pid.as_raw(), 0)
}

pub(super) fn child_has_waitable_transition(pid: Pid) -> Result<bool> {
    let mut info = unsafe { zeroed::<libc::siginfo_t>() };
    // Inspect a change since the last wait without consuming the next SIGCHLD report.
    errno_unit(unsafe {
        libc::waitid(
            libc::P_PID,
            pid.as_raw().cast_unsigned(),
            &raw mut info,
            libc::WNOHANG | libc::WNOWAIT | libc::WCONTINUED | libc::WSTOPPED | libc::WEXITED,
        )
    })?;
    Ok(unsafe { info.si_pid() } != 0)
}

pub(super) fn waitpid_group_nohang(pgid: Pid) -> Result<WaitStatus> {
    waitpid(-pgid.as_raw(), libc::WNOHANG)
}

fn waitpid(selector: libc::pid_t, options: libc::c_int) -> Result<WaitStatus> {
    let mut status = 0;
    // SAFETY: status points to writable storage for the selected child's state.
    match unsafe { libc::waitpid(selector, &raw mut status, options) } {
        0 => Ok(WaitStatus::StillAlive),
        -1 => Err(Errno::last()),
        pid => WaitStatus::from_raw(Pid::from_raw(pid), status),
    }
}

pub(super) fn new_signal_fd(block: &SigSet) -> Result<SignalFd> {
    SignalFd::with_flags(block, libc::SFD_NONBLOCK | libc::SFD_CLOEXEC)
}

pub(super) fn send_process_signal(pid: Pid, sig: libc::c_int) -> Result<()> {
    // SAFETY: arguments are forwarded directly to kill(2).
    errno_unit(unsafe { libc::kill(pid.as_raw(), sig) })
}

pub(super) fn send_process_group_signal(pgid: Pid, sig: libc::c_int) -> Result<()> {
    // SAFETY: negative pid targets the process group per kill(2).
    errno_unit(unsafe { libc::kill(-pgid.as_raw(), sig) })
}

pub(super) fn process_group_exists(pgid: Pid) -> Result<bool> {
    match send_process_group_signal(pgid, 0) {
        Ok(()) | Err(Errno::EPERM) => Ok(true),
        Err(Errno::ESRCH) => Ok(false),
        Err(err) => Err(err),
    }
}

fn errno_unit(rc: libc::c_int) -> Result<()> {
    if rc == -1 { Err(Errno::last()) } else { Ok(()) }
}

fn errno_pid(rc: libc::pid_t) -> Result<Pid> {
    if rc == -1 {
        Err(Errno::last())
    } else {
        Ok(Pid::from_raw(rc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_timeout_block_waits_forever() {
        assert_eq!(PollTimeout::BLOCK.as_millis(), -1);
    }

    #[test]
    fn errno_last_reads_recent_libc_error() {
        // SAFETY: closing an invalid fd is expected to fail and set errno.
        let rc = unsafe { libc::close(-1) };
        assert_eq!(rc, -1);
        assert_eq!(Errno::last().raw(), libc::EBADF);
    }

    #[test]
    fn poll_timeout_from_duration_rounds_up_and_caps_at_the_kernel_limit() {
        for (duration, millis) in [
            (Duration::ZERO, 0),
            (Duration::from_nanos(1), 1),
            (Duration::from_millis(25), 25),
            (Duration::from_micros(25_001), 26),
            (
                Duration::from_millis(i32::MAX as u64) + Duration::from_nanos(1),
                i32::MAX,
            ),
            (Duration::MAX, i32::MAX),
        ] {
            assert_eq!(PollTimeout::from_duration(duration).as_millis(), millis);
        }
    }

    #[test]
    fn signal_fd_poll_flags_report_readiness_and_errors() {
        assert!(!PollFlags(0).readable());
        assert!(!PollFlags(0).failed());
        assert!(PollFlags(libc::POLLIN).readable());
        assert!(!PollFlags(libc::POLLIN).failed());
        for flag in [libc::POLLERR, libc::POLLHUP, libc::POLLNVAL] {
            assert!(PollFlags(libc::POLLIN | flag).failed());
        }
    }

    #[test]
    fn wait_status_preserves_unlisted_terminating_signals() {
        let pid = Pid::from_raw(42);
        assert_eq!(
            WaitStatus::from_raw(pid, libc::SIGXCPU).unwrap(),
            WaitStatus::Signaled(pid, libc::SIGXCPU)
        );
    }

    #[test]
    fn wait_status_parses_stopped_and_continued_children() {
        let pid = Pid::from_raw(42);
        let stopped_status = (libc::SIGSTOP << 8) | 0x7f;

        assert_eq!(
            WaitStatus::from_raw(pid, stopped_status).unwrap(),
            WaitStatus::Stopped(pid, libc::SIGSTOP)
        );
        assert_eq!(
            WaitStatus::from_raw(pid, 0xffff).unwrap(),
            WaitStatus::Continued(pid)
        );
    }
}
