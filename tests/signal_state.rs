// A custom harness keeps the library probes single-threaded. libtest would
// create a worker thread before the probe can exercise the public run API.
fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {

    use std::io::{BufRead, BufReader, Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    fn wait_with_timeout(child: &mut Child) -> ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("supervisor did not observe child exit within five seconds");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn inherited_sigchld_ignore_does_not_lose_exit_status() {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tino"));
        command.args(["--no-config", "--", "/bin/sh", "-c", "exit 23"]);
        // SAFETY: this changes only the forked launcher, using async-signal-safe calls.
        unsafe {
            command.pre_exec(|| {
                let mut action: libc::sigaction = std::mem::zeroed();
                action.sa_sigaction = libc::SIG_IGN;
                libc::sigemptyset(&raw mut action.sa_mask);
                if libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().expect("launch tino with SIGCHLD ignored");
        assert_eq!(wait_with_timeout(&mut child).code(), Some(23));
    }

    fn child_sigpipe_uses_default_disposition() {
        let output = Command::new(env!("CARGO_BIN_EXE_tino"))
            .args([
                "--no-config",
                "--",
                "/bin/sh",
                "-c",
                "kill -PIPE $$; printf survived",
            ])
            .output()
            .expect("run SIGPIPE child");
        assert_eq!(output.status.code(), Some(128 + libc::SIGPIPE));
        assert!(output.stdout.is_empty());
    }

    fn exec_failure_preserves_status_with_broken_stderr() {
        for (program, expected) in [("/tino-command-that-does-not-exist", 127), ("/", 126)] {
            let mut pipe_fds = [0; 2];
            // SAFETY: pipe_fds points to storage for two newly owned descriptors.
            assert_eq!(
                unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            // SAFETY: each descriptor is freshly allocated and has a single owner.
            let reader = unsafe { OwnedFd::from_raw_fd(pipe_fds[0]) };
            let writer = unsafe { OwnedFd::from_raw_fd(pipe_fds[1]) };
            drop(reader);
            let mut child = Command::new(env!("CARGO_BIN_EXE_tino"))
                .args(["--no-config", "--", program])
                .stderr(Stdio::from(writer))
                .spawn()
                .expect("launch tino with closed stderr reader");
            assert_eq!(
                wait_with_timeout(&mut child).code(),
                Some(expected),
                "{program}"
            );
        }
    }

    fn full_stderr_pipe(socket: bool) -> (OwnedFd, OwnedFd, libc::c_int) {
        let mut fds = [0; 2];
        let result = if socket {
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            }
        } else {
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }
        };
        assert_eq!(result, 0);
        // SAFETY: pipe2/socketpair returned two newly owned descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
            0
        );
        let buffer = [b'x'; 4096];
        loop {
            let written =
                unsafe { libc::write(writer.as_raw_fd(), buffer.as_ptr().cast(), buffer.len()) };
            if written == -1 {
                let error = std::io::Error::last_os_error().raw_os_error();
                if error == Some(libc::EINTR) {
                    continue;
                }
                assert_eq!(error, Some(libc::EAGAIN));
                break;
            }
            assert!(written > 0);
        }
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags) },
            0
        );
        assert_eq!(flags & libc::O_NONBLOCK, 0);
        (reader, writer, flags)
    }

    fn run_with_full_stderr(args: &[&str], expected: i32, send_term: bool, socket: bool) {
        let (reader, writer, original_flags) = full_stderr_pipe(socket);
        let mut supervisor = Command::new(env!("CARGO_BIN_EXE_tino"))
            .arg("--no-config")
            .args(args)
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(writer.try_clone().unwrap()))
            .spawn()
            .unwrap();
        let supervisor_pid = supervisor.id().cast_signed();
        let mut main_pid = None;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            if send_term {
                let stdout = supervisor.stdout.take().unwrap();
                let mut ready = libc::pollfd {
                    fd: stdout.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(
                    unsafe { libc::poll(&raw mut ready, 1, 3000) },
                    1,
                    "workload readiness"
                );
                let mut line = String::new();
                BufReader::new(stdout).read_line(&mut line).unwrap();
                main_pid = Some(
                    line.trim()
                        .parse::<libc::pid_t>()
                        .expect("ready workload PID"),
                );
                assert_eq!(unsafe { libc::kill(supervisor_pid, libc::SIGTERM) }, 0);
            }
            let deadline = Instant::now() + Duration::from_secs(3);
            let status = loop {
                if let Some(status) = supervisor.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(
                status.and_then(|status| status.code()),
                Some(expected),
                "{args:?}, socket={socket}"
            );
            if let Some(pid) = main_pid {
                assert_eq!(
                    unsafe { libc::kill(pid, 0) },
                    -1,
                    "managed child must be reaped"
                );
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ESRCH)
                );
            }
            assert_eq!(
                unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) },
                original_flags,
                "diagnostics must not change the shared stderr flags"
            );
        }));
        // Keep the full pipe unread throughout all assertions. On failure,
        // terminate the workload before releasing stderr so tino can reap it.
        if let Err(payload) = result {
            if let Some(pid) = main_pid {
                unsafe { libc::kill(pid, libc::SIGKILL) };
            }
            drop(reader);
            let deadline = Instant::now() + Duration::from_secs(1);
            while supervisor.try_wait().unwrap().is_none() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(10));
            }
            // This isolated group also covers a workload that never reached
            // readiness; no -g option creates a separate child process group.
            unsafe { libc::kill(-supervisor_pid, libc::SIGKILL) };
            let _ = supervisor.wait();
            std::panic::resume_unwind(payload);
        }
    }

    fn full_stderr_does_not_postpone_shutdown() {
        let exe = std::env::current_exe().unwrap();
        for socket in [false, true] {
            for verbosity in ["-v", "-vv"] {
                run_with_full_stderr(
                    &[
                        verbosity,
                        "--grace-ms",
                        "20",
                        "--",
                        exe.to_str().unwrap(),
                        "full-stderr-workload",
                    ],
                    137,
                    true,
                    socket,
                );
            }
        }
    }

    fn exec_failure_preserves_status_with_full_stderr() {
        for socket in [false, true] {
            for (program, expected) in [("/tino-command-that-does-not-exist", 127), ("/", 126)] {
                run_with_full_stderr(&["--", program], expected, false, socket);
            }
        }
    }

    fn readonly_stderr_does_not_gain_write_access() {
        let fifo = std::env::temp_dir().join(format!(
            "tino-opath-stderr-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        for opath in [false, true] {
            for (program, expected) in [
                ("/bin/true", 0),
                ("/tino-command-that-does-not-exist", 127),
                ("/", 126),
            ] {
                let mut fds = [-1; 2];
                if opath {
                    fds[0] = unsafe {
                        libc::open(
                            fifo_c.as_ptr(),
                            libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                        )
                    };
                    assert!(fds[0] >= 0);
                    fds[1] = unsafe {
                        libc::open(
                            fifo_c.as_ptr(),
                            libc::O_WRONLY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                        )
                    };
                    assert!(fds[1] >= 0);
                } else {
                    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
                }
                // SAFETY: the calls above returned newly owned descriptors.
                let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
                let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
                let stderr = if opath {
                    let fd = unsafe { libc::open(fifo_c.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
                    assert!(fd >= 0);
                    unsafe { OwnedFd::from_raw_fd(fd) }
                } else {
                    reader.try_clone().unwrap()
                };
                let flags = unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_GETFL) };
                assert!(flags >= 0);
                assert_eq!(flags & libc::O_ACCMODE, libc::O_RDONLY);
                assert_eq!(flags & libc::O_PATH != 0, opath);
                let mut child = Command::new(env!("CARGO_BIN_EXE_tino"))
                    .args(["--no-config", "-v", "--", program])
                    .stderr(Stdio::from(stderr.try_clone().unwrap()))
                    .spawn()
                    .unwrap();
                assert_eq!(wait_with_timeout(&mut child).code(), Some(expected));
                assert_eq!(
                    unsafe { libc::fcntl(stderr.as_raw_fd(), libc::F_GETFL) },
                    flags
                );
                // Retain a real FIFO reader during the run so reopening the
                // O_PATH descriptor as a writer would succeed in the old code.
                drop(writer);
                let mut byte = 0u8;
                assert_eq!(
                    unsafe { libc::read(reader.as_raw_fd(), (&raw mut byte).cast(), 1) },
                    0,
                    "diagnostics wrote through a non-writable stderr: opath={opath}, program={program}"
                );
            }
        }
        std::fs::remove_file(fifo).unwrap();
    }

    fn full_stderr_workload() -> ! {
        let flags = unsafe { libc::fcntl(libc::STDERR_FILENO, libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(
            flags & libc::O_NONBLOCK,
            0,
            "workload stderr must remain blocking"
        );
        assert_ne!(
            unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) },
            libc::SIG_ERR
        );
        println!("{}", std::process::id());
        std::io::stdout().flush().unwrap();
        loop {
            unsafe { libc::pause() };
        }
    }

    fn limit_stderr_file_size(command: &mut Command) {
        // A memfd is a regular file subject to RLIMIT_FSIZE, without a fixture
        // path to clean up when an assertion or subprocess fails.
        let fd = unsafe { libc::memfd_create(c"tino-stderr-limit".as_ptr(), libc::MFD_CLOEXEC) };
        assert!(fd >= 0);
        command.stderr(Stdio::from(unsafe { OwnedFd::from_raw_fd(fd) }));
        unsafe {
            command.pre_exec(|| {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &limit) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }

    fn diagnostics_preserve_status_with_file_size_limit() {
        let cases: &[(&[&str], i32, bool)] = &[
            (&["--", "/tino-command-that-does-not-exist"], 127, false),
            (&["--", "/"], 126, false),
            // Ordinary writes by the managed program retain their SIGXFSZ behavior.
            (
                &["--", "/bin/sh", "-c", "printf x >&2"],
                128 + libc::SIGXFSZ,
                false,
            ),
            (&["--", "/bin/sh", "-c", "exit 37"], 37, true),
            (
                &[
                    "-vv",
                    "--",
                    "/bin/sh",
                    "-c",
                    "kill -TTIN $PPID; sleep 0.1; exit 37",
                ],
                37,
                false,
            ),
        ];
        for &(args, expected, early_warning) in cases {
            let mut command = Command::new(env!("CARGO_BIN_EXE_tino"));
            command.arg("--no-config").args(args);
            if early_warning {
                command.env("TINO_SUBREAPER", "invalid");
            }
            limit_stderr_file_size(&mut command);
            let mut child = command.spawn().expect("launch limited stderr probe");
            assert_eq!(
                wait_with_timeout(&mut child).code(),
                Some(expected),
                "{args:?}"
            );
        }

        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg("file-size-pending-probe")
            .env("TINO_SUBREAPER", "invalid");
        limit_stderr_file_size(&mut command);
        let mut child = command.spawn().expect("launch pending write signal probe");
        assert!(wait_with_timeout(&mut child).success());
    }

    fn file_size_pending_probe() {
        let signals = [libc::SIGPIPE, libc::SIGXFSZ];
        let mut mask = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut mask);
            for signal in signals {
                libc::sigaddset(&raw mut mask, signal);
            }
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, std::ptr::null_mut()),
                0
            );
            for signal in signals {
                assert_eq!(libc::kill(libc::getpid(), signal), 0);
            }
        }
        let cli = tino::Cli::try_parse_from([
            "tino",
            "--no-config",
            "--",
            "/tino-command-that-does-not-exist",
        ])
        .unwrap();
        // Both the early environment warning and the child's exec diagnostic
        // encounter EFBIG; neither may consume the caller's queued signals.
        assert_eq!(tino::run(cli).unwrap(), 127);
        let mut pending = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask),
                0
            );
            for signal in signals {
                assert_eq!(libc::sigismember(&raw const pending, signal), 1);
                assert_eq!(libc::sigismember(&raw const mask, signal), 1);
            }
        }
    }

    fn external_sigxfsz_is_forwarded() {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tino"))
            .args([
                "--no-config",
                "--",
                "/bin/sh",
                "-c",
                "echo ready; exec sleep 5",
            ])
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");
        assert_eq!(
            unsafe { libc::kill(child.id().cast_signed(), libc::SIGXFSZ) },
            0
        );
        assert_eq!(
            wait_with_timeout(&mut child).code(),
            Some(128 + libc::SIGXFSZ)
        );
    }

    fn library_preserves_subreaper_when_state_query_fails() {
        for initial in ["0", "1"] {
            let mut child = Command::new(std::env::current_exe().unwrap())
                .args(["subreaper-query-failure-probe", initial])
                .spawn()
                .expect("launch isolated subreaper probe");
            assert!(wait_with_timeout(&mut child).success(), "initial={initial}");
        }
    }

    fn subreaper_query_failure_probe(initial: libc::c_int) {
        const QUERY_MARKER: libc::c_ulong = 0x7165_7072;
        const LOW_WORD: u32 = if cfg!(target_endian = "little") { 0 } else { 4 };
        // Permit marked test queries to inspect the real state, while rejecting
        // the library's query. prctl ignores this extra argument for PR_GET.
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 5,
                k: libc::SYS_prctl as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16 + LOW_WORD,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 3,
                k: libc::PR_GET_CHILD_SUBREAPER as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 32 + LOW_WORD,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: QUERY_MARKER as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len().try_into().unwrap(),
            filter: filter.as_mut_ptr(),
        };
        // SAFETY: this isolated probe owns its process state; the filter and
        // query output remain valid throughout their respective calls.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, initial), 0);
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let cli = tino::Cli::try_parse_from(["tino", "-s", "--", "/bin/true"]).unwrap();
        let error = tino::run(cli).expect_err("unknown subreaper state must prevent mutation");
        assert_eq!(error.to_string(), "capture child subreaper state");
        assert_eq!(error.exit_code(), 1);
        let mut restored = -1;
        assert_eq!(
            unsafe {
                libc::prctl(
                    libc::PR_GET_CHILD_SUBREAPER,
                    &raw mut restored,
                    QUERY_MARKER,
                    0,
                    0,
                )
            },
            0
        );
        assert_eq!(restored, initial);
    }

    fn library_reports_subreaper_restore_failure() {
        for mode in ["restore", "supervision"] {
            let mut probe = Command::new(std::env::current_exe().unwrap())
                .args(["subreaper-restore-failure-probe", mode])
                .spawn()
                .unwrap();
            assert!(wait_with_timeout(&mut probe).success(), "{mode}");
        }
    }

    fn subreaper_restore_failure_probe(fail_poll: bool) {
        let mut before_mask = unsafe { std::mem::zeroed() };
        let mut before_action: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0), 0);
            libc::sigemptyset(&raw mut before_mask);
            libc::sigaddset(&raw mut before_mask, libc::SIGUSR1);
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_BLOCK,
                    &raw const before_mask,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut before_mask),
                0
            );
            before_action.sa_sigaction = record_signal as *const () as usize;
            before_action.sa_flags = libc::SA_RESTART | libc::SA_NOCLDSTOP;
            libc::sigemptyset(&raw mut before_action.sa_mask);
            libc::sigaddset(&raw mut before_action.sa_mask, libc::SIGUSR2);
            assert_eq!(
                libc::sigaction(
                    libc::SIGCHLD,
                    &raw const before_action,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut before_action),
                0
            );
        }
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        ))]
        let poll_number = libc::SYS_ppoll;
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let poll_number = libc::SYS_poll;
        let low_word = if cfg!(target_endian = "big") { 4 } else { 0 };
        let denied = libc::SECCOMP_RET_ERRNO | libc::EPERM as u32;
        // Permit subreaper activation and queries, but deny restoring zero.
        // A second mode also fails supervision so its original error must win.
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 5,
                k: libc::SYS_prctl as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 6,
                k: libc::PR_SET_CHILD_SUBREAPER as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 24 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 4,
                k: 0,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: denied,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: poll_number as u32,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::SYS_ppoll as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: if fail_poll {
                    denied
                } else {
                    libc::SECCOMP_RET_ALLOW
                },
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len().try_into().unwrap(),
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let cli = tino::Cli::try_parse_from([
            "tino",
            "--no-config",
            "-s",
            "--",
            "/bin/sh",
            "-c",
            "exit 37",
        ])
        .unwrap();
        let result = tino::run(cli);
        let mut after_mask = unsafe { std::mem::zeroed() };
        let mut after_action: libc::sigaction = unsafe { std::mem::zeroed() };
        let mut subreaper = -1;
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut after_mask),
                0
            );
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut after_action),
                0
            );
            assert_eq!(
                libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut subreaper),
                0
            );
            for signal in 1..=libc::SIGRTMAX() {
                assert_eq!(
                    libc::sigismember(&raw const before_mask, signal),
                    libc::sigismember(&raw const after_mask, signal)
                );
                assert_eq!(
                    libc::sigismember(&raw const before_action.sa_mask, signal),
                    libc::sigismember(&raw const after_action.sa_mask, signal)
                );
            }
            assert_eq!(libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        assert_eq!(before_action.sa_sigaction, after_action.sa_sigaction);
        assert_eq!(before_action.sa_flags, after_action.sa_flags);
        assert_eq!(
            subreaper, 1,
            "seccomp makes the restoration failure irreversible"
        );
        assert_eq!(
            result
                .expect_err("incomplete subreaper restoration must be reported")
                .to_string(),
            if fail_poll {
                "poll"
            } else {
                "restore child subreaper state"
            }
        );
    }

    fn library_reports_sigchld_restore_failure() {
        let mut probe = Command::new(std::env::current_exe().unwrap())
            .arg("sigchld-restore-failure-probe")
            .spawn()
            .unwrap();
        assert!(wait_with_timeout(&mut probe).success());
    }

    extern "C" fn deny_parent_sigchld_restore() {
        let low_word = if cfg!(target_endian = "big") { 4 } else { 0 };
        // This hook runs only in the parent after fork. Initial reaping setup
        // and the child's signal reset remain unrestricted; queries stay legal.
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 7,
                k: libc::SYS_rt_sigaction as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 5,
                k: libc::SIGCHLD as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 24 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 2,
                k: 0,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 28 - low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len() as u16,
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
                || libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program) != 0
            {
                libc::_exit(78);
            }
        }
    }

    fn sigchld_restore_failure_probe() {
        let mut before_mask = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 0), 0);
            libc::sigemptyset(&raw mut before_mask);
            libc::sigaddset(&raw mut before_mask, libc::SIGUSR1);
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_BLOCK,
                    &raw const before_mask,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut before_mask),
                0
            );
            action.sa_sigaction = libc::SIG_IGN;
            action.sa_flags = libc::SA_NOCLDWAIT;
            libc::sigemptyset(&raw mut action.sa_mask);
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()),
                0
            );
            assert_eq!(
                libc::pthread_atfork(None, Some(deny_parent_sigchld_restore), None),
                0
            );
        }
        let cli = tino::Cli::try_parse_from([
            "tino",
            "--no-config",
            "-s",
            "--",
            "/bin/sh",
            "-c",
            "exit 37",
        ])
        .unwrap();
        let result = tino::run(cli);
        let mut after_mask = unsafe { std::mem::zeroed() };
        let mut subreaper = -1;
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut after_mask),
                0
            );
            for signal in 1..=libc::SIGRTMAX() {
                assert_eq!(
                    libc::sigismember(&raw const before_mask, signal),
                    libc::sigismember(&raw const after_mask, signal)
                );
            }
            assert_eq!(
                libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut action),
                0
            );
            assert_eq!(
                libc::prctl(libc::PR_GET_CHILD_SUBREAPER, &raw mut subreaper),
                0
            );
            assert_eq!(libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG), -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ECHILD)
            );
        }
        assert_eq!(subreaper, 0, "other process state must still be restored");
        assert_eq!(action.sa_sigaction, libc::SIG_DFL);
        assert_eq!(
            result
                .expect_err("incomplete SIGCHLD restoration must be reported")
                .to_string(),
            "restore SIGCHLD disposition"
        );
    }

    fn library_preserves_terminal_foreground_ownership() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("tty-library-probe")
            .spawn()
            .expect("launch isolated terminal probe");
        assert!(wait_with_timeout(&mut child).success());
    }

    fn child_resets_inherited_caught_signal_handlers() {
        for mode in ["caught", "realtime", "ignored"] {
            let mut probe = Command::new(std::env::current_exe().unwrap())
                .args(["child-signal-handler-probe", mode])
                .spawn()
                .unwrap();
            assert!(wait_with_timeout(&mut probe).success(), "{mode}");
        }
    }

    static CHILD_PENDING_SIGNAL: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn queue_child_signal() {
        // fork inherits the supervisor's blocked mask. Queue a signal before
        // spawn restores the child mask, without depending on scheduler timing.
        unsafe {
            libc::kill(
                libc::getpid(),
                CHILD_PENDING_SIGNAL.load(Ordering::Relaxed) as libc::c_int,
            );
        }
    }

    extern "C" fn inherited_child_signal_handler(_: libc::c_int) {
        unsafe { libc::_exit(77) }
    }

    fn child_signal_handler_probe(mode: &str) {
        let signal = if mode == "realtime" {
            libc::SIGRTMIN()
        } else {
            libc::SIGUSR1
        };
        let handler = if mode == "ignored" {
            libc::SIG_IGN
        } else {
            inherited_child_signal_handler as *const () as usize
        };
        unsafe {
            let mut unblock = std::mem::zeroed();
            libc::sigemptyset(&raw mut unblock);
            libc::sigaddset(&raw mut unblock, signal);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const unblock, std::ptr::null_mut()),
                0
            );
            assert_ne!(libc::signal(signal, handler), libc::SIG_ERR);
            CHILD_PENDING_SIGNAL.store(signal as usize, Ordering::Relaxed);
            assert_eq!(
                libc::pthread_atfork(None, None, Some(queue_child_signal)),
                0
            );
        }
        let args: &[&str] = if mode == "ignored" {
            &[
                "tino",
                "--no-config",
                "--",
                "/bin/sh",
                "-c",
                "kill -USR1 $$; exit 0",
            ]
        } else {
            &["tino", "--no-config", "--", "/bin/true"]
        };
        let cli = tino::Cli::try_parse_from(args.iter().copied()).unwrap();
        assert_eq!(
            tino::run(cli).unwrap(),
            if mode == "ignored" { 0 } else { 128 + signal }
        );
        let mut action = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe { libc::sigaction(signal, std::ptr::null(), &raw mut action) },
            0
        );
        assert_eq!(
            action.sa_sigaction, handler,
            "caller disposition must survive run"
        );
    }

    fn library_handles_signal_discard_failures() {
        for mode in ["drain", "blocked"] {
            let mut supervisor = Command::new(std::env::current_exe().unwrap())
                .args(["signal-discard-failure-probe", mode])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut ready = String::new();
            BufReader::new(supervisor.stdout.take().unwrap())
                .read_line(&mut ready)
                .unwrap();
            let main_pid: libc::pid_t = ready.trim().parse().unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                wait_for_job_stop(supervisor.id().cast_signed());
                // Resume only after both CHLD and RT signals are queued. CHLD
                // is observed first, leaving RT backlog for final restoration.
                let deadline = Instant::now() + Duration::from_secs(1);
                loop {
                    let stat = std::fs::read_to_string(format!("/proc/{main_pid}/stat")).unwrap();
                    if stat.rsplit_once(") ").unwrap().1.starts_with("Z ") {
                        break;
                    }
                    assert!(Instant::now() < deadline, "workload did not exit");
                    std::thread::sleep(Duration::from_millis(5));
                }
                assert_eq!(
                    unsafe { libc::kill(supervisor.id().cast_signed(), libc::SIGCONT) },
                    0
                );
                assert!(wait_with_timeout(&mut supervisor).success(), "{mode}");
            }));
            if result.is_err() && supervisor.try_wait().unwrap().is_none() {
                unsafe {
                    libc::kill(main_pid, libc::SIGKILL);
                    libc::kill(supervisor.id().cast_signed(), libc::SIGCONT);
                }
                let _ = wait_with_timeout(&mut supervisor);
            }
            if let Err(panic) = result {
                std::panic::resume_unwind(panic);
            }
        }
    }

    fn signal_discard_failure_probe(deny_drain: bool) {
        let mut original_mask = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut original_mask);
            libc::sigaddset(&raw mut original_mask, libc::SIGUSR1);
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_BLOCK,
                    &raw const original_mask,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(libc::kill(libc::getpid(), libc::SIGUSR1), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut original_mask),
                0
            );
        }
        let low_word = if cfg!(target_endian = "big") { 4 } else { 0 };
        // The supported ARM/ARMv7 builds may use either time ABI. libc does not
        // export ARM's time64 constant yet; Linux assigns syscall 421 to it.
        #[cfg(target_arch = "arm")]
        let timedwait_time64 = 421;
        #[cfg(all(target_arch = "riscv32", target_env = "musl"))]
        let timedwait_time64 = libc::SYS_rt_sigtimedwait_time64 as u32;
        #[cfg(not(any(target_arch = "arm", all(target_arch = "riscv32", target_env = "musl"))))]
        let timedwait_time64 = libc::SYS_rt_sigtimedwait as u32;
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 7,
                k: libc::SYS_rt_sigaction as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 16 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 8,
                k: libc::SIGRTMAX().cast_unsigned(),
            },
            // Queries must remain available when spawn resets inherited
            // caught handlers. Deny only a non-null replacement action.
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 24 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 2,
                k: 0,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 28 - low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 4,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: libc::SYS_rt_sigtimedwait as u32,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: timedwait_time64,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: if deny_drain {
                    libc::SECCOMP_RET_ERRNO | libc::EPERM as u32
                } else {
                    libc::SECCOMP_RET_ALLOW
                },
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len().try_into().unwrap(),
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let exe = std::env::current_exe().unwrap();
        let cli = tino::Cli::try_parse_from([
            "tino",
            "--no-config",
            "--grace-ms",
            "0",
            "--",
            exe.to_str().unwrap(),
            "signal-discard-failure-workload",
        ])
        .unwrap();
        let result = tino::run(cli);
        if deny_drain {
            assert!(
                result
                    .expect_err("incomplete signal restoration must be reported")
                    .to_string()
                    .contains("left blocked")
            );
        } else {
            assert_eq!(result.unwrap(), 37);
        }
        let mut mask = unsafe { std::mem::zeroed() };
        let mut pending = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask),
                0
            );
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            for signal in 1..=libc::SIGRTMAX() {
                let expected = if deny_drain && signal == libc::SIGRTMAX() {
                    1
                } else {
                    libc::sigismember(&raw const original_mask, signal)
                };
                assert_eq!(
                    libc::sigismember(&raw const mask, signal),
                    expected,
                    "signal {signal}"
                );
            }
            assert_eq!(
                libc::sigismember(&raw const pending, libc::SIGRTMAX()),
                i32::from(deny_drain)
            );
            assert_eq!(libc::sigismember(&raw const pending, libc::SIGUSR1), 1);
        }
    }

    fn signal_discard_failure_workload() -> ! {
        println!("{}", std::process::id());
        std::io::stdout().flush().unwrap();
        unsafe {
            let supervisor = libc::getppid();
            assert_eq!(libc::kill(supervisor, libc::SIGSTOP), 0);
            assert_eq!(libc::kill(supervisor, libc::SIGRTMAX()), 0);
            assert_eq!(libc::kill(supervisor, libc::SIGRTMAX()), 0);
            libc::_exit(37);
        }
    }

    fn terminal_job_control_supports_foreground_and_background_resume() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("tty-job-control-probe")
            .spawn()
            .expect("launch isolated job control probe");
        assert!(wait_with_timeout(&mut child).success());
    }

    fn terminal_stop_keeps_orphan_supervisor_responsive() {
        let mut supervisor = Command::new(std::env::current_exe().unwrap())
            .arg("tty-orphan-supervisor-probe")
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut ready = String::new();
        BufReader::new(supervisor.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let main_pid: libc::pid_t = ready.trim().parse().unwrap();
        let supervisor_pid = supervisor.id().cast_signed();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(unsafe { libc::kill(-main_pid, libc::SIGTSTP) }, 0);
            let deadline = Instant::now() + Duration::from_secs(1);
            while !process_is_stopped(main_pid) {
                assert!(Instant::now() < deadline, "main command did not stop");
                std::thread::sleep(Duration::from_millis(5));
            }
            // Give the supervisor a chance to process the child's stop before
            // TERM; the orphan supervisor has no shell to resume it afterwards.
            std::thread::sleep(Duration::from_millis(50));
            assert!(!process_is_stopped(supervisor_pid));
            assert_eq!(unsafe { libc::kill(supervisor_pid, libc::SIGTERM) }, 0);
            assert_eq!(wait_with_timeout(&mut supervisor).code(), Some(137));
        }));
        if result.is_err() {
            unsafe {
                libc::kill(-main_pid, libc::SIGKILL);
                libc::kill(supervisor_pid, libc::SIGCONT);
            }
            let _ = wait_with_timeout(&mut supervisor);
        }
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    fn process_is_stopped(pid: libc::pid_t) -> bool {
        std::fs::read_to_string(format!("/proc/{pid}/status"))
            .unwrap()
            .lines()
            .any(|line| line.starts_with("State:\tT") || line.starts_with("State:\tt"))
    }

    fn wait_for_job_stop(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let mut status = 0;
            let result =
                unsafe { libc::waitpid(pid, &raw mut status, libc::WUNTRACED | libc::WNOHANG) };
            assert!(result >= 0);
            if result == pid {
                assert!(
                    libc::WIFSTOPPED(status),
                    "job exited instead of stopping: {status}"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "supervisor did not report stopped foreground job"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn wait_for_resumed_foreground(pid: libc::pid_t) {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            if unsafe { libc::tcgetpgrp(0) } == pid && !process_is_stopped(pid) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "managed command did not regain foreground"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    fn exercise_terminal_job_control(
        parent_group: libc::pid_t,
        master: libc::c_int,
        pending_cont: bool,
    ) {
        unsafe { libc::signal(libc::SIGTTOU, libc::SIG_IGN) };
        let mut command = if pending_cont {
            let mut command = Command::new(std::env::current_exe().unwrap());
            command.arg("tty-pending-cont-supervisor");
            command
        } else {
            let mut command = Command::new(env!("CARGO_BIN_EXE_tino"));
            command
                .args(["--no-config", "-g", "--"])
                .arg(std::env::current_exe().unwrap())
                .arg("tty-read-workload");
            command
        };
        command.stdout(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 || libc::tcsetpgrp(0, libc::getpgrp()) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut supervisor = command.spawn().unwrap();
        let supervisor_pid = supervisor.id().cast_signed();
        let mut ready = String::new();
        BufReader::new(supervisor.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        let main_pid: libc::pid_t = ready.trim().parse().unwrap();
        // A sibling in the original job group models the reader in a shell's
        // `tino ... | cat` pipeline. The shell needs both processes stopped.
        let mut peer = Command::new(std::env::current_exe().unwrap());
        peer.arg("tty-foreground-holder").stdin(Stdio::piped());
        unsafe {
            peer.pre_exec(move || {
                if libc::setpgid(0, supervisor_pid) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut peer = peer.spawn().unwrap();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_eq!(unsafe { libc::tcgetpgrp(0) }, main_pid);
            assert_eq!(unsafe { libc::kill(-main_pid, libc::SIGTSTP) }, 0);
            wait_for_job_stop(supervisor_pid);
            wait_for_job_stop(peer.id().cast_signed());
            assert_eq!(unsafe { libc::tcgetpgrp(0) }, supervisor_pid);

            // `fg`: the shell assigns the original job group before CONT.
            assert_eq!(unsafe { libc::tcsetpgrp(0, parent_group) }, 0);
            assert_eq!(unsafe { libc::tcsetpgrp(0, supervisor_pid) }, 0);
            assert_eq!(unsafe { libc::kill(-supervisor_pid, libc::SIGCONT) }, 0);
            wait_for_resumed_foreground(main_pid);
            assert_eq!(unsafe { libc::kill(-main_pid, libc::SIGTSTP) }, 0);
            wait_for_job_stop(supervisor_pid);
            wait_for_job_stop(peer.id().cast_signed());

            // `bg`: leave the shell foreground. The command's next terminal
            // read stops it with TTIN, which must stop the supervisor again.
            assert_eq!(unsafe { libc::tcsetpgrp(0, parent_group) }, 0);
            assert_eq!(unsafe { libc::kill(-supervisor_pid, libc::SIGCONT) }, 0);
            wait_for_job_stop(supervisor_pid);
            wait_for_job_stop(peer.id().cast_signed());
            assert_eq!(unsafe { libc::tcgetpgrp(0) }, parent_group);

            assert_eq!(unsafe { libc::tcsetpgrp(0, supervisor_pid) }, 0);
            assert_eq!(unsafe { libc::kill(-supervisor_pid, libc::SIGCONT) }, 0);
            wait_for_resumed_foreground(main_pid);
            assert_eq!(unsafe { libc::write(master, b"x\n".as_ptr().cast(), 2) }, 2);
            assert_eq!(wait_with_timeout(&mut supervisor).code(), Some(23));
        }));
        if result.is_err() {
            // Do not leave stopped jobs behind when a regression trips an assertion.
            unsafe {
                libc::kill(-main_pid, libc::SIGKILL);
                libc::kill(supervisor_pid, libc::SIGCONT);
                libc::kill(peer.id().cast_signed(), libc::SIGCONT);
            }
            let _ = wait_with_timeout(&mut supervisor);
        }
        drop(peer.stdin.take());
        assert!(wait_with_timeout(&mut peer).success());
        assert_eq!(unsafe { libc::tcsetpgrp(0, parent_group) }, 0);
        if let Err(panic) = result {
            std::panic::resume_unwind(panic);
        }
    }

    fn tty_pending_cont_supervisor() {
        let mut mask = unsafe { std::mem::zeroed() };
        let mut disposition = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut mask);
            libc::sigaddset(&raw mut mask, libc::SIGCONT);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, std::ptr::null_mut()),
                0
            );
            assert_eq!(libc::kill(libc::getpid(), libc::SIGCONT), 0);
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask),
                0
            );
            assert_eq!(
                libc::sigaction(libc::SIGCONT, std::ptr::null(), &raw mut disposition),
                0
            );
        }
        let exe = std::env::current_exe().unwrap();
        let cli = tino::Cli::try_parse_from([
            "tino",
            "--no-config",
            "-g",
            "--",
            exe.to_str().unwrap(),
            "tty-read-workload",
        ])
        .unwrap();
        let code = tino::run(cli).expect("supervise with preexisting pending CONT");
        let mut after_mask = unsafe { std::mem::zeroed() };
        let mut after_disposition = unsafe { std::mem::zeroed() };
        let mut pending = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut after_mask),
                0
            );
            for signal in 1..=libc::SIGRTMAX() {
                assert_eq!(
                    libc::sigismember(&raw const mask, signal),
                    libc::sigismember(&raw const after_mask, signal)
                );
            }
            assert_eq!(
                libc::sigaction(libc::SIGCONT, std::ptr::null(), &raw mut after_disposition),
                0
            );
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            // STOP clears older CONT instances in the kernel. The final fg
            // produces a new pending CONT, which must remain owned by the caller.
            assert_eq!(libc::sigismember(&raw const pending, libc::SIGCONT), 1);
        }
        assert_eq!(disposition.sa_sigaction, after_disposition.sa_sigaction);
        assert_eq!(disposition.sa_flags, after_disposition.sa_flags);
        std::process::exit(code);
    }

    fn supervision_failure_cleans_up_only_the_managed_child() {
        for mode in ["child", "group"] {
            let mut probe = Command::new(std::env::current_exe().unwrap())
                .args(["failed-supervision-probe", mode])
                .spawn()
                .expect("launch supervision failure probe");
            assert!(wait_with_timeout(&mut probe).success(), "{mode}");
        }
    }

    fn main_child_receives_signals_after_leaving_initial_group() {
        for (mode, expected) in [
            ("default", 128 + libc::SIGTERM),
            ("ignore", 128 + libc::SIGKILL),
        ] {
            let mut supervisor = Command::new(env!("CARGO_BIN_EXE_tino"))
                .args(["--no-config", "-g", "--grace-ms", "50", "--"])
                .arg(std::env::current_exe().unwrap())
                .args(["moved-main-workload", mode])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            let mut ready = String::new();
            BufReader::new(supervisor.stdout.take().unwrap())
                .read_line(&mut ready)
                .unwrap();
            let main_pid: libc::pid_t = ready.trim().parse().expect("moved main child PID");
            assert_eq!(
                unsafe { libc::kill(supervisor.id().cast_signed(), libc::SIGTERM) },
                0
            );
            let deadline = Instant::now() + Duration::from_secs(3);
            let status = loop {
                if let Some(status) = supervisor.try_wait().unwrap() {
                    break Some(status);
                }
                if Instant::now() >= deadline {
                    break None;
                }
                std::thread::sleep(Duration::from_millis(10));
            };
            if status.is_none() {
                // A regression leaves the main command outside the killed
                // group. Always terminate it directly before failing the test.
                unsafe { libc::kill(main_pid, libc::SIGKILL) };
                let _ = supervisor.kill();
                let _ = supervisor.wait();
            }
            assert_eq!(
                status.and_then(|status| status.code()),
                Some(expected),
                "{mode}"
            );
        }
    }

    fn moved_main_workload(ignore_term: bool) -> ! {
        unsafe {
            let parent_group = libc::getpgid(libc::getppid());
            assert!(parent_group > 0);
            assert_eq!(libc::setpgid(0, parent_group), 0);
            libc::signal(
                libc::SIGTERM,
                if ignore_term {
                    libc::SIG_IGN
                } else {
                    libc::SIG_DFL
                },
            );
        }
        println!("{}", std::process::id());
        std::io::stdout().flush().unwrap();
        loop {
            unsafe { libc::pause() };
        }
    }

    fn supervision_failure_reaps_adopted_descendants() {
        run_descendant_failure_probe("shutdown");
    }

    fn cleanup_failure_terminates_adopted_descendants() {
        run_descendant_failure_probe("cleanup");
    }

    fn run_descendant_failure_probe(mode: &str) {
        let mut probe = Command::new(std::env::current_exe().unwrap())
            .args(["descendant-failure-probe", mode])
            .spawn()
            .expect("launch descendant cleanup failure probe");
        assert!(wait_with_timeout(&mut probe).success());
    }

    fn descendant_failure_probe(cleanup: bool) {
        let exe = std::env::current_exe().unwrap();
        let mut unrelated = Command::new(&exe)
            .arg("tty-foreground-holder")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        ))]
        let (poll_number, infinite_timeout) = (libc::SYS_ppoll, 0);
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let (poll_number, infinite_timeout) = (libc::SYS_poll, u32::MAX);
        let low_word = if cfg!(target_endian = "big") { 4 } else { 0 };
        // Fail only timed supervisor polls. The initial wait must allow the
        // workload to fork, and its Rust startup polls use three descriptors.
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 5,
                k: poll_number as u32,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 24 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 3,
                k: 1,
            },
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 32 + low_word,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: infinite_timeout,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len().try_into().unwrap(),
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let cli = tino::Cli::try_parse_from([
            "tino",
            "-s",
            "-g",
            "--grace-ms",
            "2000",
            "--",
            exe.to_str().unwrap(),
            "descendant-failure-workload",
            if cleanup { "cleanup" } else { "shutdown" },
        ])
        .unwrap();
        let result = tino::run(cli);
        let children: Vec<libc::pid_t> =
            std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))
                .unwrap()
                .split_whitespace()
                .map(|pid| pid.parse().unwrap())
                .collect();
        for &pid in &children {
            if pid != unrelated.id().cast_signed() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
            }
        }
        assert!(unrelated.try_wait().unwrap().is_none());
        drop(unrelated.stdin.take());
        assert!(wait_with_timeout(&mut unrelated).success());
        let error = result.expect_err("timed poll failure must be preserved");
        assert_eq!(
            error.to_string(),
            if cleanup {
                "poll during child cleanup"
            } else {
                "poll"
            }
        );
        assert_eq!(children, [unrelated.id().cast_signed()]);
    }

    fn descendant_failure_workload(cleanup: bool) -> ! {
        // Both the main command and its descendant must survive the first TERM
        // so the next timed poll exercises the intended failure path.
        unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child != 0 {
            if cleanup {
                unsafe { libc::_exit(23) }
            }
            assert_eq!(unsafe { libc::kill(libc::getppid(), libc::SIGTERM) }, 0);
        }
        loop {
            unsafe { libc::pause() };
        }
    }

    fn failed_supervision_probe(group: bool) {
        let mut unrelated = Command::new(std::env::current_exe().unwrap())
            .arg("tty-foreground-holder")
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        #[cfg(any(
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        ))]
        let poll_number = libc::SYS_ppoll;
        #[cfg(not(any(
            target_arch = "aarch64",
            target_arch = "riscv32",
            target_arch = "riscv64",
            target_arch = "loongarch64"
        )))]
        let poll_number = libc::SYS_poll;
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: poll_number as u32,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: libc::SYS_ppoll as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | libc::EPERM as u32,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len().try_into().unwrap(),
            filter: filter.as_mut_ptr(),
        };
        // Install only after this isolated Rust process has initialized: its
        // runtime also uses poll before main to check standard descriptors.
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let mut args = vec!["tino"];
        if group {
            args.push("-g");
        }
        args.extend(["--", "/bin/sleep", "5"]);
        let cli = tino::Cli::try_parse_from(args).unwrap();
        let error = tino::run(cli).expect_err("injected poll failure must be reported");
        assert_eq!(error.to_string(), "poll");
        let children: Vec<libc::pid_t> =
            std::fs::read_to_string(format!("/proc/self/task/{}/children", std::process::id()))
                .unwrap()
                .split_whitespace()
                .map(|pid| pid.parse().unwrap())
                .collect();
        // Clean up a regression before asserting so failed tests do not leak
        // the managed workload into the surrounding test runner.
        for &pid in &children {
            if pid != unrelated.id().cast_signed() {
                unsafe {
                    libc::kill(pid, libc::SIGKILL);
                    libc::waitpid(pid, std::ptr::null_mut(), 0);
                }
            }
        }
        assert!(unrelated.try_wait().unwrap().is_none());
        drop(unrelated.stdin.take());
        assert!(wait_with_timeout(&mut unrelated).success());
        assert_eq!(children, [unrelated.id().cast_signed()]);
    }

    fn run_tty_command(mode: &str, args: &[String]) {
        let exe = std::env::current_exe().unwrap();
        let cli = tino::Cli::try_parse_from(
            ["tino", "-g", "--", exe.to_str().unwrap(), mode]
                .into_iter()
                .chain(args.iter().map(String::as_str)),
        )
        .unwrap();
        assert_eq!(tino::run(cli).expect("supervise terminal probe"), 0);
    }

    fn tty_library_probe(mode: &str) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: this is an isolated single-threaded probe; all output pointers
        // are valid and the newly allocated tty descriptors are owned below.
        unsafe {
            assert_ne!(libc::setsid(), -1);
            assert_eq!(
                libc::openpty(
                    &raw mut master,
                    &raw mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                ),
                0
            );
            assert_eq!(libc::fcntl(master, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            assert_eq!(libc::fcntl(slave, libc::F_SETFD, libc::FD_CLOEXEC), 0);
            assert_eq!(libc::ioctl(slave, libc::TIOCSCTTY, 0), 0);
            assert_eq!(libc::dup2(slave, libc::STDIN_FILENO), libc::STDIN_FILENO);
            // Closing the master at the end of this isolated probe sends HUP.
            libc::signal(libc::SIGHUP, libc::SIG_IGN);
        }
        let _master = unsafe { OwnedFd::from_raw_fd(master) };
        let _slave = unsafe { OwnedFd::from_raw_fd(slave) };
        let own_group = unsafe { libc::getpgrp() };
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, own_group);

        if mode == "tty-job-control-probe" {
            exercise_terminal_job_control(own_group, master, false);
            exercise_terminal_job_control(own_group, master, true);
            return;
        }
        if mode == "tty-orphan-supervisor-probe" {
            let exe = std::env::current_exe().unwrap();
            let cli = tino::Cli::try_parse_from([
                "tino",
                "--no-config",
                "-g",
                "--grace-ms",
                "30",
                "--",
                exe.to_str().unwrap(),
                "tty-read-workload",
            ])
            .unwrap();
            std::process::exit(tino::run(cli).unwrap());
        }

        run_tty_command("tty-expect-foreground", &[]);
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, own_group);

        let mut background = Command::new(std::env::current_exe().unwrap());
        background.arg("tty-background-library-probe");
        unsafe {
            background.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut background = background.spawn().unwrap();
        assert!(wait_with_timeout(&mut background).success());
        assert_eq!(unsafe { libc::tcgetpgrp(0) }, own_group);

        // A later foreground change to a separate live group must survive run.
        let mut holder = Command::new(std::env::current_exe().unwrap());
        holder.arg("tty-foreground-holder").stdin(Stdio::piped());
        unsafe {
            holder.pre_exec(|| {
                if libc::setpgid(0, 0) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut holder = holder.spawn().unwrap();
        run_tty_command("tty-move-foreground", &[holder.id().to_string()]);
        let foreground = unsafe { libc::tcgetpgrp(0) };
        unsafe {
            libc::signal(libc::SIGTTOU, libc::SIG_IGN);
            assert_eq!(libc::tcsetpgrp(0, own_group), 0);
        }
        drop(holder.stdin.take());
        assert!(wait_with_timeout(&mut holder).success());
        assert_eq!(foreground, holder.id().cast_signed());
    }

    fn inherited_blocked_abort_does_not_terminate_supervisor() {
        let mut command = Command::new(env!("CARGO_BIN_EXE_tino"));
        command.args(["--no-config", "--", "/bin/sh", "-c", "exit 23"]);
        // SAFETY: only the forked launcher is changed, using signal-safe calls.
        unsafe {
            command.pre_exec(|| {
                let mut mask = std::mem::zeroed();
                libc::sigemptyset(&raw mut mask);
                libc::sigaddset(&raw mut mask, libc::SIGABRT);
                let rc =
                    libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, std::ptr::null_mut());
                if rc != 0 {
                    return Err(std::io::Error::from_raw_os_error(rc));
                }
                if libc::kill(libc::getpid(), libc::SIGABRT) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .expect("launch with blocked pending SIGABRT");
        assert_eq!(wait_with_timeout(&mut child).code(), Some(23));
    }

    fn library_preserves_preexisting_pending_signals() {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .arg("pending-signals-library-probe")
            .spawn()
            .expect("launch isolated pending signal probe");
        assert!(wait_with_timeout(&mut child).success());
    }

    fn pending_signals_library_probe() {
        let preserved = [libc::SIGUSR1, libc::SIGRTMIN()];
        let mut mask = unsafe { std::mem::zeroed() };
        let mut pending = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = record_signal as *const () as usize;
        // SAFETY: only this isolated probe's signal state is changed, using
        // initialized storage for the signal sets and disposition.
        unsafe {
            libc::sigemptyset(&raw mut mask);
            libc::sigemptyset(&raw mut action.sa_mask);
            libc::sigaddset(&raw mut mask, libc::SIGTERM);
            for signal in preserved {
                libc::sigaddset(&raw mut mask, signal);
                assert_eq!(
                    libc::sigaction(signal, &raw const action, std::ptr::null_mut()),
                    0
                );
            }
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, std::ptr::null_mut()),
                0
            );
            for signal in preserved {
                // kill can establish one pending RT signal even if concurrent
                // flood tests have exhausted the shared sigqueue quota.
                assert_eq!(libc::kill(libc::getpid(), signal), 0);
            }
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            for signal in preserved {
                assert_eq!(libc::sigismember(&raw const pending, signal), 1);
            }
            assert_eq!(libc::sigismember(&raw const pending, libc::SIGTERM), 0);
        }

        let exe = std::env::current_exe().unwrap();
        let cli = tino::Cli::try_parse_from([
            "tino",
            "--grace-ms",
            "50",
            "--",
            exe.to_str().unwrap(),
            "pending-signals-workload",
        ])
        .unwrap();
        // TERM was blocked but not pending at entry. The workload's new TERM
        // must still start grace escalation and terminate the blocked child.
        assert_eq!(tino::run(cli).expect("supervise pending signal probe"), 137);
        assert_eq!(HANDLER_CALLS.load(Ordering::Relaxed), 0);
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask),
                0
            );
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            assert_eq!(libc::sigismember(&raw const mask, libc::SIGTERM), 1);
            assert_eq!(libc::sigismember(&raw const pending, libc::SIGTERM), 0);
            for signal in preserved {
                assert_eq!(libc::sigismember(&raw const mask, signal), 1);
                assert_eq!(libc::sigismember(&raw const pending, signal), 1);
                let mut consume = std::mem::zeroed();
                libc::sigemptyset(&raw mut consume);
                libc::sigaddset(&raw mut consume, signal);
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                assert_eq!(
                    libc::sigtimedwait(&raw const consume, std::ptr::null_mut(), &timeout),
                    signal
                );
            }
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            for signal in preserved {
                assert_eq!(libc::sigismember(&raw const pending, signal), 0);
            }
        }
    }

    fn pending_signals_workload() {
        // The inherited mask keeps TERM blocked until grace escalates to KILL.
        assert_eq!(unsafe { libc::kill(libc::getppid(), libc::SIGTERM) }, 0);
        loop {
            unsafe { libc::pause() };
        }
    }

    fn library_preserves_blocked_fault_signals() {
        let signals = [
            libc::SIGABRT,
            libc::SIGFPE,
            libc::SIGILL,
            libc::SIGSEGV,
            libc::SIGBUS,
            libc::SIGTRAP,
            libc::SIGSYS,
        ];
        let mut mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe { libc::sigemptyset(&raw mut mask) };
        let mut originals = Vec::new();
        for signal in signals {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = record_signal as *const () as usize;
            unsafe {
                libc::sigemptyset(&raw mut action.sa_mask);
                libc::sigaddset(&raw mut mask, signal);
            }
            let mut original = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(signal, &raw const action, &raw mut original) },
                0
            );
            originals.push((signal, original));
        }
        let mut previous_mask = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, &raw mut previous_mask)
            },
            0
        );
        let before = HANDLER_CALLS.load(Ordering::Relaxed);
        for signal in signals {
            assert_eq!(unsafe { libc::kill(libc::getpid(), signal) }, 0);
        }
        let cli = tino::Cli::try_parse_from(["tino", "--", "/bin/sh", "-c", "exit 23"]).unwrap();
        assert_eq!(
            tino::run(cli).expect("run with pending excluded signals"),
            23
        );
        assert_eq!(HANDLER_CALLS.load(Ordering::Relaxed), before);
        let mut pending = unsafe { std::mem::zeroed() };
        let mut restored = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::sigpending(&raw mut pending) }, 0);
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut restored)
            },
            0
        );
        for signal in signals {
            assert_eq!(unsafe { libc::sigismember(&raw const pending, signal) }, 1);
            assert_eq!(unsafe { libc::sigismember(&raw const restored, signal) }, 1);
        }
        // Deliver the preserved signals only after returning to the caller.
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const mask, std::ptr::null_mut())
            },
            0
        );
        assert_eq!(
            HANDLER_CALLS.load(Ordering::Relaxed),
            before + signals.len()
        );
        for (signal, original) in originals {
            assert_eq!(
                unsafe { libc::sigaction(signal, &raw const original, std::ptr::null_mut()) },
                0
            );
        }
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const previous_mask,
                    std::ptr::null_mut(),
                )
            },
            0
        );
    }

    fn flood_workload(cleanup: bool) -> ! {
        // This runs as a standalone, single-threaded workload, not a test worker.
        let supervisor = unsafe { libc::getppid() };
        let signal = libc::SIGRTMIN();
        unsafe {
            libc::signal(signal, libc::SIG_IGN);
            libc::signal(libc::SIGTERM, libc::SIG_IGN);
        }
        println!("{}", std::process::id());
        std::io::stdout().flush().unwrap();
        std::io::stdin()
            .read_exact(&mut [0])
            .expect("read flood gate");
        if cleanup {
            // SAFETY: the standalone workload has only this thread.
            let pid = unsafe { libc::fork() };
            assert!(pid >= 0);
            if pid != 0 {
                std::process::exit(37);
            }
        }
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            for _ in 0..256 {
                // SAFETY: the saved PID is our supervisor; the signal is valid.
                unsafe { libc::kill(supervisor, signal) };
            }
        }
        loop {
            std::thread::sleep(Duration::from_secs(1));
        }
    }

    static HANDLER_CALLS: AtomicUsize = AtomicUsize::new(0);

    extern "C" fn record_signal(_: libc::c_int) {
        HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
    }

    fn library_flood_probe() {
        // Verify that dropping queued signals does not leave SIG_IGN installed
        // or run the caller's handlers on signals consumed during supervision.
        let mut originals = Vec::new();
        for signal in [libc::SIGUSR1, libc::SIGRTMIN()] {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = record_signal as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
            let mut previous = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(signal, &raw const action, &raw mut previous) },
                0
            );
            originals.push((signal, previous));
        }
        let mut caller_mask: libc::sigset_t = unsafe { std::mem::zeroed() };
        unsafe {
            libc::sigemptyset(&raw mut caller_mask);
            libc::sigaddset(&raw mut caller_mask, libc::SIGUSR2);
        }
        let mut original_mask = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_BLOCK,
                    &raw const caller_mask,
                    &raw mut original_mask,
                )
            },
            0
        );
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut caller_mask)
            },
            0
        );

        let exe = std::env::current_exe().unwrap();
        let cli = tino::Cli::try_parse_from([
            "tino",
            "-s",
            "-g",
            "--grace-ms",
            "100",
            "--",
            exe.to_str().unwrap(),
            "flood-workload",
        ])
        .unwrap();
        assert_eq!(tino::run(cli).expect("supervise flooding workload"), 137);
        assert_eq!(HANDLER_CALLS.load(Ordering::Relaxed), 0);
        let mut restored_mask = unsafe { std::mem::zeroed() };
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut restored_mask)
            },
            0
        );
        for signal in 1..=libc::SIGRTMAX() {
            assert_eq!(
                unsafe { libc::sigismember(&raw const restored_mask, signal) },
                unsafe { libc::sigismember(&raw const caller_mask, signal) }
            );
        }
        for (signal, original) in originals {
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(signal, std::ptr::null(), &raw mut action) },
                0
            );
            assert_eq!(action.sa_sigaction, record_signal as *const () as usize);
            assert_ne!(action.sa_flags & libc::SA_RESTART, 0);
            // Concurrent flood probes share RLIMIT_SIGPENDING. Unlike raise's
            // tgkill, kill can send one signal even when that quota is full.
            // This probe is single-threaded, so delivery still tests this handler.
            assert_eq!(
                unsafe { libc::kill(libc::getpid(), signal) },
                0,
                "send signal {signal} to self failed: {}",
                std::io::Error::last_os_error()
            );
            assert_eq!(
                unsafe { libc::sigaction(signal, &raw const original, std::ptr::null_mut()) },
                0
            );
        }
        assert_eq!(HANDLER_CALLS.load(Ordering::Relaxed), 2);
        assert_eq!(
            unsafe {
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const original_mask,
                    std::ptr::null_mut(),
                )
            },
            0
        );
    }

    fn run_flood_probe(library: bool, cleanup: bool) {
        let exe = std::env::current_exe().unwrap();
        let mut command = if library {
            let mut command = Command::new(&exe);
            command.arg("library-flood-probe");
            command
        } else {
            let mut command = Command::new(env!("CARGO_BIN_EXE_tino"));
            command
                .args(["--no-config", "-s", "-g", "--grace-ms", "100", "--"])
                .arg(&exe)
                .arg(if cleanup {
                    "cleanup-flood-workload"
                } else {
                    "flood-workload"
                });
            command
        };
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdout = BufReader::new(child.stdout.take().unwrap());
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read workload PID");
        let group: libc::pid_t = line.trim().parse().expect("workload PID");
        let supervisor = child.id().cast_signed();
        // Preload a backlog before resuming the supervisor, making the test
        // independent of which process gets scheduled first after the gate.
        assert_eq!(unsafe { libc::kill(supervisor, libc::SIGSTOP) }, 0);
        child.stdin.as_mut().unwrap().write_all(b"x").unwrap();
        std::thread::sleep(Duration::from_millis(80));
        if !cleanup {
            assert_eq!(unsafe { libc::kill(supervisor, libc::SIGTERM) }, 0);
        }
        let start = Instant::now();
        assert_eq!(unsafe { libc::kill(supervisor, libc::SIGCONT) }, 0);
        let deadline = start + Duration::from_millis(1200);
        let status = loop {
            if let Some(status) = child.try_wait().unwrap() {
                break Some(status);
            }
            if Instant::now() >= deadline {
                break None;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let elapsed = start.elapsed();
        // Always clean up both the workload group and supervisor on failure.
        if status.is_none() {
            unsafe { libc::kill(-group, libc::SIGKILL) };
            let _ = child.kill();
            let _ = child.wait();
        }
        let expected = if library {
            0
        } else if cleanup {
            37
        } else {
            137
        };
        assert_eq!(
            status.and_then(|status| status.code()),
            Some(expected),
            "elapsed: {elapsed:?}"
        );
    }

    fn signal_flood_does_not_postpone_shutdown() {
        run_flood_probe(false, false);
    }

    fn signal_flood_does_not_postpone_descendant_cleanup() {
        run_flood_probe(false, true);
    }

    fn library_restores_signal_state_after_flood() {
        run_flood_probe(true, false);
    }

    fn library_restores_sigchld_disposition() {
        const PROBE_ENV: &str = "TINO_TEST_SIGCHLD_RESTORE_PROBE";
        if std::env::var_os(PROBE_ENV).is_none() {
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command.arg("sigchld-probe").env(PROBE_ENV, "1");
            let mut child = command.spawn().expect("launch signal state probe");
            assert!(wait_with_timeout(&mut child).success());
            return;
        }

        for (handler, flags) in [
            (libc::SIG_IGN, 0),
            (libc::SIG_DFL, libc::SA_NOCLDWAIT | libc::SA_NOCLDSTOP),
        ] {
            // SAFETY: the probe is isolated; all storage passed to sigaction is valid.
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = handler;
            action.sa_flags = flags;
            unsafe { libc::sigemptyset(&raw mut action.sa_mask) };
            let mut original = unsafe { std::mem::zeroed() };
            assert_eq!(
                unsafe { libc::sigaction(libc::SIGCHLD, &raw const action, &raw mut original) },
                0
            );

            for fail_before_spawn in [false, true] {
                let cli = tino::Cli::try_parse_from([
                    "tino",
                    "--",
                    "/bin/sh",
                    "-c",
                    if fail_before_spawn { "\0" } else { "exit 23" },
                ])
                .expect("parse probe command");
                let result = tino::run(cli);
                if fail_before_spawn {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.expect("run with inherited SIGCHLD action"), 23);
                }
                let mut restored: libc::sigaction = unsafe { std::mem::zeroed() };
                assert_eq!(
                    unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut restored) },
                    0
                );
                assert_eq!(restored.sa_sigaction, handler);
                assert_eq!(
                    restored.sa_flags & (libc::SA_NOCLDWAIT | libc::SA_NOCLDSTOP),
                    flags
                );
            }
            assert_eq!(
                unsafe {
                    libc::sigaction(libc::SIGCHLD, &raw const original, std::ptr::null_mut())
                },
                0
            );
        }
    }

    fn library_rejects_multithreaded_host() {
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("thread-probe")
            .spawn()
            .expect("launch multithreaded library probe");
        assert!(wait_with_timeout(&mut child).success());
    }

    fn multithreaded_probe() {
        // The main thread remains alive and unblocked while run is called from a
        // worker, matching an ordinary library host rather than arranging signals
        // specially for the supervisor.
        std::thread::spawn(|| {
            let mut before: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut mask_before: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                assert_eq!(
                    libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut before),
                    0
                );
                assert_eq!(
                    libc::pthread_sigmask(
                        libc::SIG_SETMASK,
                        std::ptr::null(),
                        &raw mut mask_before
                    ),
                    0
                );
            }
            let cli = tino::Cli::parse_from(["tino", "--", "/bin/sh", "-c", "exit 37"]);
            let err = tino::run(cli).expect_err("multithreaded supervision must be rejected");
            assert!(
                err.to_string()
                    .contains("requires a single-threaded process"),
                "{err}"
            );
            let mut after: libc::sigaction = unsafe { std::mem::zeroed() };
            let mut mask_after: libc::sigset_t = unsafe { std::mem::zeroed() };
            unsafe {
                assert_eq!(
                    libc::sigaction(libc::SIGCHLD, std::ptr::null(), &raw mut after),
                    0
                );
                assert_eq!(
                    libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut mask_after),
                    0
                );
                for signal in 1..=libc::SIGRTMAX() {
                    assert_eq!(
                        libc::sigismember(&raw const mask_before, signal),
                        libc::sigismember(&raw const mask_after, signal)
                    );
                }
                assert_eq!(libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG), -1);
                assert_eq!(
                    std::io::Error::last_os_error().raw_os_error(),
                    Some(libc::ECHILD)
                );
            }
            assert_eq!(before.sa_sigaction, after.sa_sigaction);
            assert_eq!(before.sa_flags, after.sa_flags);
        })
        .join()
        .expect("worker probe");
    }

    fn library_control_output_survives_signal_discard_failure() {
        for output in ["file", "pipe"] {
            for errno in [libc::EPERM, libc::EINTR] {
                let mut probe = Command::new(std::env::current_exe().unwrap())
                    .args([
                        "output-signal-discard-failure-probe",
                        output,
                        &errno.to_string(),
                    ])
                    .spawn()
                    .expect("launch output signal failure probe");
                assert!(
                    wait_with_timeout(&mut probe).success(),
                    "output={output}, errno={errno}"
                );
            }
        }
    }

    fn output_signal_discard_failure_probe(output: &str, errno: libc::c_int) {
        use std::os::fd::AsRawFd;

        let signal = if output == "file" {
            libc::SIGXFSZ
        } else {
            libc::SIGPIPE
        };
        let mut original_mask = unsafe { std::mem::zeroed() };
        // SAFETY: this isolated, single-threaded probe owns its signal state.
        unsafe {
            assert_ne!(libc::signal(signal, libc::SIG_DFL), libc::SIG_ERR);
            libc::sigemptyset(&raw mut original_mask);
            libc::sigaddset(&raw mut original_mask, libc::SIGUSR1);
            assert_eq!(
                libc::pthread_sigmask(
                    libc::SIG_SETMASK,
                    &raw const original_mask,
                    std::ptr::null_mut()
                ),
                0
            );
            assert_eq!(libc::kill(libc::getpid(), libc::SIGUSR1), 0);
        }
        let writer = if output == "file" {
            let fd =
                unsafe { libc::memfd_create(c"tino-output-limit".as_ptr(), libc::MFD_CLOEXEC) };
            assert!(fd >= 0);
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_FSIZE, &limit) }, 0);
            unsafe { OwnedFd::from_raw_fd(fd) }
        } else {
            let mut fds = [0; 2];
            assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
            drop(unsafe { OwnedFd::from_raw_fd(fds[0]) });
            unsafe { OwnedFd::from_raw_fd(fds[1]) }
        };
        assert_eq!(
            unsafe { libc::dup2(writer.as_raw_fd(), libc::STDOUT_FILENO) },
            libc::STDOUT_FILENO
        );

        #[cfg(target_arch = "arm")]
        let timedwait_time64 = 421;
        #[cfg(all(target_arch = "riscv32", target_env = "musl"))]
        let timedwait_time64 = libc::SYS_rt_sigtimedwait_time64 as u32;
        #[cfg(not(any(target_arch = "arm", all(target_arch = "riscv32", target_env = "musl"))))]
        let timedwait_time64 = libc::SYS_rt_sigtimedwait as u32;
        let mut filter = [
            libc::sock_filter {
                code: 0x20,
                jt: 0,
                jf: 0,
                k: 0,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 1,
                jf: 0,
                k: libc::SYS_rt_sigtimedwait as u32,
            },
            libc::sock_filter {
                code: 0x15,
                jt: 0,
                jf: 1,
                k: timedwait_time64,
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ERRNO | errno.cast_unsigned(),
            },
            libc::sock_filter {
                code: 0x06,
                jt: 0,
                jf: 0,
                k: libc::SECCOMP_RET_ALLOW,
            },
        ];
        let program = libc::sock_fprog {
            len: filter.len().try_into().unwrap(),
            filter: filter.as_mut_ptr(),
        };
        unsafe {
            assert_eq!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0), 0);
            assert_eq!(
                libc::prctl(libc::PR_SET_SECCOMP, libc::SECCOMP_MODE_FILTER, &program),
                0
            );
        }
        let error = tino::run(tino::Cli {
            explain: true,
            no_config: true,
            ..Default::default()
        })
        .expect_err("failed control output must return its I/O error");
        let io_error = std::error::Error::source(&error)
            .unwrap()
            .downcast_ref::<std::io::Error>()
            .unwrap();
        assert_eq!(
            io_error.raw_os_error(),
            Some(if output == "file" {
                libc::EFBIG
            } else {
                libc::EPIPE
            })
        );
        let mut current_mask = unsafe { std::mem::zeroed() };
        let mut pending = unsafe { std::mem::zeroed() };
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        unsafe {
            assert_eq!(
                libc::pthread_sigmask(libc::SIG_SETMASK, std::ptr::null(), &raw mut current_mask),
                0
            );
            assert_eq!(libc::sigpending(&raw mut pending), 0);
            for candidate in 1..=libc::SIGRTMAX() {
                let expected = candidate == signal
                    || libc::sigismember(&raw const original_mask, candidate) == 1;
                assert_eq!(
                    libc::sigismember(&raw const current_mask, candidate) == 1,
                    expected
                );
            }
            assert_eq!(libc::sigismember(&raw const pending, signal), 1);
            assert_eq!(libc::sigismember(&raw const pending, libc::SIGUSR1), 1);
            assert_eq!(
                libc::sigaction(signal, std::ptr::null(), &raw mut action),
                0
            );
        }
        assert_eq!(action.sa_sigaction, libc::SIG_DFL);
    }

    pub(super) fn run() {
        let tests: [(&str, fn()); 29] = [
            (
                "readonly_stderr_does_not_gain_write_access",
                readonly_stderr_does_not_gain_write_access,
            ),
            (
                "full_stderr_does_not_postpone_shutdown",
                full_stderr_does_not_postpone_shutdown,
            ),
            (
                "exec_failure_preserves_status_with_full_stderr",
                exec_failure_preserves_status_with_full_stderr,
            ),
            (
                "child_resets_inherited_caught_signal_handlers",
                child_resets_inherited_caught_signal_handlers,
            ),
            (
                "library_control_output_survives_signal_discard_failure",
                library_control_output_survives_signal_discard_failure,
            ),
            (
                "inherited_sigchld_ignore_does_not_lose_exit_status",
                inherited_sigchld_ignore_does_not_lose_exit_status,
            ),
            (
                "child_sigpipe_uses_default_disposition",
                child_sigpipe_uses_default_disposition,
            ),
            (
                "exec_failure_preserves_status_with_broken_stderr",
                exec_failure_preserves_status_with_broken_stderr,
            ),
            (
                "diagnostics_preserve_status_with_file_size_limit",
                diagnostics_preserve_status_with_file_size_limit,
            ),
            (
                "external_sigxfsz_is_forwarded",
                external_sigxfsz_is_forwarded,
            ),
            (
                "library_preserves_subreaper_when_state_query_fails",
                library_preserves_subreaper_when_state_query_fails,
            ),
            (
                "library_reports_subreaper_restore_failure",
                library_reports_subreaper_restore_failure,
            ),
            (
                "library_reports_sigchld_restore_failure",
                library_reports_sigchld_restore_failure,
            ),
            (
                "library_preserves_terminal_foreground_ownership",
                library_preserves_terminal_foreground_ownership,
            ),
            (
                "library_handles_signal_discard_failures",
                library_handles_signal_discard_failures,
            ),
            (
                "terminal_job_control_supports_foreground_and_background_resume",
                terminal_job_control_supports_foreground_and_background_resume,
            ),
            (
                "terminal_stop_keeps_orphan_supervisor_responsive",
                terminal_stop_keeps_orphan_supervisor_responsive,
            ),
            (
                "supervision_failure_cleans_up_only_the_managed_child",
                supervision_failure_cleans_up_only_the_managed_child,
            ),
            (
                "main_child_receives_signals_after_leaving_initial_group",
                main_child_receives_signals_after_leaving_initial_group,
            ),
            (
                "supervision_failure_reaps_adopted_descendants",
                supervision_failure_reaps_adopted_descendants,
            ),
            (
                "cleanup_failure_terminates_adopted_descendants",
                cleanup_failure_terminates_adopted_descendants,
            ),
            (
                "inherited_blocked_abort_does_not_terminate_supervisor",
                inherited_blocked_abort_does_not_terminate_supervisor,
            ),
            (
                "library_preserves_blocked_fault_signals",
                library_preserves_blocked_fault_signals,
            ),
            (
                "library_preserves_preexisting_pending_signals",
                library_preserves_preexisting_pending_signals,
            ),
            (
                "library_restores_sigchld_disposition",
                library_restores_sigchld_disposition,
            ),
            (
                "library_rejects_multithreaded_host",
                library_rejects_multithreaded_host,
            ),
            (
                "signal_flood_does_not_postpone_shutdown",
                signal_flood_does_not_postpone_shutdown,
            ),
            (
                "signal_flood_does_not_postpone_descendant_cleanup",
                signal_flood_does_not_postpone_descendant_cleanup,
            ),
            (
                "library_restores_signal_state_after_flood",
                library_restores_signal_state_after_flood,
            ),
        ];
        let args: Vec<_> = std::env::args().skip(1).collect();
        match args.first().map(String::as_str) {
            Some("full-stderr-workload") => full_stderr_workload(),
            Some("sigchld-restore-failure-probe") => {
                sigchld_restore_failure_probe();
                return;
            }
            Some("subreaper-restore-failure-probe") => {
                subreaper_restore_failure_probe(args[1] == "supervision");
                return;
            }
            Some("child-signal-handler-probe") => {
                child_signal_handler_probe(args[1].as_str());
                return;
            }
            Some("output-signal-discard-failure-probe") => {
                output_signal_discard_failure_probe(&args[1], args[2].parse().unwrap());
                return;
            }
            Some("signal-discard-failure-probe") => {
                signal_discard_failure_probe(args[1] == "blocked");
                return;
            }
            Some("signal-discard-failure-workload") => {
                signal_discard_failure_workload();
            }
            Some("file-size-pending-probe") => {
                file_size_pending_probe();
                return;
            }
            Some("pending-signals-library-probe") => {
                pending_signals_library_probe();
                return;
            }
            Some("pending-signals-workload") => {
                pending_signals_workload();
                return;
            }
            Some("moved-main-workload") => {
                moved_main_workload(args[1] == "ignore");
            }
            Some("descendant-failure-probe") => {
                descendant_failure_probe(args[1] == "cleanup");
                return;
            }
            Some("descendant-failure-workload") => {
                descendant_failure_workload(args[1] == "cleanup");
            }
            Some("subreaper-query-failure-probe") => {
                subreaper_query_failure_probe(args[1].parse().unwrap());
                return;
            }
            Some("failed-supervision-probe") => {
                failed_supervision_probe(args[1] == "group");
                return;
            }
            Some(
                mode @ ("tty-library-probe"
                | "tty-job-control-probe"
                | "tty-orphan-supervisor-probe"),
            ) => {
                tty_library_probe(mode);
                return;
            }
            Some("tty-pending-cont-supervisor") => {
                tty_pending_cont_supervisor();
                return;
            }
            Some("tty-read-workload") => {
                // Exercise ordinary terminal reads even if the test launcher
                // inherited a blocked or ignored TTIN from its own shell.
                unsafe {
                    libc::signal(libc::SIGTTIN, libc::SIG_DFL);
                    let mut mask = std::mem::zeroed();
                    libc::sigemptyset(&raw mut mask);
                    libc::sigaddset(&raw mut mask, libc::SIGTTIN);
                    assert_eq!(
                        libc::pthread_sigmask(
                            libc::SIG_UNBLOCK,
                            &raw const mask,
                            std::ptr::null_mut()
                        ),
                        0
                    );
                }
                println!("{}", std::process::id());
                std::io::stdout().flush().unwrap();
                let mut byte = [0];
                std::io::stdin().read_exact(&mut byte).unwrap();
                assert_eq!(byte[0], b'x');
                std::process::exit(23);
            }
            Some("tty-background-library-probe") => {
                run_tty_command("tty-expect-background", &[]);
                return;
            }
            Some(mode @ ("tty-expect-foreground" | "tty-expect-background")) => {
                let foreground = unsafe { libc::tcgetpgrp(0) };
                assert!(foreground > 0);
                assert_eq!(
                    foreground == unsafe { libc::getpgrp() },
                    mode == "tty-expect-foreground",
                );
                return;
            }
            Some("tty-move-foreground") => {
                let group: libc::pid_t = args[1].parse().unwrap();
                assert_eq!(unsafe { libc::tcsetpgrp(0, group) }, 0);
                return;
            }
            Some("tty-foreground-holder") => {
                std::io::stdin().read_to_end(&mut Vec::new()).unwrap();
                return;
            }
            Some("flood-workload") => flood_workload(false),
            Some("cleanup-flood-workload") => flood_workload(true),
            Some("library-flood-probe") => {
                library_flood_probe();
                return;
            }
            Some("sigchld-probe") => {
                library_restores_sigchld_disposition();
                return;
            }
            Some("thread-probe") => {
                multithreaded_probe();
                return;
            }
            _ => {}
        }
        // Implement nextest's custom-harness protocol while running each probe on
        // this process's main thread. There are no ignored tests in this harness.
        if args.iter().any(|arg| arg == "--ignored") {
            return;
        }
        let list = args.iter().any(|arg| arg == "--list");
        let exact = args.iter().any(|arg| arg == "--exact");
        let mut filters = Vec::new();
        let mut skips = Vec::new();
        let mut arguments = args.iter();
        while let Some(arg) = arguments.next() {
            match arg.as_str() {
                "--format" | "--color" | "--test-threads" | "-Z" => {
                    arguments.next();
                }
                "--skip" => {
                    if let Some(skip) = arguments.next() {
                        skips.push(skip);
                    }
                }
                _ if !arg.starts_with('-') => filters.push(arg),
                _ => {}
            }
        }
        let matches = |name: &str, filter: &String| {
            if exact {
                name == filter
            } else {
                name.contains(filter.as_str())
            }
        };
        for (name, test) in tests {
            if (!filters.is_empty() && !filters.iter().any(|filter| matches(name, filter)))
                || skips.iter().any(|skip| matches(name, skip))
            {
                continue;
            }
            if list {
                println!("{name}: test");
            } else {
                test();
                println!("test {name} ... ok");
            }
        }
    }
}
