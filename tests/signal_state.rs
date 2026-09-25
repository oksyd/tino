// A custom harness keeps the library probes single-threaded. libtest would
// create a worker thread before the probe can exercise the public run API.
fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {

    use std::io::{BufRead, BufReader, Read, Write};
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

    pub(super) fn run() {
        let tests: [(&str, fn()); 9] = [
            (
                "inherited_sigchld_ignore_does_not_lose_exit_status",
                inherited_sigchld_ignore_does_not_lose_exit_status,
            ),
            (
                "child_sigpipe_uses_default_disposition",
                child_sigpipe_uses_default_disposition,
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
