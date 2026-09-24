// A custom harness keeps the library probes single-threaded. libtest would
// create a worker thread before the probe can exercise the public run API.
fn main() {
    #[cfg(target_os = "linux")]
    linux::run();
}

#[cfg(target_os = "linux")]
mod linux {

    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, ExitStatus};
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
        let tests: [(&str, fn()); 4] = [
            (
                "inherited_sigchld_ignore_does_not_lose_exit_status",
                inherited_sigchld_ignore_does_not_lose_exit_status,
            ),
            (
                "child_sigpipe_uses_default_disposition",
                child_sigpipe_uses_default_disposition,
            ),
            (
                "library_restores_sigchld_disposition",
                library_restores_sigchld_disposition,
            ),
            (
                "library_rejects_multithreaded_host",
                library_rejects_multithreaded_host,
            ),
        ];
        let args: Vec<_> = std::env::args().skip(1).collect();
        match args.first().map(String::as_str) {
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
        let filter = args.first().filter(|arg| !arg.starts_with('-'));
        for (name, test) in tests {
            if filter.is_some_and(|filter| {
                if exact {
                    name != filter
                } else {
                    !name.contains(filter.as_str())
                }
            }) {
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
