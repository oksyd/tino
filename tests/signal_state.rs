#![cfg(target_os = "linux")]

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

#[test]
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

#[test]
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

#[test]
fn library_restores_sigchld_disposition() {
    const PROBE_ENV: &str = "TINO_TEST_SIGCHLD_RESTORE_PROBE";
    if std::env::var_os(PROBE_ENV).is_none() {
        // Run process-wide signal mutations in an isolated test process. Block
        // SIGCHLD before the harness creates threads so the supervisor owns it.
        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command
            .args([
                "--exact",
                "library_restores_sigchld_disposition",
                "--nocapture",
            ])
            .env(PROBE_ENV, "1");
        // SAFETY: only async-signal-safe calls execute in the forked launcher.
        unsafe {
            command.pre_exec(|| {
                let mut mask = std::mem::zeroed();
                libc::sigemptyset(&raw mut mask);
                libc::sigaddset(&raw mut mask, libc::SIGCHLD);
                let rc =
                    libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, std::ptr::null_mut());
                if rc != 0 {
                    return Err(std::io::Error::from_raw_os_error(rc));
                }
                Ok(())
            });
        }
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
            unsafe { libc::sigaction(libc::SIGCHLD, &raw const original, std::ptr::null_mut()) },
            0
        );
    }
}
