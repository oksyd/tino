use super::*;
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(super::tests::unique_env_name("PINNED_POLICY"));
        std::fs::create_dir(&path).expect("create policy fixture");
        Self(path)
    }

    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn require_abi(version: u32) -> bool {
    let available = landlock::query_abi_version()
        .ok()
        .flatten()
        .is_some_and(|abi| abi >= version);
    if std::env::var_os("TINO_TEST_REQUIRE_LANDLOCK").is_some() {
        assert!(available, "Landlock ABI {version} required for policy test");
    }
    available
}

fn run_policy(config: &LandlockConfig, args: &[&str]) -> i32 {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let (program, argv) = prepare_resolved_command(&args).expect("prepare policy probe");
    let mask = SigSet::thread_get_mask().expect("read test signal mask");
    let pid = spawn_child(&mask, None, Some(config), false, &program, &argv)
        .expect("spawn policy probe")
        .as_raw();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut status = 0;
        // SAFETY: only reap this test's child; status points to writable storage.
        let waited = unsafe { libc::waitpid(pid, &raw mut status, libc::WNOHANG) };
        if waited == pid {
            assert!(libc::WIFEXITED(status), "policy probe terminated: {status}");
            return libc::WEXITSTATUS(status);
        }
        assert!(
            waited >= 0 || Errno::last() == Errno::EINTR,
            "waitpid failed"
        );
        if Instant::now() >= deadline {
            // SAFETY: terminate and reap the owned probe on timeout.
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &raw mut status, 0);
            }
            panic!("policy probe timed out");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn write_rules_keep_validated_directory_after_symlink_replacement() {
    let _lock = CHILD_TEST_LOCK.lock().unwrap();
    if !require_abi(3) {
        return;
    }
    let root = Fixture::new();
    let allowed = root.join("allowed");
    let saved = root.join("saved");
    let outside = root.join("outside");
    std::fs::create_dir(&allowed).unwrap();
    std::fs::create_dir(&outside).unwrap();
    let cli = Cli {
        write_allow: vec![allowed.to_str().unwrap().into()],
        write_no_dev: true,
        ..Cli::default()
    };
    let config = build_landlock_config(&cli).unwrap().unwrap();
    std::fs::rename(&allowed, &saved).unwrap();
    symlink(&outside, &allowed).unwrap();

    let status = run_policy(
        &config,
        &[
            "/bin/sh",
            "-c",
            r#"printf allowed > "$1/ok" || exit 10; if (printf denied > "$2/deny"); then exit 11; fi; exit 13"#,
            "probe",
            saved.to_str().unwrap(),
            allowed.to_str().unwrap(),
        ],
    );
    assert_eq!(status, 13);
    assert_eq!(std::fs::read(saved.join("ok")).unwrap(), b"allowed");
    assert!(!outside.join("deny").exists());
}

#[test]
fn exec_rules_keep_validated_file_after_symlink_replacement() {
    let _lock = CHILD_TEST_LOCK.lock().unwrap();
    if !require_abi(1) {
        return;
    }
    let root = Fixture::new();
    let allowed = root.join("allowed");
    let saved = root.join("saved");
    let outside = root.join("outside");
    std::fs::copy("/bin/true", &allowed).unwrap();
    std::fs::copy("/bin/true", &outside).unwrap();
    let cli = Cli {
        exec_allow: vec![allowed.to_str().unwrap().into()],
        cmd: vec!["/bin/sh".into()],
        ..Cli::default()
    };
    let config = build_landlock_config(&cli).unwrap().unwrap();
    std::fs::rename(&allowed, &saved).unwrap();
    symlink(&outside, &allowed).unwrap();

    for (target, expected) in [(&saved, 0), (&allowed, 126), (&outside, 126)] {
        assert_eq!(
            run_policy(
                &config,
                &[
                    "/bin/sh",
                    "-c",
                    r#"exec "$1""#,
                    "probe",
                    target.to_str().unwrap(),
                ]
            ),
            expected,
            "target: {}",
            target.display()
        );
    }
}

#[test]
fn ioctl_rules_do_not_follow_directory_replaced_with_dev_symlink() {
    let _lock = CHILD_TEST_LOCK.lock().unwrap();
    if !require_abi(5)
        || !Command::new("python3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    {
        return;
    }
    let root = Fixture::new();
    let allowed = root.join("allowed");
    std::fs::create_dir(&allowed).unwrap();
    let cli = Cli {
        device_ioctl_allow: vec![allowed.to_str().unwrap().into()],
        ..Cli::default()
    };
    let config = build_landlock_config(&cli).unwrap().unwrap();
    std::fs::rename(&allowed, root.join("saved")).unwrap();
    symlink("/dev", &allowed).unwrap();
    let script = r#"import fcntl, os, sys, termios
fd = os.open('/dev/ptmx', os.O_RDWR | os.O_NOCTTY)
try:
    fcntl.ioctl(fd, termios.TIOCGWINSZ, b'\0' * 8)
except PermissionError:
    sys.exit(13)
sys.exit(0)
"#;
    // Verify the device supports this ioctl before checking the denial.
    let control = Cli {
        device_ioctl_allow: vec!["/dev".into()],
        ..Cli::default()
    };
    assert_eq!(
        run_policy(
            &build_landlock_config(&control).unwrap().unwrap(),
            &["python3", "-c", script]
        ),
        0
    );
    assert_eq!(run_policy(&config, &["python3", "-c", script]), 13);
}

#[test]
fn interpreter_discovery_reads_validated_inode_after_replacement() {
    let root = Fixture::new();
    let script = root.join("script");
    std::fs::write(&script, b"#!/bin/sh\nexit 0\n").unwrap();
    let pinned = PinnedPath::open(&script, PathRuleKind::Any).unwrap();
    std::fs::rename(&script, root.join("saved")).unwrap();
    std::fs::write(&script, b"#!/bin/false\n").unwrap();
    let interpreters = detect_exec_interpreters_in_context(&pinned, &ExecContext::inherited())
        .expect("inspect pinned script");
    assert!(
        matches!(&interpreters[..], [ExecInterpreter::Candidate(path)] if path == Path::new("/bin/sh"))
    );
}
