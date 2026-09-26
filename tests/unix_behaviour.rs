#![cfg(target_os = "linux")]

use std::io::{BufRead, BufReader};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn tino_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tino")
}

fn tino_command() -> Command {
    let mut command = Command::new(tino_bin());
    command.arg("--no-config");
    command
}

fn landlock_available() -> bool {
    let output = tino_command()
        .args([
            "--restrict-warn-only",
            "--write-preset",
            "tmp",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("failed to probe landlock availability");

    let require = std::env::var_os("TINO_TEST_REQUIRE_LANDLOCK").is_some();
    if !output.status.success() {
        if require {
            panic!(
                "landlock probe failed with exit status {:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return false;
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let available = !stderr.contains("access restriction unavailable; continuing");
    if require && !available {
        panic!("landlock required for CI but unavailable:\n{stderr}");
    }
    available
}

fn landlock_tcp_available() -> bool {
    let output = tino_command()
        .args([
            "--restrict-warn-only",
            "--bind-tcp-allow",
            "1",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("failed to probe landlock TCP availability");

    let require = std::env::var_os("TINO_TEST_REQUIRE_LANDLOCK").is_some();
    if !output.status.success() {
        if require {
            panic!(
                "landlock TCP probe failed with exit status {:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return false;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let available = !stderr.contains("access restriction unavailable; continuing");
    if require && !available {
        panic!("landlock TCP restrictions required for CI but unavailable:\n{stderr}");
    }
    available
}

fn landlock_scope_available() -> bool {
    let output = tino_command()
        .args([
            "--restrict-warn-only",
            "--scope-signals",
            "--",
            "sh",
            "-c",
            "exit 0",
        ])
        .output()
        .expect("failed to probe landlock scope availability");

    let require = std::env::var_os("TINO_TEST_REQUIRE_LANDLOCK").is_some();
    if !output.status.success() {
        if require {
            panic!(
                "landlock scope probe failed with exit status {:?}\nstderr:\n{}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        return false;
    }

    let stderr = String::from_utf8_lossy(&output.stderr);
    let available = !stderr.contains("access restriction unavailable; continuing");
    if require && !available {
        panic!("landlock IPC scopes required for CI but unavailable:\n{stderr}");
    }
    available
}

fn python3_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

fn next_free_tcp_port() -> u16 {
    TcpListener::bind(("127.0.0.1", 0))
        .expect("bind ephemeral TCP port")
        .local_addr()
        .expect("query listener address")
        .port()
}

fn distinct_free_tcp_ports() -> (u16, u16) {
    let first = next_free_tcp_port();
    loop {
        let second = next_free_tcp_port();
        if second != first {
            return (first, second);
        }
    }
}

fn unique_temp_dir(prefix: &str) -> std::path::PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}-{}-{nanos}", std::process::id()))
}

fn write_exec_fixture(path: &std::path::Path, text: &str) {
    std::fs::write(path, text).expect("write executable fixture");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("chmod executable fixture");
}

fn without_capabilities(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    // Even a root CI runner must encounter EACCES on execute-only files. These
    // calls only reduce the forked launcher's privileges and allocate nothing.
    unsafe {
        command.pre_exec(|| {
            let header = [0x2008_0522u32, 0]; // Linux capability ABI version 3, self.
            let data = [0u32; 6]; // Two effective/permitted/inheritable triples.
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1
                || libc::syscall(libc::SYS_capset, header.as_ptr(), data.as_ptr()) == -1
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[test]
fn landlock_exec_allows_execute_only_main_by_absolute_path_and_path_search() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-execute-only-main");
    std::fs::create_dir_all(&root).expect("create execute-only fixture directory");
    let program = root.join("probe");
    std::fs::copy("/bin/true", &program).expect("copy execute-only program");
    std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o111))
        .expect("remove read permissions");
    for main in [program.as_os_str(), std::ffi::OsStr::new("probe")] {
        let mut command = tino_command();
        command
            .env("PATH", &root)
            .args(["--exec-allow", "/bin/true", "--"])
            .arg(main);
        without_capabilities(&mut command);
        let output = command.output().expect("run execute-only main");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{main:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(root).expect("remove execute-only fixtures");
}

#[test]
fn landlock_exec_preserves_inaccessible_main_command_status() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-inaccessible-main");
    let private = root.join("private");
    std::fs::create_dir_all(&private).expect("create inaccessible main fixture");
    let program = private.join("main");
    std::fs::copy("/bin/true", &program).expect("copy inaccessible main");
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o600))
        .expect("remove directory search permission");

    for restricted in [false, true] {
        let mut command = tino_command();
        if restricted {
            command.args(["--exec-allow", "/bin/true"]);
        }
        command.arg("--").arg(&program);
        without_capabilities(&mut command);
        let output = command.output().expect("run inaccessible main");
        assert_eq!(
            output.status.code(),
            Some(126),
            "restricted={restricted}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("permission denied"));
    }

    // An explicitly requested allow path still requires successful validation.
    let mut command = tino_command();
    command
        .arg("--exec-allow")
        .arg(&program)
        .args(["--", "/bin/true"]);
    without_capabilities(&mut command);
    let output = command
        .output()
        .expect("validate inaccessible explicit allow path");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("open exec allow path"));

    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700))
        .expect("restore fixture directory access");
    std::fs::remove_dir_all(root).expect("remove inaccessible main fixture");
}

#[test]
fn landlock_exec_preserves_unexecutable_main_errors() {
    use std::os::unix::ffi::OsStrExt;

    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-unexecutable-main");
    std::fs::create_dir(&root).expect("create unexecutable main fixture");
    let loop_path = root.join("loop");
    std::os::unix::fs::symlink("loop", &loop_path).expect("create symlink loop");
    let long_path = root.join("x".repeat(256));
    let fifo = root.join("fifo");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o700) }, 0);
    for path in [loop_path, long_path, fifo, "/dev/null".into()] {
        for restricted in [false, true] {
            let mut command = tino_command();
            if restricted {
                command.args(["--exec-allow", "/bin/true"]);
            }
            let output = command.arg("--").arg(&path).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(126),
                "path={path:?}, restricted={restricted}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stderr).contains("tino: execvp failed"));
        }
        let output = tino_command()
            .arg("--exec-allow")
            .arg(&path)
            .args(["--", "/bin/true"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1), "explicit path={path:?}");
    }
    std::fs::remove_dir_all(root).expect("remove unexecutable main fixture");
}

// Locate ELF segments without depending on patchelf or a compiler. /bin/true
// may be static on minimal systems, in which case interpreter tests skip it.
fn native_elf_segment(
    bytes: &[u8],
    kind: usize,
) -> Option<(std::ops::Range<usize>, std::ops::Range<usize>)> {
    if !bytes.starts_with(b"\x7fELF") {
        return None;
    }
    let little = bytes[5] == 1;
    let number = |offset: usize, len: usize| -> usize {
        let slice = &bytes[offset..offset + len];
        if little {
            slice
                .iter()
                .rev()
                .fold(0, |value, byte| (value << 8) | usize::from(*byte))
        } else {
            slice
                .iter()
                .fold(0, |value, byte| (value << 8) | usize::from(*byte))
        }
    };
    let (table, stride, count, offset_field, size_field, word) = match bytes[4] {
        1 => (number(28, 4), number(42, 2), number(44, 2), 4, 16, 4),
        2 => (number(32, 8), number(54, 2), number(56, 2), 8, 32, 8),
        _ => return None,
    };
    for index in 0..count {
        let header = table + index * stride;
        if number(header, 4) == kind {
            let offset = number(header + offset_field, word);
            return Some((
                header..header + stride,
                offset..offset + number(header + size_field, word),
            ));
        }
    }
    None
}

fn native_elf_interpreter_range(bytes: &[u8]) -> Option<std::ops::Range<usize>> {
    native_elf_segment(bytes, 3).map(|(_, range)| range)
}

#[test]
fn landlock_exec_uses_first_elf_interpreter() {
    if !landlock_available() {
        return;
    }
    let original = std::fs::read("/bin/true").expect("read native executable");
    let Some((interpreter_header, _)) = native_elf_segment(&original, 3) else {
        return;
    };
    let Some((note_header, _)) = native_elf_segment(&original, 4) else {
        return;
    };
    assert!(note_header.start > interpreter_header.start);
    let root = unique_temp_dir("tino-multiple-elf-interpreters");
    let allowed = root.join("empty");
    std::fs::create_dir_all(&allowed).unwrap();
    let program = root.join("probe");
    let (offset_field, size_field, word) = if original[4] == 2 {
        (8, 32, 8)
    } else {
        (4, 16, 4)
    };
    for invalid_range in [false, true] {
        let mut bytes = original.clone();
        bytes[note_header.clone()].copy_from_slice(&original[interpreter_header.clone()]);
        let extra = b"/definitely/missing/tino-ignored-interpreter\0";
        let offset = bytes.len() + if invalid_range { 4096 } else { 0 };
        for (field, value) in [(offset_field, offset), (size_field, extra.len())] {
            let value = value as u64;
            let (encoded, start) = if original[5] == 1 {
                (value.to_le_bytes(), 0)
            } else {
                (value.to_be_bytes(), 8 - word)
            };
            let field = note_header.start + field;
            bytes[field..field + word].copy_from_slice(&encoded[start..start + word]);
        }
        bytes.extend_from_slice(extra);
        std::fs::write(&program, bytes).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(Command::new(&program).status().unwrap().success());
        // Cover automatic main-command discovery and strict explicit entries.
        for allow in [&allowed, &program] {
            let output = tino_command()
                .arg("--exec-allow")
                .arg(allow)
                .arg("--")
                .arg(&program)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(0),
                "invalid_range={invalid_range}, allow={allow:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_allows_file_backed_load_segments_past_eof() {
    use std::os::unix::ffi::OsStrExt;

    if !landlock_available() {
        return;
    }
    let original = std::fs::read("/bin/true").expect("read native executable");
    let Some(interpreter) = native_elf_interpreter_range(&original) else {
        return;
    };
    let Some((extra_header, _)) = native_elf_segment(&original, 0x6474_e552) else {
        return; // Use the optional GNU_RELRO entry without changing the table size.
    };
    let root = unique_temp_dir("tino-elf-load-past-eof");
    let allowed = root.join("empty");
    std::fs::create_dir_all(&allowed).unwrap();
    let loader = std::ffi::OsStr::from_bytes(
        original[interpreter.clone()]
            .split(|byte| *byte == 0)
            .next()
            .unwrap(),
    );
    // A distinct inode prevents the shell fallback's system loader grant from
    // hiding failure to discover the main executable's actual interpreter.
    std::fs::copy(loader, root.join("ld")).expect("copy local loader");
    let program = root.join("probe");
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let offset = original.len().div_ceil(page) * page + page;
    let (offset_field, vaddr_field, size_field, memsz_field, align_field, flags_field, word) =
        if original[4] == 2 {
            (8, 16, 32, 40, 48, 4, 8)
        } else {
            (4, 8, 16, 20, 28, 24, 4)
        };
    for filesz in [0, 1, page] {
        let mut bytes = original.clone();
        bytes[interpreter.clone()].fill(0);
        bytes[interpreter.start..interpreter.start + 3].copy_from_slice(b"ld\0");
        bytes[extra_header.clone()].fill(0);
        for (field, len, value) in [
            (0, 4, 1),           // PT_LOAD
            (flags_field, 4, 4), // PF_R
            (offset_field, word, offset),
            (vaddr_field, word, 0x100_0000),
            (size_field, word, filesz),
            (memsz_field, word, page),
            (align_field, word, page),
        ] {
            let (encoded, start) = if original[5] == 1 {
                ((value as u64).to_le_bytes(), 0)
            } else {
                ((value as u64).to_be_bytes(), 8 - len)
            };
            let field = extra_header.start + field;
            bytes[field..field + len].copy_from_slice(&encoded[start..start + len]);
        }
        std::fs::write(&program, bytes).unwrap();
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            Command::new(&program)
                .current_dir(&root)
                .status()
                .unwrap()
                .success(),
            "kernel must accept the fixture, filesz={filesz}"
        );
        for allow in [&allowed, &program] {
            let output = tino_command()
                .current_dir(&root)
                .arg("--exec-allow")
                .arg(allow)
                .arg("--")
                .arg(&program)
                .output()
                .unwrap();
            assert_eq!(
                output.status.code(),
                Some(0),
                "filesz={filesz}, allow={allow:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_resolves_bare_elf_loader_from_cwd() {
    use std::os::unix::ffi::OsStrExt;

    if !landlock_available() {
        return;
    }
    let original = std::fs::read("/bin/true").expect("read native executable");
    let Some(range) = native_elf_interpreter_range(&original) else {
        return;
    };
    let loader = std::ffi::OsStr::from_bytes(
        original[range.clone()]
            .split(|byte| *byte == 0)
            .next()
            .unwrap(),
    );
    let root = unique_temp_dir("tino-relative-elf-loader");
    let allowed = root.join("empty");
    std::fs::create_dir_all(&allowed).expect("create ELF fixture directory");
    std::os::unix::fs::symlink(loader, root.join("auditld")).expect("link local loader");
    let program = root.join("probe");
    for interpreter in [b"auditld\0".as_slice(), b"./auditld\0"] {
        assert!(interpreter.len() <= range.len());
        let mut bytes = original.clone();
        bytes[range.clone()].fill(0);
        bytes[range.start..range.start + interpreter.len()].copy_from_slice(interpreter);
        std::fs::write(&program, bytes).expect("write native ELF with relative loader");
        std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(
            Command::new(&program)
                .current_dir(&root)
                .status()
                .unwrap()
                .success()
        );
        let output = tino_command()
            .current_dir(&root)
            .env("PATH", &allowed)
            .arg("--exec-allow")
            .arg(&allowed)
            .arg("--")
            .arg(&program)
            .output()
            .expect("run ELF with relative loader under Landlock");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{interpreter:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(root).expect("remove ELF fixtures");
}

#[test]
fn landlock_exec_ignores_unreadable_later_path_candidate() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-unreadable-path");
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(&first).expect("create first PATH dir");
    std::fs::create_dir_all(&second).expect("create second PATH dir");
    write_exec_fixture(&first.join("probe"), "#!/bin/sh\nexit 37\n");
    let unreadable = second.join("probe");
    std::fs::copy("/bin/true", &unreadable).expect("copy execute-only binary");
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o111))
        .expect("remove read permission");
    let path = std::env::join_paths([&first, &second]).expect("PATH");
    for args in [
        vec!["--", "probe"],
        vec!["--exec-allow", "/bin/true", "--", "probe"],
        vec!["--exec-allow", "probe", "--", "/usr/bin/env", "probe"],
    ] {
        let mut command = tino_command();
        command.env("PATH", &path).args(&args);
        without_capabilities(&mut command);
        let output = command
            .output()
            .expect("run past unreadable PATH candidate");
        assert_eq!(
            output.status.code(),
            Some(37),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    // Explicitly requesting inspection of this file remains an error, proving
    // the permission fixture is effective even when the runner starts as root.
    let mut explicit = tino_command();
    explicit
        .arg("--exec-allow")
        .arg(&unreadable)
        .args(["--", "/bin/true"]);
    without_capabilities(&mut explicit);
    let output = explicit
        .output()
        .expect("probe unreadable explicit allow path");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("for interpreter discovery"));
    std::fs::remove_dir_all(root).expect("remove PATH fixtures");
}

#[test]
fn recursive_env_split_string_reports_an_error_without_aborting() {
    let root = unique_temp_dir("tino-recursive-env-split");
    std::fs::create_dir_all(&root).unwrap();
    let script = root.join("script");
    write_exec_fixture(&script, "#!/usr/bin/env -S ${TINO_SPLIT_LOOP}\n");
    for value in ["-S ${TINO_SPLIT_LOOP}", "--split-string=${TINO_SPLIT_LOOP}"] {
        let mut child = tino_command()
            .env("TINO_SPLIT_LOOP", value)
            .args(["--explain", "--exec-allow"])
            .arg(&script)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let status = wait_child_with_timeout(&mut child, Duration::from_secs(2));
        if status.is_none() {
            let _ = child.kill();
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            status.and_then(|status| status.code()),
            Some(1),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stderr)
                .contains("env split-string expansion exceeds 32 steps")
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_matches_kernel_shebang_argument_truncation() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-shebang-truncate");
    std::fs::create_dir_all(&root).expect("create shebang fixtures");
    let runner = root.join("runner");
    let extra = root.join("runnerX");
    write_exec_fixture(&runner, "#!/bin/sh\nexit 37\n");
    write_exec_fixture(&extra, "#!/bin/sh\nexit 39\n");
    let script = root.join("main");
    let command = extra.to_str().unwrap();
    let prefix = "#!/usr/bin/env -S ";
    let padding = 256usize
        .checked_sub(prefix.len() + command.len())
        .expect("fixture fits shebang buffer");
    write_exec_fixture(
        &script,
        &format!("{prefix}{}{command}\n", " ".repeat(padding)),
    );
    let allowed = root.join("empty");
    std::fs::create_dir(&allowed).unwrap();
    for allow in [None, Some(&allowed), Some(&script)] {
        let mut command = tino_command();
        if let Some(path) = allow {
            command.arg("--exec-allow").arg(path);
        }
        let output = command.arg("--").arg(&script).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(37),
            "allow={allow:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_preserves_env_dash_after_option_terminator() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-env-dash");
    std::fs::create_dir_all(&root).expect("create env dash fixtures");
    let runner = root.join("runner");
    write_exec_fixture(&runner, "#!/bin/sh\nexit 37\n");
    let script = root.join("main");
    write_exec_fixture(
        &script,
        &format!("#!/usr/bin/env -S -- - {}\n", runner.display()),
    );
    for allow in [None, Some("/bin/true"), Some(script.to_str().unwrap())] {
        let mut command = tino_command();
        if let Some(path) = allow {
            command.args(["--exec-allow", path]);
        }
        let output = command
            .arg("--")
            .arg(&script)
            .output()
            .expect("run env dash script");
        assert_eq!(
            output.status.code(),
            Some(37),
            "allow={allow:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(root).expect("remove env dash fixtures");
}

#[test]
fn landlock_exec_preserves_env_single_quote_escapes() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-env-quote");
    std::fs::create_dir_all(&root).expect("create env quote fixtures");
    let script = root.join("main");
    for name in ["runner'quoted", r"runner\slash"] {
        let runner = root.join(name);
        write_exec_fixture(&runner, "#!/bin/sh\nexit 37\n");
        let escaped = runner
            .to_str()
            .expect("runner path")
            .replace('\\', "\\\\")
            .replace('\'', "\\'");
        write_exec_fixture(&script, &format!("#!/usr/bin/env -S '{escaped}'\n"));
        for allow in [None, Some("/bin/true"), Some(script.to_str().unwrap())] {
            let mut command = tino_command();
            if let Some(path) = allow {
                command.args(["--exec-allow", path]);
            }
            let output = command
                .arg("--")
                .arg(&script)
                .output()
                .expect("run escaped env interpreter");
            assert_eq!(
                output.status.code(),
                Some(37),
                "{name:?}, allow={allow:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(root).expect("remove env quote fixtures");
}

#[test]
fn landlock_exec_discovers_env_aliases_with_nested_context() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-env-alias");
    let work = root.join("work");
    std::fs::create_dir_all(&work).expect("create env alias fixtures");
    let alias = root.join("env-link");
    std::os::unix::fs::symlink("/usr/bin/env", &alias).expect("create env alias");
    let main = root.join("main");
    let runner = work.join("runner");
    write_exec_fixture(&work.join("leaf"), "#!/bin/sh\nexit 37\n");
    let allowed = root.join("empty");
    std::fs::create_dir(&allowed).unwrap();
    for (outer, inner) in [
        (
            format!(
                "#!{} -S PATH={} SELECTED=leaf runner\n",
                alias.display(),
                work.display()
            ),
            format!("#!{} -S ${{SELECTED}}\n", alias.display()),
        ),
        (
            "#!./env-link -S -C work PATH=. SELECTED=leaf runner\n".to_owned(),
            "#!../env-link -S ${SELECTED}\n".to_owned(),
        ),
    ] {
        write_exec_fixture(&main, &outer);
        write_exec_fixture(&runner, &inner);
        for allow in [None, Some(&allowed), Some(&main)] {
            let mut command = tino_command();
            command
                .current_dir(&root)
                .env("PATH", "/usr/bin:/bin")
                .env_remove("SELECTED");
            if let Some(path) = allow {
                command.arg("--exec-allow").arg(path);
            }
            let output = command.arg("--").arg(&main).output().unwrap();
            assert_eq!(
                output.status.code(),
                Some(37),
                "outer={outer:?}, inner={inner:?}, allow={allow:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_does_not_treat_an_unrelated_env_name_as_env() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-unrelated-env");
    std::fs::create_dir_all(&root).expect("create unrelated env fixtures");
    let interpreter = root.join("env");
    write_exec_fixture(&interpreter, "#!/bin/sh\nexec \"$TARGET\"\n");
    let helper = root.join("helper");
    std::fs::copy("/bin/false", &helper).expect("copy helper executable");
    let main = root.join("main");
    write_exec_fixture(&main, &format!("#!{} -S helper\n", interpreter.display()));
    let allowed = root.join("empty");
    std::fs::create_dir(&allowed).unwrap();
    for allow in [None, Some(&allowed), Some(&main)] {
        let mut command = tino_command();
        command.env("PATH", &root).env("TARGET", &helper);
        if let Some(path) = allow {
            command.arg("--exec-allow").arg(path);
        }
        let output = command.arg("--").arg(&main).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(if allow.is_none() { 1 } else { 126 }),
            "allow={allow:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_uses_only_the_final_env_chdir_option() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-env-final-chdir");
    let work = root.join("work");
    let blocked = root.join("blocked");
    let allowed = root.join("empty");
    std::fs::create_dir_all(&work).unwrap();
    std::fs::create_dir_all(blocked.join("nested")).unwrap();
    std::fs::create_dir(&allowed).unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();
    write_exec_fixture(&work.join("runner"), "#!/bin/sh\nexit 37\n");
    std::os::unix::fs::symlink("/usr/bin/env", root.join("env-link")).unwrap();
    let main = root.join("main");
    for interpreter in ["/usr/bin/env", "./env-link"] {
        for (options, expected) in [
            ("-C missing -C work", 37),
            ("--chdir=blocked/nested --chdir=work", 37),
            ("-C '' -C work", 37),
            ("-C work -C work", 37),
            ("-C work -C missing", 125),
            ("-C work --chdir=blocked/nested", 125),
            ("-C work -C ''", 125),
        ] {
            write_exec_fixture(&main, &format!("#!{interpreter} -S {options} ./runner\n"));
            for allow in [None, Some(&allowed), Some(&main)] {
                let mut command = tino_command();
                command.current_dir(&root);
                if let Some(path) = allow {
                    command.arg("--exec-allow").arg(path);
                }
                command.arg("--").arg(&main);
                without_capabilities(&mut command);
                let output = command.output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(expected),
                    "interpreter={interpreter}, options={options}, allow={allow:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_ignores_unset_options_when_env_clears_environment() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-env-ignore-unset");
    std::fs::create_dir(&root).unwrap();
    let runner = root.join("runner");
    write_exec_fixture(
        &runner,
        "#!/bin/sh\n[ \"$SELECTED\" = kept ] || exit 38\nexit 37\n",
    );
    let allowed = root.join("empty");
    std::fs::create_dir(&allowed).unwrap();
    std::os::unix::fs::symlink("/usr/bin/env", root.join("env-link")).unwrap();
    let main = root.join("main");
    for interpreter in ["/usr/bin/env", "./env-link"] {
        for (options, expected) in [
            ("-u = -i", 37),
            ("-i -u =", 37),
            ("--unset= --ignore-environment", 37),
            ("-u = -", 37),
            ("-u = -- -", 37),
            ("-u = -S '-i'", 37),
            ("-u SELECTED", 37),
            ("-u =", 125),
            ("--unset=", 125),
        ] {
            write_exec_fixture(
                &main,
                &format!(
                    "#!{interpreter} -S {options} SELECTED=kept {}\n",
                    runner.display()
                ),
            );
            for allow in [None, Some(&allowed), Some(&main)] {
                let mut command = tino_command();
                command.current_dir(&root).env("SELECTED", "inherited");
                if let Some(path) = allow {
                    command.arg("--exec-allow").arg(path);
                }
                let output = command.arg("--").arg(&main).output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(expected),
                    "interpreter={interpreter}, options={options}, allow={allow:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_uses_final_env_signal_dispositions() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-env-signal-options");
    std::fs::create_dir(&root).unwrap();
    let runner = root.join("runner");
    write_exec_fixture(&runner, "#!/bin/sh\nexit 37\n");
    let allowed = root.join("empty");
    std::fs::create_dir(&allowed).unwrap();
    std::os::unix::fs::symlink("/usr/bin/env", root.join("env-link")).unwrap();
    let main = root.join("main");
    let mut cases = vec![
        ("--ignore-signal=KILL --default-signal".to_owned(), 37),
        ("--default-signal=STOP --ignore-signal".to_owned(), 37),
        ("--default-signal --ignore-signal=KILL".to_owned(), 125),
        ("--ignore-signal --default-signal=STOP".to_owned(), 125),
        ("--ignore-signal=KILL --default-signal=TERM".to_owned(), 125),
        ("--ignore-signal=KILL --default-signal=".to_owned(), 125),
        ("--block-signal=KILL --default-signal".to_owned(), 37),
        ("--ignore-signal=0 --default-signal".to_owned(), 125),
        ("--ignore-signal=NOPE --default-signal".to_owned(), 125),
        ("--ignore-signal=999 --default-signal".to_owned(), 125),
    ];
    for signal in [32, 33] {
        cases.extend([
            (format!("--ignore-signal={signal} --default-signal"), 37),
            (format!("--default-signal={signal} --ignore-signal"), 37),
            (format!("--default-signal --ignore-signal={signal}"), 125),
            (format!("--block-signal={signal} --block-signal"), 125),
            (format!("--block-signal={signal} --default-signal"), 125),
        ]);
    }
    for interpreter in ["/usr/bin/env", "./env-link"] {
        for (options, expected) in &cases {
            write_exec_fixture(
                &main,
                &format!("#!{interpreter} -S {options} {}\n", runner.display()),
            );
            for allow in [None, Some(&allowed), Some(&main)] {
                let mut command = tino_command();
                command.current_dir(&root);
                if let Some(path) = allow {
                    command.arg("--exec-allow").arg(path);
                }
                let output = command.arg("--").arg(&main).output().unwrap();
                assert_eq!(
                    output.status.code(),
                    Some(*expected),
                    "interpreter={interpreter}, options={options}, allow={allow:?}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
        }
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn landlock_exec_preserves_nested_env_context() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-nested-env");
    let work = root.join("work");
    let nested = work.join("nested");
    std::fs::create_dir_all(&nested).expect("create nested work dir");
    let start = root.join("start");
    let runner = work.join("runner");
    for path in [work.join("helper"), nested.join("helper")] {
        write_exec_fixture(&path, "#!/bin/sh\nexit 37\n");
    }
    let cases = [
        (
            format!("#!/usr/bin/env -S PATH={} runner\n", work.display()),
            "#!/usr/bin/env helper\n",
        ),
        (
            format!(
                "#!/usr/bin/env -S PATH={} SELECTED=helper runner\n",
                work.display()
            ),
            "#!/usr/bin/env -S ${SELECTED}\n",
        ),
        (
            "#!/usr/bin/env -S -C work ./runner\n".to_owned(),
            "#!./helper\n",
        ),
        (
            "#!/usr/bin/env -S -C work ./runner\n".to_owned(),
            "#!/usr/bin/env -S -C nested ./helper\n",
        ),
        (
            "#!/usr/bin/env -S -C work PATH=. runner\n".to_owned(),
            "#!/usr/bin/env helper\n",
        ),
    ];
    for (outer, inner) in cases {
        write_exec_fixture(&start, &outer);
        write_exec_fixture(&runner, inner);
        for explicit in [
            None,
            Some("/bin/true"),
            Some(start.to_str().expect("fixture path")),
        ] {
            let mut command = tino_command();
            command
                .current_dir(&root)
                .env("PATH", "/usr/bin:/bin")
                .env_remove("SELECTED");
            if let Some(path) = explicit {
                command.args(["--exec-allow", path]);
            }
            let output = command
                .arg("--")
                .arg(&start)
                .output()
                .expect("run nested interpreters");
            assert_eq!(
                output.status.code(),
                Some(37),
                "outer={outer:?}, inner={inner:?}, allow={explicit:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    std::fs::remove_dir_all(root).expect("remove nested env fixtures");
}

#[test]
fn landlock_exec_discovers_shared_interpreter_in_each_environment() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-shared-interpreter");
    let shared = root.join("shared");
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(&first).expect("first env dir");
    std::fs::create_dir_all(&second).expect("second env dir");
    write_exec_fixture(&shared, "#!/usr/bin/env helper\n");
    for (dir, code) in [(&first, 11), (&second, 37)] {
        write_exec_fixture(
            &dir.join("probe"),
            &format!("#!/usr/bin/env -S PATH={} runner\n", dir.display()),
        );
        std::os::unix::fs::symlink(&shared, dir.join("runner")).expect("shared runner symlink");
        write_exec_fixture(&dir.join("helper"), &format!("#!/bin/sh\nexit {code}\n"));
    }
    let output = tino_command()
        .env(
            "PATH",
            std::env::join_paths([&first, &second]).expect("PATH"),
        )
        .args([
            "--exec-allow",
            "probe",
            "--",
            "/bin/sh",
            "-c",
            "exec \"$1\"",
            "sh",
        ])
        .arg(second.join("probe"))
        .output()
        .expect("run second shared interpreter context");
    assert_eq!(
        output.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    std::fs::remove_dir_all(root).expect("remove shared interpreter fixtures");
}

#[test]
fn broken_stderr_logging_does_not_signal_the_managed_command() {
    if !landlock_available() {
        return;
    }
    for verbose in [false, true] {
        let (reader, writer) = std::io::pipe().expect("create broken stderr pipe");
        drop(reader);
        let mut command = tino_command();
        if verbose {
            command.arg("-vv");
        }
        let mut child = command
            .args([
                "--exec-allow",
                "/bin/sleep",
                "--",
                "/bin/sh",
                "-c",
                "sleep 0.2; exit 37",
            ])
            .stdout(Stdio::null())
            .stderr(writer)
            .spawn()
            .expect("spawn broken stderr probe");
        let status = wait_child_with_timeout(&mut child, Duration::from_secs(5));
        if status.is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(37),
            "verbose: {verbose}"
        );
    }
}

#[test]
fn externally_sent_sigpipe_is_forwarded() {
    let mut child = tino_command()
        .args([
            "--",
            "/bin/sh",
            "-c",
            "printf 'ready\\n'; read token; exit 99",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn external SIGPIPE probe");
    let mut stdout = BufReader::new(child.stdout.take().expect("probe stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read readiness marker");
    assert_eq!(line.trim(), "ready");
    // SAFETY: child.id() is the live supervisor PID returned by spawn.
    assert_eq!(
        unsafe { libc::kill(child.id().cast_signed(), libc::SIGPIPE) },
        0
    );
    let status = wait_child_with_timeout(&mut child, Duration::from_secs(2));
    if status.is_none() {
        let _ = child.kill();
        let _ = child.wait();
    }
    assert_eq!(status.and_then(|s| s.code()), Some(128 + libc::SIGPIPE));
}

#[test]
fn shutdown_grace_is_shared_by_main_and_descendant_cleanup() {
    if !python3_available() {
        return;
    }
    let script = r#"import os, signal, time
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    os.write(writer, b'1')
    os.close(writer)
    while True: time.sleep(1)
else:
    os.close(writer)
    os.read(reader, 1)
    os.close(reader)
    def terminate(*_):
        time.sleep(1.3)
        os._exit(37)
    signal.signal(signal.SIGTERM, terminate)
    print(pid, flush=True)
    while True: time.sleep(1)
"#;
    let mut child = tino_command()
        .args([
            "-s",
            "-g",
            "--grace-ms",
            "2000",
            "--",
            "python3",
            "-c",
            script,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn shared grace probe");
    let mut stdout = BufReader::new(child.stdout.take().expect("probe stdout"));
    let mut line = String::new();
    stdout.read_line(&mut line).expect("read grandchild PID");
    let grandchild: libc::pid_t = line.trim().parse().expect("grandchild PID");
    let started = Instant::now();
    // SAFETY: child.id() is the live supervisor PID returned by spawn.
    assert_eq!(
        unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) },
        0
    );
    // A restarted grace period would take at least 3.3 seconds. Allow 0.9
    // seconds for scheduling and reaping beyond the shared 2-second deadline.
    let status = wait_child_with_timeout(&mut child, Duration::from_millis(2900));
    if status.is_none() {
        let _ = unsafe { libc::kill(grandchild, libc::SIGKILL) };
        if wait_child_with_timeout(&mut child, Duration::from_secs(1)).is_none() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    assert_eq!(
        status.and_then(|s| s.code()),
        Some(37),
        "elapsed: {:?}",
        started.elapsed()
    );
    assert!(!process_exists(grandchild), "descendant must be reaped");
}

#[test]
fn signals_during_group_cleanup_preserve_main_exit_and_are_forwarded() {
    if !python3_available() {
        return;
    }
    let script = r#"import os, signal, time
reader, writer = os.pipe()
pid = os.fork()
if pid == 0:
    os.close(reader)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    signal.signal(signal.SIGUSR1, lambda *_: os._exit(0))
    os.write(writer, b'1')
    os.close(writer)
    while True: time.sleep(1)
else:
    os.close(writer)
    os.read(reader, 1)
    os.close(reader)
    print(pid, flush=True)
    os._exit(37)
"#;
    for sig in [libc::SIGTERM, libc::SIGINT, libc::SIGUSR1] {
        let mut child = tino_command()
            .args([
                "-s",
                "-g",
                "-v",
                "--grace-ms",
                "5000",
                "--",
                "python3",
                "-c",
                script,
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn cleanup probe");
        let mut stdout = BufReader::new(child.stdout.take().expect("probe stdout"));
        let mut line = String::new();
        stdout.read_line(&mut line).expect("read grandchild PID");
        let grandchild: libc::pid_t = line.trim().parse().expect("grandchild PID");
        let mut stderr = BufReader::new(child.stderr.take().expect("probe stderr"));
        loop {
            line.clear();
            assert_ne!(stderr.read_line(&mut line).expect("read cleanup log"), 0);
            if line.contains("sending SIGTERM to PGID") {
                break;
            }
        }
        // The log marks entry into cleanup, after the main exit is recorded.
        assert_eq!(unsafe { libc::kill(child.id().cast_signed(), sig) }, 0);
        let status = wait_child_with_timeout(&mut child, Duration::from_secs(2));
        if status.is_none() {
            let _ = child.kill();
            let _ = unsafe { libc::kill(grandchild, libc::SIGKILL) };
            let _ = child.wait();
        }
        assert_eq!(
            status.and_then(|s| s.code()),
            Some(37),
            "cleanup signal {sig}"
        );
        assert!(
            !process_exists(grandchild),
            "cleanup must reap the descendant"
        );
    }
}

fn assert_execvp_shell_fallback_reached(label: &str, status: ExitStatus, stderr: &str) {
    assert!(
        !status.success(),
        "{label} fixture should fail after reaching the shell fallback"
    );
    assert!(
        !stderr.contains("ERROR tino:"),
        "{label} must not fail in the parent process:\n{stderr}"
    );
    assert!(
        !stderr.contains("tino: execvp failed"),
        "Landlock must not deny the {label} shell fallback:\n{stderr}"
    );
}

fn unique_abstract_socket_name(prefix: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{prefix}-{}-{nanos}", std::process::id())
}

fn executable_path(program: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(program);
        let Ok(metadata) = std::fs::metadata(&candidate) else {
            continue;
        };
        if metadata.is_file() && metadata.permissions().mode() & 0o111 != 0 {
            return candidate.canonicalize().ok();
        }
    }
    None
}

fn wait_child_with_timeout(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        if let Some(status) = child.try_wait().expect("poll child status") {
            return Some(status);
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return None;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn process_exists(pid: libc::pid_t) -> bool {
    // SAFETY: signal 0 performs existence/permission checking without delivering a signal.
    let rc = unsafe { libc::kill(pid, 0) };
    if rc == 0 {
        return true;
    }
    let err = std::io::Error::last_os_error();
    err.raw_os_error().is_some_and(|code| code == libc::EPERM)
}

fn wait_for_process_to_exit(pid: libc::pid_t, timeout: Duration) -> bool {
    let deadline = Instant::now().checked_add(timeout);
    loop {
        if !process_exists(pid) {
            return true;
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn parse_pid_and_pgid(output: &[u8]) -> (libc::pid_t, libc::pid_t) {
    let stdout = String::from_utf8_lossy(output);
    let mut fields = stdout.split_whitespace();
    let pid = fields
        .next()
        .expect("pid field")
        .parse::<libc::pid_t>()
        .expect("parse pid field");
    let pgid = fields
        .next()
        .expect("pgid field")
        .parse::<libc::pid_t>()
        .expect("parse pgid field");
    assert!(
        fields.next().is_none(),
        "unexpected extra process group fields: {stdout:?}"
    );
    (pid, pgid)
}

fn spawn_pty_holder() -> Option<(std::process::Child, PathBuf)> {
    if !python3_available() {
        return None;
    }

    let script = r#"import os, pty, time
master, slave = pty.openpty()
print(os.ttyname(slave), flush=True)
time.sleep(5)
"#;
    let mut child = Command::new("python3")
        .args(["-u", "-c", script])
        .stdout(Stdio::piped())
        .spawn()
        .ok()?;
    let mut stdout = BufReader::new(child.stdout.take()?);
    let mut line = String::new();
    stdout.read_line(&mut line).ok()?;
    drop(stdout);
    let path = PathBuf::from(line.trim());
    Some((child, path))
}

#[test]
fn help_flag_prints_usage_and_exits_successfully() {
    let output = tino_command()
        .arg("--help")
        .output()
        .expect("failed to run tino --help");

    assert!(output.status.success(), "help flag exited with failure");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("usage: tino [OPTIONS] [--] CMD [ARGS...]"),
        "unexpected help output\n{}",
        stdout
    );
}

#[test]
fn diagnostic_file_size_limits_preserve_exit_status() {
    use std::os::unix::process::CommandExt;

    let root = unique_temp_dir("tino-diagnostic-file-limit");
    std::fs::create_dir(&root).unwrap();
    let missing = root.join("missing");
    for (args, expected, stdout) in [
        (vec!["--invalid"], 2, false),
        (
            vec![
                "--write-allow",
                missing.to_str().unwrap(),
                "--",
                "/bin/true",
            ],
            1,
            false,
        ),
        (vec!["--help"], 1, true),
        (vec!["--print-config", "--subreaper"], 1, true),
        (vec!["--explain", "--", "/bin/true"], 1, true),
    ] {
        let file = std::fs::File::create(root.join("output")).unwrap();
        let mut command = tino_command();
        command.args(&args);
        if stdout {
            command.stdout(file);
        } else {
            command.stderr(file);
        }
        // SAFETY: only the forked launcher's resource limit changes; no
        // allocation or locking occurs before exec.
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
        let result = command.output().expect("run with diagnostic file limit");
        assert_eq!(result.status.code(), Some(expected), "{args:?}");
    }
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn help_and_version_report_stdout_write_failures() {
    for flag in ["-h", "--help", "-V", "--version"] {
        let full = std::fs::OpenOptions::new()
            .write(true)
            .open("/dev/full")
            .expect("open full output device");
        let output = tino_command()
            .arg(flag)
            .stdout(full)
            .output()
            .expect("run help/version with failing stdout");
        assert_eq!(output.status.code(), Some(1), "{flag}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("write stdout"),
            "{flag}: {:?}",
            output.stderr
        );
    }
}

#[test]
fn version_flag_prints_version_and_exits_successfully() {
    let output = tino_command()
        .arg("--version")
        .output()
        .expect("failed to run tino --version");

    assert!(output.status.success(), "version flag exited with failure");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.starts_with("tino "),
        "unexpected version output\n{}",
        stdout
    );
}

#[test]
fn unknown_argument_exits_with_parse_error() {
    let output = tino_command()
        .arg("--nope")
        .output()
        .expect("failed to run tino with unknown argument");

    assert_eq!(
        output.status.code(),
        Some(2),
        "unexpected exit code for parse failure: {:?}",
        output.status.code()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument"),
        "missing parse error message\n{}",
        stderr
    );
    assert!(
        stderr.contains("usage: tino [OPTIONS] [--] CMD [ARGS...]"),
        "missing usage text in parse failure output\n{}",
        stderr
    );
}

#[test]
fn long_supervision_options_match_short_forms() {
    let run = |args: &[&str]| {
        let output = tino_command().args(args).output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        output.stdout
    };
    assert_eq!(
        run(&["-pTERM", "-vv", "--explain", "--", "/bin/true"]),
        run(&[
            "--parent-death-signal=TERM",
            "--verbose",
            "--verbose",
            "--explain",
            "--",
            "/bin/true"
        ])
    );
    let output = tino_command()
        .args(["--", "/bin/echo", "--parent-death-signal=TERM", "--verbose"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(output.stdout, b"--parent-death-signal=TERM --verbose\n");
}

#[test]
fn usage_errors_return_two_without_running_a_command() {
    for args in [
        vec!["--print-config", "--", "/bin/sh", "-c", "printf unexpected"],
        vec!["--write-config", "--", "/bin/sh", "-c", "printf unexpected"],
        vec!["--explain", "--print-config", "--", "/bin/true"],
        vec!["--write-allow", "relative", "--", "/bin/true"],
        vec!["--expand-env", "--", "/bin/echo", "${UNFINISHED"],
        vec!["--", ""],
    ] {
        let output = tino_command().args(&args).output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stdout.is_empty(), "{args:?}");
    }
}

#[test]
fn operational_failures_and_child_exit_codes_are_preserved() {
    let missing = unique_temp_dir("tino-missing-allow-dir");
    let output = tino_command()
        .arg("--write-allow")
        .arg(&missing)
        .args(["--", "/bin/sh", "-c", "printf unexpected"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    for code in [1, 2, 23] {
        let output = tino_command()
            .args(["--", "/bin/sh", "-c", &format!("exit {code}")])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(code));
        assert!(output.stderr.is_empty());
    }
}

#[test]
fn conflicting_control_modes_exit_with_error() {
    let output = Command::new(tino_bin())
        .args(["--check-config", "--write-config"])
        .output()
        .expect("failed to run tino conflicting control-mode test");

    assert_eq!(output.status.code(), Some(2), "conflicting modes must fail");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--check-config cannot be used with --write-config"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn no_config_check_config_exits_with_error() {
    let output = tino_command()
        .arg("--check-config")
        .output()
        .expect("failed to run tino no-config check-config test");

    assert_eq!(
        output.status.code(),
        Some(2),
        "contradictory config modes must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--no-config cannot be used with --check-config"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn check_config_rejects_inline_runtime_options() {
    for (args, option) in [
        (
            vec!["--check-config", "--write-allow", "/tmp"],
            "--write-allow",
        ),
        (vec!["--check-config", "--grace-ms", "500"], "--grace-ms"),
        (vec!["-t500", "--check-config"], "--grace-ms"),
        (vec!["--check-config", "--verbose"], "--verbose"),
        (
            vec!["--check-config", "--parent-death-signal=TERM"],
            "--parent-death-signal",
        ),
    ] {
        let output = Command::new(tino_bin())
            .args(args)
            .output()
            .expect("failed to run tino check-config inline option test");

        assert_eq!(
            output.status.code(),
            Some(2),
            "check-config with inline runtime option must fail"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(&format!("--check-config does not accept {option}")),
            "unexpected stderr:\n{stderr}"
        );
    }
}

#[test]
fn attached_flag_values_are_rejected_before_running_the_command() {
    for flag in [
        "--no-config=false",
        "--restrict-warn-only=false",
        "--help=false",
    ] {
        let output = tino_command()
            .args([flag, "--", "/bin/sh", "-c", "printf child-was-started"])
            .output()
            .expect("run malformed flag probe");
        assert_eq!(output.status.code(), Some(2), "{flag}");
        assert!(output.stdout.is_empty(), "{flag}");
        assert!(
            String::from_utf8_lossy(&output.stderr).contains("does not take a value"),
            "{flag}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn landlock_path_options_reject_surrounding_whitespace() {
    let output = tino_command()
        .args(["--write-allow", " /tmp", "--explain", "--", "/bin/true"])
        .output()
        .expect("failed to run tino whitespace path option test");

    assert!(
        !output.status.success(),
        "path option with surrounding whitespace must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--write-allow PATH cannot have surrounding whitespace"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn landlock_path_options_reject_relative_allow_paths() {
    let output = tino_command()
        .args(["--write-allow", "logs", "--explain", "--", "/bin/true"])
        .output()
        .expect("failed to run tino relative path option test");

    assert!(
        !output.status.success(),
        "relative write allow path must fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--write-allow PATH must be absolute"),
        "unexpected stderr:\n{stderr}"
    );
}

#[test]
fn missing_command_exits_with_error() {
    let output = tino_command()
        .output()
        .expect("failed to run tino without args");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected exit code 2 when CMD is missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing CMD (use --help)"),
        "missing command error should be captured by the test\n{stderr}"
    );
}

#[test]
fn successful_command_is_quiet_by_default() {
    let output = tino_command()
        .args(["--", "/bin/true"])
        .output()
        .expect("failed to run tino quiet-default test");

    assert!(
        output.status.success(),
        "quiet-default command failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "default successful execution should not emit logs\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn default_run_preserves_parent_process_group() {
    // SAFETY: getpgrp(2) has no preconditions.
    let parent_pgid = unsafe { libc::getpgrp() };
    let output = tino_command()
        .args([
            "--",
            "sh",
            "-c",
            r#"printf '%s %s\n' "$$" "$(cut -d ' ' -f 5 /proc/$$/stat)""#,
        ])
        .output()
        .expect("failed to run tino process-group default test");

    assert!(
        output.status.success(),
        "process-group default test failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let (_, child_pgid) = parse_pid_and_pgid(&output.stdout);
    assert_eq!(
        child_pgid, parent_pgid,
        "default mode should not create a child process group"
    );
}

#[test]
fn pgroup_kill_starts_child_as_process_group_leader() {
    let output = tino_command()
        .args([
            "-g",
            "--",
            "sh",
            "-c",
            r#"printf '%s %s\n' "$$" "$(cut -d ' ' -f 5 /proc/$$/stat)""#,
        ])
        .output()
        .expect("failed to run tino process-group enabled test");

    assert!(
        output.status.success(),
        "process-group enabled test failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let (child_pid, child_pgid) = parse_pid_and_pgid(&output.stdout);
    assert_eq!(
        child_pgid, child_pid,
        "--pgroup-kill should make the child the process-group leader"
    );
}

#[test]
fn invalid_env_default_warning_escapes_control_bytes() {
    let output = tino_command()
        .args(["--", "/bin/true"])
        .env("TINO_SUBREAPER", "\u{1b}[31m")
        .env_remove("TINI_SUBREAPER")
        .output()
        .expect("failed to run tino invalid env default escaping test");

    assert!(
        output.status.success(),
        "invalid env default should not prevent child execution: {:?}",
        output.status.code()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r"\x1b"),
        "expected escaped control byte in invalid env default warning\n{stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "invalid env default warning must not emit raw terminal control bytes\n{stderr}"
    );
}

#[test]
fn invalid_verbosity_warning_escapes_control_bytes() {
    let output = tino_command()
        .args(["--", "/bin/true"])
        .env("TINO_VERBOSITY", "\u{1b}[31m")
        .env_remove("TINI_VERBOSITY")
        .output()
        .expect("failed to run tino invalid verbosity escaping test");

    assert!(
        output.status.success(),
        "invalid verbosity env default should not prevent child execution: {:?}",
        output.status.code()
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r"\x1b"),
        "expected escaped control byte in invalid verbosity warning\n{stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "invalid verbosity warning must not emit raw terminal control bytes\n{stderr}"
    );
}

#[test]
fn verbose_successful_command_reports_exit() {
    let output = tino_command()
        .args(["-v", "--", "/bin/true"])
        .output()
        .expect("failed to run tino verbose exit test");

    assert!(
        output.status.success(),
        "verbose command failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("INFO tino: exiting with 0"),
        "verbose execution should report exit status\n{stderr}"
    );
}

#[test]
fn remap_exit_zeroes_expected_codes() {
    let status = tino_command()
        .args(["-e", "3", "--", "sh", "-c", "exit 3"])
        .status()
        .expect("failed to run tino remap test");

    assert!(
        status.success(),
        "expected tino to map exit code 3 to success, got {:?}",
        status.code()
    );
}

#[test]
fn expand_env_interpolates_child_arguments_without_shell() {
    let output = tino_command()
        .args([
            "--expand-env",
            "--",
            "/bin/echo",
            "-port=${SERVICE_PORT:-8900}",
            "${SERVICE_NAME}",
        ])
        .env_remove("SERVICE_PORT")
        .env("SERVICE_NAME", "collector")
        .output()
        .expect("failed to run tino expand-env test");

    assert!(
        output.status.success(),
        "expand-env scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "-port=8900 collector\n"
    );
}

#[test]
fn expand_env_leaves_unbraced_dollar_names_unchanged() {
    let output = tino_command()
        .args(["--expand-env", "--", "/bin/echo", "$SERVICE_PORT"])
        .env("SERVICE_PORT", "9000")
        .output()
        .expect("failed to run tino unbraced expand-env test");

    assert!(
        output.status.success(),
        "unbraced expand-env scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "$SERVICE_PORT\n");
}

#[test]
fn expand_env_keeps_escaped_dollar_inside_default_literal() {
    let missing = format!(
        "__TINO_TEST_MISSING_LITERAL_DEFAULT_{}__",
        std::process::id()
    );
    let arg = format!("${{{missing}:-x$${{HOME}}y}}");
    let output = tino_command()
        .args(["--expand-env", "--", "/bin/echo"])
        .arg(arg)
        .env_remove(&missing)
        .output()
        .expect("failed to run tino escaped-default expand-env test");

    assert!(
        output.status.success(),
        "escaped-default expand-env scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "x${HOME}y\n");
}

#[test]
fn expand_env_reports_invalid_syntax() {
    let output = tino_command()
        .args(["--expand-env", "--", "/bin/echo", "${SERVICE_PORT"])
        .output()
        .expect("failed to run tino invalid expand-env test");

    assert!(
        !output.status.success(),
        "expected invalid expansion syntax to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("missing closing '}'"),
        "expected missing-brace error\n{stderr}"
    );
}

#[test]
fn expand_env_error_does_not_leak_other_command_args() {
    let secret = "tino-secret-argument-should-not-leak";
    let output = tino_command()
        .args(["--expand-env", "--", "/bin/echo", "${BAD:+value}", secret])
        .output()
        .expect("failed to run tino expand-env secret-leak test");

    assert!(
        !output.status.success(),
        "expected unsupported expansion syntax to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unsupported braced environment expansion"),
        "expected unsupported-expansion error\n{stderr}"
    );
    assert!(
        !stderr.contains(secret),
        "error context must not echo unrelated command arguments\n{stderr}"
    );
}

#[test]
fn expand_env_error_escapes_control_bytes() {
    let output = tino_command()
        .args(["--expand-env", "--", "/bin/echo", "${BAD:\u{1b}}"])
        .output()
        .expect("failed to run tino expand-env escaped-error test");

    assert!(
        !output.status.success(),
        "expected unsupported expansion syntax to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r"\u{1b}"),
        "expected escaped control byte in expansion error\n{stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "expansion error must not emit raw terminal control bytes\n{stderr}"
    );
}

#[test]
fn expand_env_rejects_empty_program_name() {
    let missing = format!("__TINO_TEST_MISSING_PROGRAM_{}__", std::process::id());
    let output = tino_command()
        .args(["--expand-env", "--"])
        .arg(format!("${{{missing}}}"))
        .env_remove(&missing)
        .output()
        .expect("failed to run tino empty-program expand-env test");

    assert!(
        !output.status.success(),
        "expected empty expanded program to fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("command program cannot be empty"),
        "expected empty-program error\n{stderr}"
    );
}

#[test]
fn explain_rejects_empty_program_name() {
    let missing = format!("__TINO_TEST_MISSING_PROGRAM_{}__", std::process::id());
    let output = tino_command()
        .args(["--expand-env", "--explain", "--"])
        .arg(format!("${{{missing}}}"))
        .env_remove(&missing)
        .output()
        .expect("failed to run tino empty-program explain test");

    assert!(
        !output.status.success(),
        "expected explain to reject empty expanded program"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("command program cannot be empty"),
        "expected empty-program error\n{stderr}"
    );
}

#[test]
fn print_config_emits_line_based_config_without_running_child() {
    let root = unique_temp_dir("tino-print-config");
    let allowed_dir = root.join("logs");
    std::fs::create_dir_all(&allowed_dir).expect("create print-config write allow dir");
    let allowed_dir = allowed_dir
        .to_str()
        .expect("print-config write allow dir must be UTF-8");

    let output = tino_command()
        .args([
            "--no-config",
            "--print-config",
            "--expand-env",
            "--write-preset",
            "runtime",
            "--write-allow",
            allowed_dir,
            "--bind-tcp-allow",
            "8900",
            "--exec-allow",
            "/bin/sh",
        ])
        .output()
        .expect("failed to run tino print-config test");

    assert!(
        output.status.success(),
        "print-config failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!(
            concat!(
                "write-allow {}\n",
                "write-preset runtime\n",
                "bind-tcp-allow 8900\n",
                "exec-allow /bin/sh\n",
                "expand-env\n",
            ),
            allowed_dir
        )
    );
}

#[test]
fn print_config_rejects_missing_write_allow_path() {
    let missing = unique_temp_dir("tino-missing-print-config");
    let missing = missing
        .to_str()
        .expect("missing print-config path must be UTF-8");
    let output = tino_command()
        .args(["--print-config", "--write-allow", missing])
        .output()
        .expect("failed to run tino print-config missing-path test");

    assert!(
        !output.status.success(),
        "print-config should reject missing write allow paths"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("open write allow path"),
        "expected write-allow validation error\n{stderr}"
    );
}

#[test]
fn print_config_validates_runtime_options() {
    let missing = format!("__tino_missing_print_config_{}__", std::process::id());
    let output = tino_command()
        .args(["--print-config", "--exec-allow"])
        .arg(missing)
        .output()
        .expect("failed to run tino print-config validation test");

    assert!(
        !output.status.success(),
        "print-config should reject invalid runtime options"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("resolve exec allow path"),
        "expected exec-allow validation error\n{stderr}"
    );
}

#[test]
fn explain_reports_effective_configuration() {
    let root = unique_temp_dir("tino-explain");
    let allowed_dir = root.join("allowed");
    std::fs::create_dir_all(&allowed_dir).expect("create allowed dir");
    let canonical_allowed = allowed_dir
        .canonicalize()
        .expect("canonicalize allowed dir");

    let output = tino_command()
        .args([
            "--expand-env",
            "--write-restrict",
            "--write-allow",
            allowed_dir.to_str().expect("allowed dir utf-8"),
            "--explain",
            "--",
            "/bin/echo",
            "-port=${SERVICE_PORT:-8900}",
        ])
        .env_remove("SERVICE_PORT")
        .env("TINI_SUBREAPER", "1")
        .output()
        .expect("failed to run tino explain test");

    assert!(
        output.status.success(),
        "explain scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("mode: explain"),
        "missing explain header\n{stdout}"
    );
    assert!(
        stdout.contains("subreaper: true"),
        "missing effective subreaper\n{stdout}"
    );
    assert!(
        stdout.contains("subreaper.source: env:TINI_SUBREAPER"),
        "missing subreaper source\n{stdout}"
    );
    assert!(
        stdout.contains(r#"command.effective: ["/bin/echo", "-port=8900"]"#),
        "missing effective command\n{stdout}"
    );
    assert!(
        stdout.contains("write_restrict.enabled: true"),
        "missing write restriction status\n{stdout}"
    );
    assert!(
        stdout.contains("write_restrict.presets: []"),
        "missing preset list\n{stdout}"
    );
    assert!(
        stdout.contains("write_restrict.dev_writable: true"),
        "missing write restriction /dev behavior\n{stdout}"
    );
    assert!(
        stdout.contains(&canonical_allowed.display().to_string()),
        "missing canonical allowlist path\n{stdout}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn explain_reports_native_env_defaults_before_tini_compatibility_defaults() {
    let output = tino_command()
        .args(["--explain", "--", "/bin/true"])
        .env("TINO_SUBREAPER", "1")
        .env("TINI_SUBREAPER", "0")
        .env("TINO_VERBOSITY", "2")
        .env("TINI_VERBOSITY", "3")
        .output()
        .expect("failed to run tino native env explain test");

    assert!(
        output.status.success(),
        "native env explain scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("subreaper.source: env:TINO_SUBREAPER"),
        "missing native subreaper source\n{stdout}"
    );
    assert!(
        stdout.contains("verbosity: 2"),
        "missing native verbosity value\n{stdout}"
    );
    assert!(
        stdout.contains("verbosity.source: env:TINO_VERBOSITY"),
        "missing native verbosity source\n{stdout}"
    );
}

#[test]
fn explain_reports_write_preset_expansion() {
    let output = tino_command()
        .args(["--write-preset", "tmp", "--explain", "--", "/bin/true"])
        .output()
        .expect("failed to run tino explain preset test");

    assert!(
        output.status.success(),
        "explain preset scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(r#"write_restrict.presets: ["tmp"]"#),
        "missing preset list\n{stdout}"
    );
    assert!(
        stdout.contains("/tmp"),
        "missing expanded tmp preset path\n{stdout}"
    );
}

#[test]
fn explain_reports_tcp_restrictions() {
    let output = tino_command()
        .args([
            "--bind-tcp-allow",
            "8900",
            "--connect-tcp-allow",
            "443",
            "--explain",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("failed to run tino explain tcp test");

    assert!(
        output.status.success(),
        "explain TCP scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("tcp_restrict.enabled: true"),
        "missing TCP restriction status\n{stdout}"
    );
    assert!(
        stdout.contains("tcp_restrict.bind_allow_ports: [8900]"),
        "missing bind TCP allowlist\n{stdout}"
    );
    assert!(
        stdout.contains("tcp_restrict.connect_allow_ports: [443]"),
        "missing connect TCP allowlist\n{stdout}"
    );
}

#[test]
fn explain_reports_ipc_scopes() {
    let output = tino_command()
        .args([
            "--scope-signals",
            "--scope-abstract-unix",
            "--explain",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("failed to run tino explain scope test");

    assert!(
        output.status.success(),
        "explain IPC scope scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("ipc_scope.enabled: true"),
        "missing IPC scope status\n{stdout}"
    );
    assert!(
        stdout.contains("ipc_scope.signals: true"),
        "missing signal scope status\n{stdout}"
    );
    assert!(
        stdout.contains("ipc_scope.abstract_unix: true"),
        "missing abstract UNIX scope status\n{stdout}"
    );
}

#[test]
fn explain_reports_exec_restrictions() {
    let sh = executable_path("sh").expect("resolve sh path");
    let output = tino_command()
        .args([
            "--exec-allow",
            sh.to_str().expect("sh path utf-8"),
            "--explain",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("failed to run tino explain exec test");

    assert!(
        output.status.success(),
        "explain exec scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("exec_restrict.enabled: true"),
        "missing exec restriction status\n{stdout}"
    );
    assert!(
        stdout.contains(&sh.display().to_string()),
        "missing configured exec allow path\n{stdout}"
    );
    assert!(
        stdout.contains("/bin/true"),
        "missing auto-allowed main executable path\n{stdout}"
    );
}

#[test]
fn explain_reports_device_ioctl_restrictions() {
    let output = tino_command()
        .args([
            "--device-ioctl-allow",
            "/dev/null",
            "--explain",
            "--",
            "/bin/true",
        ])
        .output()
        .expect("failed to run tino explain device ioctl test");

    assert!(
        output.status.success(),
        "explain device ioctl scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("device_ioctl_restrict.enabled: true"),
        "missing device ioctl restriction status\n{stdout}"
    );
    assert!(
        stdout.contains("/dev/null"),
        "missing configured device ioctl allow path\n{stdout}"
    );
}

#[test]
fn explain_does_not_execute_child() {
    let root = unique_temp_dir("tino-explain-noexec");
    std::fs::create_dir_all(&root).expect("create explain root");
    let marker = root.join("marker");

    let output = tino_command()
        .args(["--explain", "--", "sh", "-c", r#"touch "$MARKER""#])
        .env("MARKER", &marker)
        .output()
        .expect("failed to run tino explain noexec test");

    assert!(
        output.status.success(),
        "explain noexec scenario failed: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !marker.exists(),
        "expected explain mode to avoid executing the child"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn exec_failure_reports_missing_binary_reason() {
    let output = tino_command()
        .args(["--", "/definitely/missing/tino-test-binary"])
        .output()
        .expect("failed to run tino missing-binary test");

    assert!(
        !output.status.success(),
        "expected missing binary execution to fail"
    );
    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("file not found; check the path or PATH lookup"),
        "expected friendly ENOENT hint\n{stderr}"
    );
}

#[test]
fn exec_failure_escapes_control_bytes_in_program_name() {
    let output = tino_command()
        .args(["--", "/definitely/missing/tino-\u{1b}[31m"])
        .output()
        .expect("failed to run tino escaped exec-failure test");

    assert!(
        !output.status.success(),
        "expected missing binary execution to fail"
    );
    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r"\x1b"),
        "expected escaped control byte in exec failure\n{stderr}"
    );
    assert!(
        !stderr.contains('\u{1b}'),
        "exec failure must not emit raw terminal control bytes\n{stderr}"
    );
}

#[test]
fn exec_failure_escapes_quotes_in_program_name() {
    let output = tino_command()
        .args(["--", r#"/definitely/missing/tino-'quote""#])
        .output()
        .expect("failed to run tino quote-escaped exec-failure test");

    assert!(
        !output.status.success(),
        "expected missing binary execution to fail"
    );
    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(r#"tino-\'quote\""#),
        "expected quoted program name to be escaped\n{stderr}"
    );
}

#[test]
fn exec_failure_with_exec_restriction_reports_missing_binary_reason() {
    let output = tino_command()
        .args([
            "--restrict-warn-only",
            "--exec-allow",
            "/bin/sh",
            "--",
            "/definitely/missing/tino-test-binary",
        ])
        .output()
        .expect("failed to run tino missing-binary exec-restrict test");

    assert!(
        !output.status.success(),
        "expected missing binary execution to fail"
    );
    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("file not found; check the path or PATH lookup"),
        "expected friendly ENOENT hint under exec restriction\n{stderr}"
    );
}

#[test]
fn exec_failure_with_exec_restriction_reports_not_directory_reason() {
    let root = unique_temp_dir("tino-exec-restrict-not-dir");
    std::fs::create_dir_all(&root).expect("create exec-restrict not-dir root");
    let file = root.join("file");
    std::fs::write(&file, b"not a directory").expect("write not-dir path component");
    let command = file.join("child");

    let output = tino_command()
        .args(["--restrict-warn-only", "--exec-allow", "/bin/sh", "--"])
        .arg(command.to_str().expect("not-dir command path utf-8"))
        .output()
        .expect("failed to run tino not-directory exec-restrict test");

    assert!(
        !output.status.success(),
        "expected not-directory execution to fail"
    );
    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("a path component is not a directory"),
        "expected friendly ENOTDIR hint under exec restriction\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn exec_failure_reports_non_executable_reason() {
    use std::os::unix::fs::PermissionsExt;

    let root = unique_temp_dir("tino-exec-failure");
    std::fs::create_dir_all(&root).expect("create exec failure root");
    let script = root.join("non-executable.sh");
    std::fs::write(&script, "#!/bin/sh\necho should-not-run\n").expect("write non executable file");
    let mut perms = std::fs::metadata(&script)
        .expect("stat non executable file")
        .permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&script, perms).expect("chmod non executable file");

    let output = tino_command()
        .arg("--")
        .arg(&script)
        .output()
        .expect("failed to run tino non-executable test");

    assert!(
        !output.status.success(),
        "expected non-executable child to fail"
    );
    assert_eq!(output.status.code(), Some(126));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("permission denied or file is not executable"),
        "expected friendly EACCES hint\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn exec_failure_reports_not_directory_as_command_not_found() {
    let root = unique_temp_dir("tino-exec-not-dir");
    std::fs::create_dir_all(&root).expect("create exec not-dir root");
    let file = root.join("file");
    std::fs::write(&file, b"not a directory").expect("write not-dir path component");
    let command = file.join("child");

    let output = tino_command()
        .arg("--")
        .arg(command.to_str().expect("not-dir command path utf-8"))
        .output()
        .expect("failed to run tino not-directory exec test");

    assert!(
        !output.status.success(),
        "expected not-directory execution to fail"
    );
    assert_eq!(output.status.code(), Some(127));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("a path component is not a directory"),
        "expected friendly ENOTDIR hint\n{stderr}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn signal_forwarding_reaches_child() {
    let mut child = tino_command()
        .stdout(Stdio::piped())
        .args([
            "--",
            "sh",
            "-c",
            "trap 'exit 42' TERM; printf 'ready\\n'; while :; do :; done",
        ])
        .spawn()
        .expect("failed to spawn tino signal test");

    let mut stdout = BufReader::new(child.stdout.take().expect("signal test stdout"));
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .expect("read readiness marker for signal test");

    assert_eq!(ready.trim_end(), "ready", "unexpected readiness marker");
    drop(stdout);
    // SAFETY: child.id() is the live child PID returned by std::process::Child.
    let rc = unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
    assert_eq!(
        rc,
        0,
        "failed to send SIGTERM: {}",
        std::io::Error::last_os_error()
    );

    let status = child.wait().expect("failed to wait on tino signal test");
    assert_eq!(
        status.code(),
        Some(42),
        "expected child to receive forwarded SIGTERM"
    );
}

#[test]
fn signal_forwarding_escalates_after_grace_without_process_group() {
    let mut child = tino_command()
        .stdout(Stdio::piped())
        .args([
            "-t",
            "50",
            "--",
            "sh",
            "-c",
            "trap '' TERM; printf 'ready\\n'; while :; do :; done",
        ])
        .spawn()
        .expect("failed to spawn tino single-process grace test");

    let mut stdout = BufReader::new(child.stdout.take().expect("grace test stdout"));
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .expect("read readiness marker for grace test");

    assert_eq!(ready.trim_end(), "ready", "unexpected readiness marker");
    drop(stdout);
    // SAFETY: child.id() is the live child PID returned by std::process::Child.
    let rc = unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
    assert_eq!(
        rc,
        0,
        "failed to send SIGTERM: {}",
        std::io::Error::last_os_error()
    );

    let status = child.wait().expect("failed to wait on tino grace test");
    assert_eq!(
        status.code(),
        Some(137),
        "expected non-pgroup child to be escalated to SIGKILL"
    );
}

#[test]
fn pdeath_signal_is_configured_for_execed_child() {
    if !python3_available() {
        return;
    }

    let script = r#"import ctypes, signal, sys
libc = ctypes.CDLL(None)
value = ctypes.c_int()
if libc.prctl(2, ctypes.byref(value), 0, 0, 0) != 0:
    sys.exit(100)
sys.exit(0 if value.value == signal.SIGUSR1 else 101)
"#;

    for option in ["-p", "--parent-death-signal"] {
        let status = tino_command()
            .args([option, "USR1", "--", "python3", "-c", script])
            .status()
            .expect("failed to run tino pdeath test");
        assert!(
            status.success(),
            "expected execed child to inherit configured PDEATHSIG, got {status:?}"
        );
    }
}

#[test]
fn signal_forwarding_preserves_unlisted_linux_signals() {
    let signal = libc::SIGXCPU;
    let mut child = tino_command()
        .stdout(Stdio::piped())
        .args([
            "--",
            "sh",
            "-c",
            "trap 'exit 45' \"$SIGNAL\"; printf 'ready\\n'; while true; do sleep 1; done",
        ])
        .env("SIGNAL", signal.to_string())
        .spawn()
        .expect("failed to spawn tino unlisted signal test");

    let mut stdout = BufReader::new(child.stdout.take().expect("unlisted signal test stdout"));
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .expect("read readiness marker for unlisted signal test");

    assert_eq!(ready.trim_end(), "ready", "unexpected readiness marker");
    drop(stdout);
    // SAFETY: child.id() is the live child PID returned by std::process::Child.
    let rc = unsafe { libc::kill(child.id().cast_signed(), signal) };
    assert_eq!(
        rc,
        0,
        "failed to send unlisted signal: {}",
        std::io::Error::last_os_error()
    );

    let status = wait_child_with_timeout(&mut child, Duration::from_secs(2)).unwrap_or_else(|| {
        let _ = child.kill();
        let _ = child.wait();
        panic!("timed out waiting for unlisted signal forwarding test");
    });
    assert_eq!(
        status.code(),
        Some(45),
        "expected child to receive forwarded unlisted signal"
    );
}

#[test]
fn warn_on_reap_emits_warning() {
    let output = tino_command()
        .args(["-w", "--", "sh", "-c", "(sleep 0.1 &) && exit 0"])
        .output()
        .expect("failed to run tino warning test");

    assert!(
        output.status.success(),
        "warn-on-reap scenario failed: {:?}",
        output.status.code()
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("reaped secondary PID"),
        "expected warning about secondary PID\n{stderr}"
    );
}

#[test]
fn pgroup_kill_escalates_after_grace() {
    let mut child = tino_command()
        .stdout(Stdio::piped())
        .args([
            "-g",
            "-t",
            "50",
            "--",
            "sh",
            "-c",
            "trap '' TERM; printf 'ready\\n'; while true; do sleep 1; done",
        ])
        .spawn()
        .expect("failed to spawn tino pgroup test");

    let mut stdout = BufReader::new(child.stdout.take().expect("pgroup test stdout"));
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .expect("read readiness marker for pgroup test");
    assert_eq!(ready.trim_end(), "ready", "unexpected readiness marker");
    drop(stdout);
    // SAFETY: child.id() is the live child PID returned by std::process::Child.
    let rc = unsafe { libc::kill(child.id().cast_signed(), libc::SIGTERM) };
    assert_eq!(
        rc,
        0,
        "failed to send SIGTERM: {}",
        std::io::Error::last_os_error()
    );

    let status = child.wait().expect("failed to wait on tino pgroup test");
    assert_eq!(
        status.code(),
        Some(137),
        "expected escalation to SIGKILL reflected in exit code"
    );
}

#[test]
fn pgroup_kill_escalates_unwaitable_group_members_after_main_exit() {
    let root = unique_temp_dir("tino-pgroup-unwaitable");
    std::fs::create_dir_all(&root).expect("create pgroup test root");
    let pid_file = root.join("grandchild.pid");

    let status = tino_command()
        .args([
            "-g",
            "-t",
            "50",
            "--",
            "sh",
            "-c",
            r#"trap '' TERM; while true; do sleep 1; done & printf '%s\n' "$!" > "$PID_FILE"; exit 0"#,
        ])
        .env("PID_FILE", &pid_file)
        .status()
        .expect("failed to run tino pgroup unwaitable-member test");

    assert!(
        status.success(),
        "main process exit should still determine tino status, got {status:?}"
    );

    let pid = std::fs::read_to_string(&pid_file)
        .expect("read grandchild pid")
        .trim()
        .parse::<libc::pid_t>()
        .expect("parse grandchild pid");
    let exited = wait_for_process_to_exit(pid, Duration::from_secs(2));
    if !exited {
        // SAFETY: pid comes from the child process we just spawned; cleanup is best-effort.
        let _ = unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert!(
        exited,
        "process group member that ignored SIGTERM should be SIGKILLed"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn landlock_allows_writes_within_allowlist() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-landlock-allow");
    let allowed_dir = root.join("allowed");
    std::fs::create_dir_all(&allowed_dir).expect("create allowed dir");

    let status = tino_command()
        .args([
            "--write-restrict",
            "--write-allow",
            allowed_dir.to_str().expect("allowed dir utf-8"),
            "--",
            "sh",
            "-c",
            r#"set -e; echo ok > "$ALLOWED/ok""#,
        ])
        .env("ALLOWED", &allowed_dir)
        .status()
        .expect("run tino landlock allow test");

    assert!(
        status.success(),
        "expected write within allowlist to succeed"
    );
    assert!(
        allowed_dir.join("ok").exists(),
        "expected allowlisted file to be created"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn write_allow_enables_write_restriction() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-write-allow-enables");
    let allowed_dir = root.join("allowed");
    let outside_dir = root.join("outside");
    std::fs::create_dir_all(&allowed_dir).expect("create allowed dir");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");

    let status = tino_command()
        .args([
            "--write-allow",
            allowed_dir.to_str().expect("allowed dir utf-8"),
            "--",
            "sh",
            "-c",
            r#"set -e; echo ok > "$ALLOWED/ok"; if (echo denied > "$OUTSIDE/deny") 2>/dev/null; then exit 0; else exit 13; fi"#,
        ])
        .env("ALLOWED", &allowed_dir)
        .env("OUTSIDE", &outside_dir)
        .status()
        .expect("run tino write-allow auto restriction test");

    assert!(
        !status.success(),
        "expected --write-allow alone to restrict other writes, got {status:?}"
    );
    assert!(
        allowed_dir.join("ok").exists(),
        "expected allowlisted file to be created"
    );
    assert!(
        !outside_dir.join("deny").exists(),
        "expected file outside allowlist to be denied"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn write_preset_tmp_allows_writes_in_tmp() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-write-preset-tmp");
    std::fs::create_dir_all(&root).expect("create tmp preset root");

    let status = tino_command()
        .args([
            "--write-preset",
            "tmp",
            "--",
            "sh",
            "-c",
            r#"set -e; echo ok > "$TARGET/ok""#,
        ])
        .env("TARGET", &root)
        .status()
        .expect("run tino write preset tmp test");

    assert!(
        status.success(),
        "expected tmp preset to allow writes under /tmp"
    );
    assert!(
        root.join("ok").exists(),
        "expected tmp preset file to be created"
    );

    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn landlock_allows_bind_only_on_allowlisted_tcp_ports() {
    if !landlock_available() || !landlock_tcp_available() || !python3_available() {
        return;
    }

    let (allowed_port, denied_port) = distinct_free_tcp_ports();
    let bind_script = r#"import socket, sys
s = socket.socket()
s.bind(("127.0.0.1", int(sys.argv[1])))
s.close()
"#;
    let bind_denied_script = r#"import socket, sys
s = socket.socket()
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except PermissionError:
    sys.exit(13)
else:
    s.close()
    sys.exit(0)
"#;

    let allowed = tino_command()
        .args([
            "--bind-tcp-allow",
            &allowed_port.to_string(),
            "--",
            "python3",
            "-c",
            bind_script,
            &allowed_port.to_string(),
        ])
        .status()
        .expect("run tino bind TCP allow test");
    assert!(
        allowed.success(),
        "expected allowlisted TCP bind to succeed, got {allowed:?}"
    );

    let denied = tino_command()
        .args([
            "--bind-tcp-allow",
            &allowed_port.to_string(),
            "--",
            "python3",
            "-c",
            bind_denied_script,
            &denied_port.to_string(),
        ])
        .status()
        .expect("run tino bind TCP deny test");
    assert!(
        !denied.success(),
        "expected non-allowlisted TCP bind to fail, got {denied:?}"
    );
}

#[test]
fn landlock_allows_connect_only_on_allowlisted_tcp_ports() {
    if !landlock_available() || !landlock_tcp_available() || !python3_available() {
        return;
    }

    let allowed_listener =
        TcpListener::bind(("127.0.0.1", 0)).expect("bind allowlisted TCP listener");
    let denied_listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind denied TCP listener");
    let allowed_port = allowed_listener
        .local_addr()
        .expect("query allowlisted TCP listener addr")
        .port();
    let denied_port = denied_listener
        .local_addr()
        .expect("query denied TCP listener addr")
        .port();
    let connect_script = r#"import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
s.close()
"#;
    let connect_denied_script = r#"import socket, sys
try:
    s = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
except PermissionError:
    sys.exit(13)
else:
    s.close()
    sys.exit(0)
"#;

    let allowed = tino_command()
        .args([
            "--connect-tcp-allow",
            &allowed_port.to_string(),
            "--",
            "python3",
            "-c",
            connect_script,
            &allowed_port.to_string(),
        ])
        .status()
        .expect("run tino connect TCP allow test");
    assert!(
        allowed.success(),
        "expected allowlisted TCP connect to succeed, got {allowed:?}"
    );

    let denied = tino_command()
        .args([
            "--connect-tcp-allow",
            &allowed_port.to_string(),
            "--",
            "python3",
            "-c",
            connect_denied_script,
            &denied_port.to_string(),
        ])
        .status()
        .expect("run tino connect TCP deny test");
    assert!(
        !denied.success(),
        "expected non-allowlisted TCP connect to fail, got {denied:?}"
    );

    drop(allowed_listener);
    drop(denied_listener);
}

#[test]
fn landlock_exec_restrict_auto_allows_main_command() {
    if !landlock_available() {
        return;
    }

    let status = tino_command()
        .args(["--exec-allow", "/bin/sh", "--", "/bin/true"])
        .status()
        .expect("run tino exec auto-allow test");

    assert!(
        status.success(),
        "expected exec restriction to auto-allow main command, got {status:?}"
    );
}

#[test]
fn landlock_exec_restrict_auto_allows_env_shebang_command() {
    if !landlock_available() {
        return;
    }

    let env = executable_path("env");
    let sh = executable_path("sh");
    let (Some(env), Some(_sh)) = (env, sh) else {
        return;
    };

    let root = unique_temp_dir("tino-env-shebang");
    std::fs::create_dir_all(&root).expect("create env shebang dir");
    let script = root.join("script");
    std::fs::write(
        &script,
        format!("#!{} sh\nexit 0\n", env.display()).as_bytes(),
    )
    .expect("write env shebang script");
    let mut perms = std::fs::metadata(&script)
        .expect("stat env shebang script")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(&script, perms).expect("chmod env shebang script");

    let status = tino_command()
        .args([
            "--exec-allow",
            script.to_str().expect("script path utf-8"),
            "--",
            script.to_str().expect("script path utf-8"),
        ])
        .status()
        .expect("run tino env shebang exec test");

    assert!(
        status.success(),
        "expected env shebang script to succeed under exec restriction, got {status:?}"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_preserves_path_fallbacks() {
    if !landlock_available() {
        return;
    }
    let root = unique_temp_dir("tino-exec-path-fallback");
    let first = root.join("first");
    let second = root.join("second");
    std::fs::create_dir_all(&first).expect("create first PATH directory");
    std::fs::create_dir_all(&second).expect("create second PATH directory");
    let broken = first.join("probe");
    let working = second.join("probe");
    std::fs::write(
        &broken,
        format!("#!{}\n", root.join("missing-interpreter").display()),
    )
    .expect("write broken PATH candidate");
    std::fs::write(&working, "#!/bin/sh\nexit 37\n").expect("write working PATH candidate");
    for file in [&broken, &working] {
        std::fs::set_permissions(file, std::fs::Permissions::from_mode(0o755))
            .expect("chmod candidate");
    }
    let path = std::env::join_paths([&first, &second]).expect("build PATH");
    for args in [
        vec!["--", "probe"],
        vec!["--exec-allow", "/bin/true", "--", "probe"],
        vec!["--exec-allow", "probe", "--", "/usr/bin/env", "probe"],
    ] {
        let output = tino_command()
            .env("PATH", &path)
            .args(&args)
            .output()
            .expect("run PATH fallback");
        assert_eq!(
            output.status.code(),
            Some(37),
            "{args:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Only the owner permission class applies to an unprivileged file owner.
    // Other-user execute bits must not make this unreadable file stop lookup.
    if unsafe { libc::geteuid() } != 0 {
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o041))
            .expect("make first candidate inaccessible to its owner");
        let output = tino_command()
            .env("PATH", &path)
            .args(["--exec-allow", "/bin/true", "--", "probe"])
            .output()
            .expect("run past inaccessible PATH candidate");
        assert_eq!(
            output.status.code(),
            Some(37),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::set_permissions(&broken, std::fs::Permissions::from_mode(0o755))
            .expect("restore missing-interpreter fixture");
    }

    let script = root.join("env-script");
    std::fs::write(
        &script,
        format!("#!/usr/bin/env -S PATH={} probe\n", path.to_string_lossy()),
    )
    .expect("write env PATH script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755))
        .expect("chmod env script");
    let output = tino_command()
        .arg("--exec-allow")
        .arg(&script)
        .arg("--")
        .arg(&script)
        .output()
        .expect("run env PATH fallback");
    assert_eq!(
        output.status.code(),
        Some(37),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let unrelated = second.join("unrelated");
    std::fs::write(&unrelated, "#!/bin/sh\nexit 77\n").expect("write unrelated program");
    std::fs::set_permissions(&unrelated, std::fs::Permissions::from_mode(0o755))
        .expect("chmod unrelated program");
    let output = tino_command()
        .env("PATH", &path)
        .args([
            "--exec-allow",
            "probe",
            "--",
            "/bin/sh",
            "-c",
            "exec \"$1\"",
            "sh",
        ])
        .arg(&unrelated)
        .output()
        .expect("run unlisted program");
    assert_eq!(
        output.status.code(),
        Some(126),
        "PATH fallback must not allow whole directories"
    );
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_auto_allows_relative_shebang_interpreter_from_cwd() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-relative-shebang");
    std::fs::create_dir_all(&root).expect("create relative shebang dir");
    let interpreter = root.join("interp");
    let script = root.join("script");
    std::fs::write(&interpreter, b"#!/bin/sh\nexec /bin/sh \"$@\"\n")
        .expect("write relative shebang interpreter");
    std::fs::write(&script, b"#!interp\necho relative-shebang-ok\n")
        .expect("write relative shebang script");
    for path in [&interpreter, &script] {
        let mut perms = std::fs::metadata(path)
            .expect("stat relative shebang file")
            .permissions();
        perms.set_mode(perms.mode() | 0o755);
        std::fs::set_permissions(path, perms).expect("chmod relative shebang file");
    }

    let output = tino_command()
        .current_dir(&root)
        .args([
            "--exec-allow",
            script.to_str().expect("script path utf-8"),
            "--",
            script.to_str().expect("script path utf-8"),
        ])
        .output()
        .expect("run tino relative shebang exec test");

    assert!(
        output.status.success(),
        "expected relative shebang to succeed under exec restriction: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        "relative-shebang-ok\n"
    );

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_auto_allows_execvp_shell_fallback() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-execvp-shell-fallback");
    std::fs::create_dir_all(&root).expect("create execvp fallback dir");
    let script = root.join("script");
    std::fs::write(&script, b"echo no-shebang-ok\n").expect("write no-shebang script");
    let mut perms = std::fs::metadata(&script)
        .expect("stat no-shebang script")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(&script, perms).expect("chmod no-shebang script");

    let output = tino_command()
        .args([
            "--exec-allow",
            script.to_str().expect("script path utf-8"),
            "--",
            script.to_str().expect("script path utf-8"),
        ])
        .output()
        .expect("run tino execvp fallback exec test");

    assert!(
        output.status.success(),
        "expected no-shebang script to succeed under exec restriction: {:?}\nstderr:\n{}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&output.stdout), "no-shebang-ok\n");

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_auto_allows_execvp_shell_for_malformed_elf() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-malformed-elf-shell-fallback");
    std::fs::create_dir_all(&root).expect("create malformed ELF fallback dir");
    let program = root.join("badelf");
    std::fs::write(&program, b"\x7FELFnot really elf\n").expect("write malformed ELF");
    let mut perms = std::fs::metadata(&program)
        .expect("stat malformed ELF")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(&program, perms).expect("chmod malformed ELF");

    let output = tino_command()
        .args([
            "--exec-allow",
            program.to_str().expect("malformed ELF path utf-8"),
            "--",
            program.to_str().expect("malformed ELF path utf-8"),
        ])
        .output()
        .expect("run tino malformed ELF fallback exec test");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_execvp_shell_fallback_reached("malformed ELF", output.status, &stderr);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_auto_allows_execvp_shell_for_invalid_static_elf() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-invalid-static-elf-shell-fallback");
    std::fs::create_dir_all(&root).expect("create invalid static ELF fallback dir");
    let program = root.join("badelf");
    let mut bytes = vec![0u8; 120];
    bytes[0..4].copy_from_slice(b"\x7FELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    std::fs::write(&program, bytes).expect("write invalid static ELF");
    let mut perms = std::fs::metadata(&program)
        .expect("stat invalid static ELF")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(&program, perms).expect("chmod invalid static ELF");

    let output = tino_command()
        .args([
            "--exec-allow",
            program.to_str().expect("invalid static ELF path utf-8"),
            "--",
            program.to_str().expect("invalid static ELF path utf-8"),
        ])
        .output()
        .expect("run tino invalid static ELF fallback exec test");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_execvp_shell_fallback_reached("invalid static ELF", output.status, &stderr);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_auto_allows_execvp_shell_for_non_native_elf() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-non-native-elf-shell-fallback");
    std::fs::create_dir_all(&root).expect("create non-native ELF fallback dir");
    let program = root.join("badelf");
    let mut bytes = vec![0u8; 120];
    bytes[0..4].copy_from_slice(b"\x7FELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[18..20].copy_from_slice(&0u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&64u64.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    bytes[64..68].copy_from_slice(&1u32.to_le_bytes());
    bytes[64 + 32..64 + 40].copy_from_slice(&1u64.to_le_bytes());
    std::fs::write(&program, bytes).expect("write non-native ELF");
    let mut perms = std::fs::metadata(&program)
        .expect("stat non-native ELF")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(&program, perms).expect("chmod non-native ELF");

    let output = tino_command()
        .args([
            "--exec-allow",
            program.to_str().expect("non-native ELF path utf-8"),
            "--",
            program.to_str().expect("non-native ELF path utf-8"),
        ])
        .output()
        .expect("run tino non-native ELF fallback exec test");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_execvp_shell_fallback_reached("non-native ELF", output.status, &stderr);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_auto_allows_execvp_shell_for_invalid_elf_program_headers() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-invalid-elf-phoff-shell-fallback");
    std::fs::create_dir_all(&root).expect("create invalid phoff ELF fallback dir");
    let program = root.join("badelf");
    let mut bytes = vec![0u8; 64];
    bytes[0..4].copy_from_slice(b"\x7FELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    bytes[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes[54..56].copy_from_slice(&56u16.to_le_bytes());
    bytes[56..58].copy_from_slice(&1u16.to_le_bytes());
    std::fs::write(&program, bytes).expect("write invalid phoff ELF");
    let mut perms = std::fs::metadata(&program)
        .expect("stat invalid phoff ELF")
        .permissions();
    perms.set_mode(perms.mode() | 0o755);
    std::fs::set_permissions(&program, perms).expect("chmod invalid phoff ELF");

    let output = tino_command()
        .args([
            "--exec-allow",
            program.to_str().expect("invalid phoff ELF path utf-8"),
            "--",
            program.to_str().expect("invalid phoff ELF path utf-8"),
        ])
        .output()
        .expect("run tino invalid phoff ELF fallback exec test");
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_execvp_shell_fallback_reached("invalid ELF program headers", output.status, &stderr);

    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn landlock_exec_restrict_blocks_non_allowlisted_execs() {
    if !landlock_available() {
        return;
    }

    let sh = executable_path("sh");
    let uname = executable_path("uname");
    let (Some(sh), Some(uname)) = (sh, uname) else {
        return;
    };

    let status = tino_command()
        .args([
            "--exec-allow",
            sh.to_str().expect("sh path utf-8"),
            "--",
            sh.to_str().expect("sh path utf-8"),
            "-c",
            r#""$UNAME" >/dev/null 2>/dev/null"#,
        ])
        .env("UNAME", &uname)
        .status()
        .expect("run tino exec deny test");

    assert!(
        !status.success(),
        "expected non-allowlisted exec to fail, got {status:?}"
    );
}

#[test]
fn landlock_exec_restrict_allows_configured_execs() {
    if !landlock_available() {
        return;
    }

    let sh = executable_path("sh");
    let uname = executable_path("uname");
    let (Some(sh), Some(uname)) = (sh, uname) else {
        return;
    };

    let status = tino_command()
        .args([
            "--exec-allow",
            sh.to_str().expect("sh path utf-8"),
            "--exec-allow",
            uname.to_str().expect("uname path utf-8"),
            "--",
            sh.to_str().expect("sh path utf-8"),
            "-c",
            r#""$UNAME" >/dev/null"#,
        ])
        .env("UNAME", &uname)
        .status()
        .expect("run tino exec allow test");

    assert!(
        status.success(),
        "expected configured exec to succeed, got {status:?}"
    );
}

#[test]
fn landlock_device_ioctl_restrict_allows_configured_paths() {
    if !landlock_available() || !python3_available() {
        return;
    }

    let Some((mut holder, tty_path)) = spawn_pty_holder() else {
        return;
    };
    let script = r#"import fcntl, os, sys, termios
fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOCTTY)
fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
os.close(fd)
"#;

    let status = tino_command()
        .args([
            "--device-ioctl-allow",
            tty_path.to_str().expect("tty path utf-8"),
            "--",
            "python3",
            "-c",
            script,
            tty_path.to_str().expect("tty path utf-8"),
        ])
        .status()
        .expect("run tino device ioctl allow test");

    let _ = holder.kill();
    let _ = holder.wait();

    assert!(
        status.success(),
        "expected configured device ioctl path to succeed, got {status:?}"
    );
}

#[test]
fn landlock_device_ioctl_restrict_blocks_non_allowlisted_paths() {
    if !landlock_available() || !python3_available() {
        return;
    }

    let Some((mut holder, tty_path)) = spawn_pty_holder() else {
        return;
    };
    let script = r#"import fcntl, os, sys, termios
try:
    fd = os.open(sys.argv[1], os.O_RDONLY | os.O_NOCTTY)
    try:
        fcntl.ioctl(fd, termios.TIOCGWINSZ, b"\0" * 8)
    finally:
        os.close(fd)
except PermissionError:
    sys.exit(13)
else:
    sys.exit(0)
"#;

    let status = tino_command()
        .args([
            "--device-ioctl-allow",
            "/dev/null",
            "--",
            "python3",
            "-c",
            script,
            tty_path.to_str().expect("tty path utf-8"),
        ])
        .status()
        .expect("run tino device ioctl deny test");

    let _ = holder.kill();
    let _ = holder.wait();

    assert!(
        !status.success(),
        "expected non-allowlisted device ioctl to fail, got {status:?}"
    );
}

#[test]
fn landlock_signal_scope_allows_same_domain_signals() {
    if !landlock_available() || !landlock_scope_available() {
        return;
    }

    let status = tino_command()
        .args([
            "--scope-signals",
            "--",
            "sh",
            "-c",
            r#"sleep 10 & pid=$!; kill -TERM "$pid"; wait "$pid"; code=$?; test "$code" -eq 143"#,
        ])
        .status()
        .expect("run tino same-domain signal scope test");

    assert!(
        status.success(),
        "expected same-domain signal delivery to succeed, got {status:?}"
    );
}

#[test]
fn landlock_signal_scope_blocks_out_of_domain_signals() {
    if !landlock_available() || !landlock_scope_available() {
        return;
    }

    let mut target = Command::new("sh")
        .stdout(Stdio::piped())
        .args([
            "-c",
            "trap 'exit 0' TERM; printf 'ready\\n'; while true; do sleep 1; done",
        ])
        .spawn()
        .expect("spawn out-of-domain signal target");
    let mut stdout = BufReader::new(target.stdout.take().expect("signal scope target stdout"));
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .expect("read readiness marker for signal scope target");
    assert_eq!(ready.trim_end(), "ready", "unexpected readiness marker");
    drop(stdout);

    let status = tino_command()
        .args([
            "--scope-signals",
            "--",
            "sh",
            "-c",
            r#"kill -TERM "$TARGET_PID" 2>/dev/null || exit 13"#,
        ])
        .env("TARGET_PID", target.id().to_string())
        .status()
        .expect("run tino out-of-domain signal scope test");

    assert!(
        !status.success(),
        "expected out-of-domain signal delivery to fail, got {status:?}"
    );
    assert!(
        target
            .try_wait()
            .expect("poll signal scope target")
            .is_none(),
        "expected out-of-domain target to remain alive"
    );

    // SAFETY: target.id() is the live child PID returned by std::process::Child.
    let rc = unsafe { libc::kill(target.id().cast_signed(), libc::SIGTERM) };
    assert_eq!(
        rc,
        0,
        "terminate signal scope target: {}",
        std::io::Error::last_os_error()
    );
    let cleanup = target.wait().expect("wait for signal scope target");
    assert!(
        cleanup.success(),
        "signal scope target cleanup failed: {cleanup:?}"
    );
}

#[test]
fn landlock_abstract_unix_scope_allows_same_domain_connects() {
    if !landlock_available() || !landlock_scope_available() || !python3_available() {
        return;
    }

    let script = r#"import socket, threading, uuid
name = "\0" + "tino-scope-" + uuid.uuid4().hex
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(name)
server.listen(1)
accepted = []

def accept_once():
    conn, _ = server.accept()
    conn.close()
    accepted.append(True)

thread = threading.Thread(target=accept_once)
thread.start()
client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
client.connect(name)
client.close()
thread.join(timeout=2)
assert accepted, "same-domain abstract UNIX socket connect should succeed"
server.close()
"#;

    let status = tino_command()
        .args(["--scope-abstract-unix", "--", "python3", "-c", script])
        .status()
        .expect("run tino same-domain abstract UNIX scope test");

    assert!(
        status.success(),
        "expected same-domain abstract UNIX connect to succeed, got {status:?}"
    );
}

#[test]
fn landlock_abstract_unix_scope_blocks_out_of_domain_connects() {
    if !landlock_available() || !landlock_scope_available() || !python3_available() {
        return;
    }

    let socket_name = unique_abstract_socket_name("tino-abstract-scope");
    let server_script = r#"import socket, sys, time
name = "\0" + sys.argv[1]
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(name)
sock.listen(1)
print("ready", flush=True)
time.sleep(5)
sock.close()
"#;
    let connect_script = r#"import socket, sys
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
try:
    sock.connect("\0" + sys.argv[1])
except PermissionError:
    sys.exit(13)
else:
    sock.close()
    sys.exit(0)
"#;

    let mut server = Command::new("python3")
        .args(["-u", "-c", server_script, &socket_name])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn abstract UNIX scope server");
    let mut stdout = BufReader::new(
        server
            .stdout
            .take()
            .expect("abstract UNIX scope server stdout"),
    );
    let mut ready = String::new();
    stdout
        .read_line(&mut ready)
        .expect("read readiness marker for abstract UNIX scope server");
    assert_eq!(ready.trim_end(), "ready", "unexpected readiness marker");
    drop(stdout);

    let status = tino_command()
        .args([
            "--scope-abstract-unix",
            "--",
            "python3",
            "-c",
            connect_script,
            &socket_name,
        ])
        .status()
        .expect("run tino out-of-domain abstract UNIX scope test");

    assert!(
        !status.success(),
        "expected out-of-domain abstract UNIX connect to fail, got {status:?}"
    );

    let _ = server.kill();
    let _ = server.wait();
}

#[test]
fn landlock_denies_writes_outside_allowlist() {
    if !landlock_available() {
        return;
    }

    let root = unique_temp_dir("tino-landlock-deny");
    let allowed_dir = root.join("allowed");
    let outside_dir = root.join("outside");
    std::fs::create_dir_all(&allowed_dir).expect("create allowed dir");
    std::fs::create_dir_all(&outside_dir).expect("create outside dir");

    let status = tino_command()
        .args([
            "--write-restrict",
            "--write-allow",
            allowed_dir.to_str().expect("allowed dir utf-8"),
            "--",
            "sh",
            "-c",
            r#"set -e; echo ok > "$ALLOWED/ok"; if (echo denied > "$OUTSIDE/deny") 2>/dev/null; then exit 0; else exit 13; fi"#,
        ])
        .env("ALLOWED", &allowed_dir)
        .env("OUTSIDE", &outside_dir)
        .status()
        .expect("run tino landlock deny test");

    assert!(
        !status.success(),
        "expected write outside allowlist to fail, got {status:?}"
    );
    assert!(
        allowed_dir.join("ok").exists(),
        "expected allowlisted file to be created"
    );
    assert!(
        !outside_dir.join("deny").exists(),
        "expected file outside allowlist to be denied"
    );

    let _ = std::fs::remove_dir_all(&root);
}
