#![cfg(target_os = "linux")]

use std::fs;
use std::process::Command;

fn tino_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tino")
}

fn readme() -> String {
    fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).expect("read README.md")
}

#[test]
fn readme_contains_core_install_and_usage_snippets() {
    let readme = readme();

    for snippet in [
        "COPY --from=ghcr.io/oksyd/tino:latest /sbin/tino /sbin/tino",
        "ENTRYPOINT [\"/sbin/tino\", \"-g\", \"-s\", \"--\"]",
        "tino --expand-env -- /opt/app/service '--port=${SERVICE_PORT:-8900}'",
        "--write-preset runtime",
        "--write-allow /data/logs",
        "--bind-tcp-allow 8900",
        "--exec-allow /opt/app/service",
        "referenced files and directories already exist",
        "`--write-allow` and `--write-preset` enable write restriction automatically",
        "--security-opt seccomp=./seccomp-landlock.json",
    ] {
        assert!(
            readme.contains(snippet),
            "README is missing documented snippet: {snippet}"
        );
    }
}

#[test]
fn readme_and_help_stay_aligned_on_key_flags() {
    let readme = readme();
    let output = Command::new(tino_bin())
        .arg("--help")
        .output()
        .expect("run tino --help");
    assert!(output.status.success(), "--help exited with failure");
    let help = String::from_utf8_lossy(&output.stdout);

    for flag in [
        "--verbose",
        "--write-restrict",
        "--write-allow",
        "--write-preset",
        "--restrict-warn-only",
        "--bind-tcp-allow",
        "--connect-tcp-allow",
        "--scope-signals",
        "--scope-abstract-unix",
        "--exec-allow",
        "--device-ioctl-allow",
        "--expand-env",
        "--print-config",
        "--write-config",
        "--check-config",
        "--no-config",
        "--explain",
    ] {
        assert!(
            readme.contains(flag),
            "README is missing documented flag: {flag}"
        );
        assert!(help.contains(flag), "--help is missing flag: {flag}");
    }

    assert!(
        help.contains("Warn and continue when access restriction fails"),
        "--help should describe --restrict-warn-only as applying to all access restrictions"
    );
    assert!(
        help.contains("Allow writes to PATH; enables restriction"),
        "--help should document that --write-allow enables write restriction"
    );
    assert!(
        help.contains("Allow tmp/runtime writes; enables restriction"),
        "--help should document that --write-preset enables write restriction"
    );
}
