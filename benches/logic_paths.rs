use std::hint::black_box;
use std::time::{Duration, Instant};

const MIN_SAMPLE_TIME: Duration = Duration::from_millis(200);
const MAX_ITERS: u64 = 1 << 32;

fn main() {
    bench_expand_command_args();

    cfg_select! {
        target_os = "linux" => {
            bench_parse_shebang_interpreter();
            bench_parse_elf_interpreter();
        }
        _ => {}
    }
}

fn bench_expand_command_args() {
    let cmd = vec![
        "/opt/app/service".to_string(),
        r"--port=${SERVICE_PORT:-8900}".to_string(),
        r"--listen=${LISTEN_HOST:-127.0.0.1}".to_string(),
        r"--node=${APP_HOME:-/opt/app}/node-${SERVICE_PORT:-8900}".to_string(),
        r"--meta=$${literal}-${REGION:-${ZONE:-default}}".to_string(),
        r"--labels=${LABELS:-team=infra,role=service,env=prod}".to_string(),
    ];

    bench("resolve_command_args_expand_env", || {
        tino::bench_support::resolve_command_args(black_box(&cmd), true)
            .expect("expand env benchmark should succeed")
    });
}

cfg_select! {
    target_os = "linux" => {
        fn bench_parse_shebang_interpreter() {
            let script = br#"#!/usr/bin/env -S python3 -u
print("hello")
"#;

            bench("parse_shebang_interpreter", || {
                tino::bench_support::parse_shebang_interpreter(black_box(script))
            });
        }

        fn bench_parse_elf_interpreter() {
            let executable = std::env::current_exe().expect("locate benchmark executable");
            let elf = std::fs::read(executable).expect("read native ELF executable");

            bench("parse_elf_interpreter", || {
                tino::bench_support::parse_elf_interpreter(black_box(&elf))
                    .expect("parse native ELF executable")
            });
        }
    }
    _ => {}
}

fn bench<T>(name: &str, mut f: impl FnMut() -> T) {
    let mut iters = 1u64;

    loop {
        let started = Instant::now();
        for _ in 0..iters {
            black_box(f());
        }
        let elapsed = started.elapsed();
        if elapsed >= MIN_SAMPLE_TIME || iters >= MAX_ITERS {
            report(name, iters, elapsed);
            break;
        }
        iters = iters.saturating_mul(2).min(MAX_ITERS);
    }
}

fn report(name: &str, iters: u64, elapsed: Duration) {
    let nanos_per_iter = elapsed.as_nanos() / u128::from(iters);
    println!("{name}: {nanos_per_iter} ns/iter ({iters} iterations in {elapsed:.3?})");
}
