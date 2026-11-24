use std::cell::Cell;
use std::fmt;
#[cfg(target_os = "linux")]
use std::fmt::Write as _;
#[cfg(not(target_os = "linux"))]
use std::io::{self, Write};
use std::mem::DropGuard;

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum Level {
    Warn,
    Info,
    Debug,
}

impl Level {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Warn => "WARN",
            Self::Info => "INFO",
            Self::Debug => "DEBUG",
        }
    }
}

thread_local! {
    static MAX_LEVEL: Cell<Level> = const { Cell::new(Level::Warn) };
}

pub(crate) fn with_verbosity<T>(verbosity: u8, run: impl FnOnce() -> T) -> T {
    let level = match verbosity {
        0 => Level::Warn,
        1 => Level::Info,
        _ => Level::Debug,
    };
    let _restore = DropGuard::new(MAX_LEVEL.replace(level), |previous| MAX_LEVEL.set(previous));
    run()
}

pub(crate) fn debug_enabled() -> bool {
    enabled(Level::Debug)
}

pub(crate) fn warn(args: fmt::Arguments<'_>) {
    log(Level::Warn, args);
}

pub(crate) fn info(args: fmt::Arguments<'_>) {
    log(Level::Info, args);
}

pub(crate) fn debug(args: fmt::Arguments<'_>) {
    log(Level::Debug, args);
}

fn enabled(level: Level) -> bool {
    level <= MAX_LEVEL.get()
}

fn log(level: Level, args: fmt::Arguments<'_>) {
    if enabled(level) {
        stderr_line(format_args!("{} tino: {args}", level.as_str()));
    }
}

pub(crate) fn stderr_line(args: fmt::Arguments<'_>) {
    #[cfg(target_os = "linux")]
    let Some(mut stderr) = crate::platform::unix::sys::DiagnosticWriter::stderr() else {
        return;
    };
    #[cfg(not(target_os = "linux"))]
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{args}");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn failed_explain_restores_log_verbosity_for_the_next_call() {
        let cli = crate::Cli::try_parse_from(["tino", "-vv", "--explain", "--", ""]).unwrap();
        assert_eq!(crate::run(cli).unwrap_err().exit_code(), 2);
        assert!(!debug_enabled());
    }

    #[test]
    fn verbose_calls_do_not_enable_debug_on_other_threads() {
        with_verbosity(2, || {
            assert!(debug_enabled());
            assert!(!std::thread::spawn(debug_enabled).join().unwrap());
        });
    }

    #[test]
    fn verbosity_maps_to_expected_levels() {
        assert!(!enabled(Level::Info));
        assert!(!debug_enabled());

        with_verbosity(1, || {
            assert!(enabled(Level::Info));
            assert!(!debug_enabled());
        });
        assert!(!enabled(Level::Info));
    }
}
