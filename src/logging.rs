use std::fmt;
#[cfg(target_os = "linux")]
use std::fmt::Write as _;
#[cfg(not(target_os = "linux"))]
use std::io::{self, Write};
use std::sync::atomic::{AtomicU8, Ordering};

#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
enum Level {
    Warn = 1,
    Info = 2,
    Debug = 3,
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

static MAX_LEVEL: AtomicU8 = AtomicU8::new(Level::Warn as u8);

pub(crate) fn init(verbosity: u8) {
    let level = match verbosity {
        0 => Level::Warn,
        1 => Level::Info,
        _ => Level::Debug,
    };
    MAX_LEVEL.store(level as u8, Ordering::Relaxed);
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
    (level as u8) <= MAX_LEVEL.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn reset_for_test() {
    init(0);
}

#[cfg(test)]
pub(crate) fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    use std::sync::{Mutex, OnceLock};

    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .expect("logging test lock poisoned")
}

fn log(level: Level, args: fmt::Arguments<'_>) {
    if !enabled(level) {
        return;
    }

    #[cfg(target_os = "linux")]
    let Some(mut stderr) = crate::platform::unix::sys::DiagnosticWriter::stderr() else {
        return;
    };
    #[cfg(not(target_os = "linux"))]
    let mut stderr = io::stderr().lock();
    let _ = writeln!(stderr, "{} tino: {}", level.as_str(), args);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_maps_verbosity_to_expected_levels() {
        let _lock = test_lock();

        reset_for_test();
        assert!(!enabled(Level::Info));
        assert!(!debug_enabled());

        init(1);
        assert!(enabled(Level::Info));
        assert!(!debug_enabled());

        init(2);
        assert!(enabled(Level::Info));
        assert!(debug_enabled());

        reset_for_test();
    }
}
