use crate::diagnostic::escape_str;
#[cfg(target_os = "linux")]
use crate::platform::unix::sys::Signal;

pub(crate) struct ParentDeathSignal {
    pub(crate) name: &'static str,
    #[cfg(target_os = "linux")]
    pub(crate) number: Signal,
}

macro_rules! parent_death_signals {
    ($($signal:ident),+ $(,)?) => {
        &[$(ParentDeathSignal {
            name: stringify!($signal),
            #[cfg(target_os = "linux")]
            number: Signal::$signal,
        }),+]
    };
}

const PARENT_DEATH_SIGNALS: &[ParentDeathSignal] = parent_death_signals![
    SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT, SIGBUS, SIGFPE, SIGKILL, SIGUSR1, SIGSEGV,
    SIGUSR2, SIGPIPE, SIGALRM, SIGTERM, SIGCONT, SIGWINCH, SIGTSTP, SIGTTIN, SIGTTOU,
];

pub(crate) fn strip_sig_prefix(raw: &str) -> &str {
    match raw.split_at_checked(3) {
        Some((prefix, name)) if prefix.eq_ignore_ascii_case("SIG") => name,
        _ => raw,
    }
}

impl ParentDeathSignal {
    fn short_name(&self) -> &'static str {
        &self.name[3..]
    }

    pub(crate) fn parse(raw: &str) -> Result<&'static Self, String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err("signal name cannot be empty".into());
        }
        let name = strip_sig_prefix(trimmed);
        PARENT_DEATH_SIGNALS
            .iter()
            .find(|signal| signal.short_name().eq_ignore_ascii_case(name))
            .ok_or_else(|| {
                let supported = PARENT_DEATH_SIGNALS
                    .iter()
                    .map(Self::short_name)
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(
                    "invalid signal '{}'; supported values: {supported}",
                    escape_str(raw)
                )
            })
    }
}
