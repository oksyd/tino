use super::LandlockExplain;
use crate::{Result, bail, cli::Cli};

pub(super) fn run_impl(_cli: Cli) -> Result<i32> {
    linux_required()
}

pub(super) fn explain_config(_cli: &Cli) -> Result<(Vec<String>, LandlockExplain)> {
    linux_required()
}

pub(super) fn validate_landlock_config(_cli: &Cli) -> Result<()> {
    linux_required()
}

fn linux_required<T>() -> Result<T> {
    bail!(
        "tino supports Linux targets only. Build and test inside a Linux container or VM \
         (see README requirements)."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cli() -> Cli {
        Cli {
            cmd: vec!["/bin/true".into()],
            ..Cli::default()
        }
    }

    #[test]
    fn stub_reports_linux_requirement() {
        let cli = base_cli();
        let err = run_impl(cli).unwrap_err();
        let message = format!("{err}");
        assert!(
            message.contains("supports Linux targets"),
            "unexpected stub message: {message}"
        );
    }
}
