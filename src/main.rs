#![deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use tino::{Cli, run};

fn main() {
    let cli = Cli::parse();

    std::process::exit(run(cli).unwrap_or_else(|err| err.exit()));
}
