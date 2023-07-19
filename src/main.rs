use clap::Parser;

use axeman_rs::*;

fn main() -> anyhow::Result<()> {
    env_logger::init();
    let args = Cli::parse();
    handle_download(&args)
}
