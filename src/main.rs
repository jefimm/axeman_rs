use std::process::ExitCode;

use clap::Parser;

use axeman_rs::*;

mod ct_log;
mod merkle_tree;

fn main() -> ExitCode {
    env_logger::init();
    let args = Cli::parse();
    if args.list_mode {
        handle_list_mode();
    } else {
        if !handle_download(&args) {
            return ExitCode::FAILURE;
        };
    }
    ExitCode::SUCCESS
}
