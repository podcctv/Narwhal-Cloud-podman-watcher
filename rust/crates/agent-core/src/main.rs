#![forbid(unsafe_code)]

use std::io;
use std::process;
use std::sync::atomic::AtomicBool;

use agent_core::{run_with_config, AgentState, Config, ConfigError};

fn print_usage() {
    println!(
        "narwhal-agent [--server URL] [--secret SECRET] [--interval SECS] [--host-id ID] [--node-id ID] [--once] [--dry-run] [--check-config]"
    );
}

fn main() {
    let config = match Config::from_env_and_args() {
        Ok(cfg) => cfg,
        Err(ConfigError::HelpRequested) => {
            print_usage();
            process::exit(0);
        }
        Err(err) => {
            eprintln!("narwhal-agent: {err}");
            process::exit(2);
        }
    };

    let mut state = AgentState::new(&config);
    let stop = AtomicBool::new(false);
    let stdout = io::stdout();
    let mut handle = stdout.lock();

    match run_with_config(&config, &mut state, &mut handle, &stop) {
        Ok(code) => process::exit(code),
        Err(err) => {
            eprintln!("narwhal-agent: {err}");
            process::exit(1);
        }
    }
}
