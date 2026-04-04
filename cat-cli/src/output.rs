//! Output formatting and display.

use std::io::IsTerminal;

use crate::types::{AgentInfo, AuditEntry, ResultItem};

pub fn print_json(s: String) {
    match serde_json::from_str::<serde_json::Value>(&s) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(_) => println!("{s}"),
    }
}

pub fn print_agents(s: &str) -> anyhow::Result<()> {
    let agents: Vec<AgentInfo> = serde_json::from_str(s)?;
    crate::display::print_agents_table(&agents, false);
    Ok(())
}

pub fn print_agents_with_tags(list: Vec<AgentInfo>) {
    crate::display::print_agents_table(&list, true);
}

pub fn print_history(s: &str) -> anyhow::Result<()> {
    let items: Vec<ResultItem> = serde_json::from_str(s)?;
    crate::display::print_history_timeline(&items);
    Ok(())
}

pub fn print_audit(s: &str) -> anyhow::Result<()> {
    let items: Vec<AuditEntry> = serde_json::from_str(s)?;
    crate::display::print_audit_entries(&items);
    Ok(())
}

pub fn print_banner(version: &str) {
    let art = r#"
     /\_/\   CloakCat C2
    ( o.o )  Stealthy C2 Framework
     > ^ <   🐾  Command. Control. Vanish.
    "#;

    if colors_enabled() {
        println!(
            "\x1b[95m{}\x1b[0m\x1b[90mversion {}\x1b[0m",
            art.trim_end(),
            version
        );
    } else {
        println!("{}\nversion {}", art.trim_end(), version);
    }
}

fn colors_enabled() -> bool {
    std::env::var_os("NO_COLOR").is_none() && std::io::stdout().is_terminal()
}
