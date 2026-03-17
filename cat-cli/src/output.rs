//! Output formatting and display.

use std::io::IsTerminal;

use chrono::{DateTime, Utc};

use crate::types::{AgentInfo, AuditEntry, ResultItem};

pub fn print_json(s: String) {
    match serde_json::from_str::<serde_json::Value>(&s) {
        Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap()),
        Err(_) => println!("{s}"),
    }
}

pub fn compute_status(agent: &AgentInfo) -> &'static str {
    let last = match &agent.last_seen_at {
        Some(s) => match DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc)) {
            Ok(dt) => dt,
            Err(_) => return "unknown",
        },
        None => return "never",
    };

    let now = Utc::now();
    let delta_ms = (now - last).num_milliseconds();
    if delta_ms < 0 {
        return "unknown";
    }
    let beacon_ms = agent.beacon_max_ms.unwrap_or(10_000);
    let backoff_ms = agent.backoff_max_ms.unwrap_or(60_000);

    if delta_ms <= 2 * beacon_ms {
        "online"
    } else if delta_ms <= backoff_ms {
        "unstable"
    } else {
        "offline"
    }
}

pub fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        let mut t = s[..max_len].to_string();
        t.push('…');
        t
    }
}

pub fn print_agents(s: &str) -> anyhow::Result<()> {
    let agents: Vec<AgentInfo> = serde_json::from_str(s)?;

    println!(
        "{:<10}  {:<12}  {:<8}  {:<12}  {:<9}  {:<18}  {:<18}  {:<12}  {:<12}  {}",
        "agent_id",
        "alias",
        "platform",
        "profile",
        "status",
        "hostname",
        "username",
        "last_seen",
        "beacon",
        "note"
    );
    for item in agents {
        let beacon_ms = match (item.beacon_min_ms, item.beacon_max_ms) {
            (Some(min), Some(max)) => format!("{}/{}", min, max),
            (Some(min), None) => format!("{}/-", min),
            (None, Some(max)) => format!("-/{}", max),
            _ => "-".to_string(),
        };
        let status = compute_status(&item);
        let short_id = if item.agent_id.len() > 10 {
            &item.agent_id[..10]
        } else {
            &item.agent_id
        };
        let hostname = item
            .hostname
            .as_deref()
            .map(|s| truncate_str(s, 18))
            .unwrap_or_else(|| "-".to_string());
        let username = item
            .username
            .as_deref()
            .map(|s| truncate_str(s, 18))
            .unwrap_or_else(|| "-".to_string());
        let note = item.note.as_deref().unwrap_or("-");
        println!(
            "{:<10}  {:<12}  {:<8}  {:<12}  {:<9}  {:<18}  {:<18}  {:<12}  {:<12}  {} | {} | {}",
            short_id,
            item.alias.as_deref().unwrap_or("-"),
            item.platform,
            item.profile_name.as_deref().unwrap_or("-"),
            status,
            hostname,
            username,
            item.last_seen_at.as_deref().unwrap_or("-"),
            beacon_ms,
            note,
            item.os_version
                .as_deref()
                .map(|s| truncate_str(s, 24))
                .unwrap_or_else(|| "-".to_string()),
            item.ip_addrs
                .as_deref()
                .map(|s| truncate_str(s, 24))
                .unwrap_or_else(|| "-".to_string())
        );
    }

    Ok(())
}

pub fn print_agents_with_tags(list: Vec<AgentInfo>) {
    println!(
        "{:<10}  {:<12}  {:<8}  {:<12}  {:<9}  {:<18}  {:<18}  {:<12}  {:<12}  {:<16}  {}",
        "agent_id",
        "alias",
        "platform",
        "profile",
        "status",
        "hostname",
        "username",
        "last_seen",
        "beacon",
        "tags",
        "note"
    );
    for item in list {
        let beacon_ms = match (item.beacon_min_ms, item.beacon_max_ms) {
            (Some(min), Some(max)) => format!("{}/{}", min, max),
            (Some(min), None) => format!("{}/-", min),
            (None, Some(max)) => format!("-/{}", max),
            _ => "-".to_string(),
        };
        let status = compute_status(&item);
        let short_id = if item.agent_id.len() > 10 {
            &item.agent_id[..10]
        } else {
            &item.agent_id
        };
        let hostname = item
            .hostname
            .as_deref()
            .map(|s| truncate_str(s, 18))
            .unwrap_or_else(|| "-".to_string());
        let username = item
            .username
            .as_deref()
            .map(|s| truncate_str(s, 18))
            .unwrap_or_else(|| "-".to_string());
        let note = item.note.as_deref().unwrap_or("-");
        let tags = if item.tags.is_empty() {
            "-".to_string()
        } else {
            truncate_str(&item.tags.join(","), 16)
        };
        println!(
            "{:<10}  {:<12}  {:<8}  {:<12}  {:<9}  {:<18}  {:<18}  {:<12}  {:<12}  {:<16}  {}",
            short_id,
            item.alias.as_deref().unwrap_or("-"),
            item.platform,
            item.profile_name.as_deref().unwrap_or("-"),
            status,
            hostname,
            username,
            item.last_seen_at.as_deref().unwrap_or("-"),
            beacon_ms,
            tags,
            note,
        );
    }
}

pub fn print_history(s: &str) -> anyhow::Result<()> {
    let items: Vec<ResultItem> = serde_json::from_str(s)?;
    for item in items {
        let ts = item.created_at.as_deref().unwrap_or("");
        let stdout_first = item
            .stdout
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();
        let stderr_first = item
            .stderr
            .lines()
            .next()
            .unwrap_or("")
            .chars()
            .take(80)
            .collect::<String>();
        println!("[{}] cmd={} exit={}", ts, item.cmd_id, item.exit_code);
        if !stdout_first.is_empty() {
            println!("stdout: {}", stdout_first);
        }
        if !stderr_first.is_empty() {
            println!("stderr: {}", stderr_first);
        }
    }
    Ok(())
}

pub fn print_audit(s: &str) -> anyhow::Result<()> {
    let items: Vec<AuditEntry> = serde_json::from_str(s)?;
    for item in items {
        let mut ctx_str = serde_json::to_string(&item.context)?;
        if ctx_str.len() > 120 {
            ctx_str.truncate(120);
            ctx_str.push_str("...");
        }
        println!(
            "[{}] actor={} action={} target={}:{}",
            item.ts, item.actor, item.action, item.target_type, item.target_id
        );
        if !ctx_str.is_empty() {
            println!("ctx: {}", ctx_str);
        }
    }
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
