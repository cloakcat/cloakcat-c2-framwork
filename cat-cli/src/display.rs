//! Rich terminal output — colors, tables, relative timestamps.

use chrono::{DateTime, Local, Utc};
use colored::Colorize;
use comfy_table::{Attribute, Cell, Color, ContentArrangement, Table};

use crate::types::{AgentInfo, AuditEntry, ResultItem};

const TRUNCATE_LINES: usize = 20;

// ── Helpers ────────────────────────────────────────────────────────────────

pub fn separator() -> String {
    "─".repeat(60).dimmed().to_string()
}

fn short_id(id: &str) -> &str {
    if id.len() > 8 { &id[..8] } else { id }
}

fn relative_time(rfc: &str) -> String {
    let dt = match DateTime::parse_from_rfc3339(rfc) {
        Ok(dt) => dt.with_timezone(&Utc),
        Err(_) => return rfc.to_string(),
    };
    let secs = Utc::now().signed_duration_since(dt).num_seconds();
    if secs < 0 {
        return "future".to_string();
    }
    if secs < 60 {
        format!("{}s ago", secs)
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86400)
    }
}

fn ts_ms_to_local(ts_ms: i64) -> String {
    match DateTime::from_timestamp_millis(ts_ms) {
        Some(dt) => dt.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "-".to_string(),
    }
}

fn exit_badge(code: i64) -> String {
    if code == 0 {
        "[OK]".green().bold().to_string()
    } else {
        format!("[ERR {}]", code).red().bold().to_string()
    }
}

fn action_colored(action: &str) -> String {
    match action {
        "create" | "register" => action.green().to_string(),
        "delete" | "kill" | "cleanup" => action.red().to_string(),
        "update" | "alias" | "tag" => action.yellow().to_string(),
        _ => action.cyan().to_string(),
    }
}

// ── Agent status ───────────────────────────────────────────────────────────

pub fn compute_status(agent: &AgentInfo) -> &'static str {
    let last = match &agent.last_seen_at {
        Some(s) => match DateTime::parse_from_rfc3339(s).map(|dt| dt.with_timezone(&Utc)) {
            Ok(dt) => dt,
            Err(_) => return "unknown",
        },
        None => return "never",
    };
    let delta_ms = (Utc::now() - last).num_milliseconds();
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

// ── Agents table ───────────────────────────────────────────────────────────

pub fn print_agents_table(agents: &[AgentInfo], show_tags: bool) {
    if agents.is_empty() {
        println!("{}", "no agents registered".dimmed());
        return;
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);

    let mut headers: Vec<Cell> = vec![
        Cell::new("id").add_attribute(Attribute::Bold),
        Cell::new("alias").add_attribute(Attribute::Bold),
        Cell::new("platform").add_attribute(Attribute::Bold),
        Cell::new("status").add_attribute(Attribute::Bold),
        Cell::new("hostname").add_attribute(Attribute::Bold),
        Cell::new("username").add_attribute(Attribute::Bold),
        Cell::new("last_seen").add_attribute(Attribute::Bold),
        Cell::new("beacon").add_attribute(Attribute::Bold),
    ];
    if show_tags {
        headers.push(Cell::new("tags").add_attribute(Attribute::Bold));
    }
    headers.push(Cell::new("note").add_attribute(Attribute::Bold));
    table.set_header(headers);

    for agent in agents {
        let status = compute_status(agent);
        let status_cell = match status {
            "online" => Cell::new(status).fg(Color::Green),
            "unstable" => Cell::new(status).fg(Color::Yellow),
            _ => Cell::new(status).fg(Color::Red),
        };
        let last_seen = agent
            .last_seen_at
            .as_deref()
            .map(relative_time)
            .unwrap_or_else(|| "-".to_string());
        let beacon = match (agent.beacon_min_ms, agent.beacon_max_ms) {
            (Some(min), Some(max)) => format!("{}/{}", min, max),
            (Some(min), None) => format!("{}/-", min),
            (None, Some(max)) => format!("-/{}", max),
            _ => "-".to_string(),
        };

        let mut row: Vec<Cell> = vec![
            Cell::new(short_id(&agent.agent_id)).fg(Color::Cyan),
            Cell::new(agent.alias.as_deref().unwrap_or("-")),
            Cell::new(&agent.platform),
            status_cell,
            Cell::new(agent.hostname.as_deref().unwrap_or("-")),
            Cell::new(agent.username.as_deref().unwrap_or("-")),
            Cell::new(last_seen).add_attribute(Attribute::Dim),
            Cell::new(beacon),
        ];
        if show_tags {
            let tags = if agent.tags.is_empty() {
                "-".to_string()
            } else {
                agent.tags.join(", ")
            };
            row.push(Cell::new(tags));
        }
        row.push(Cell::new(agent.note.as_deref().unwrap_or("-")));
        table.add_row(row);
    }

    println!("{table}");
}

// ── Results ────────────────────────────────────────────────────────────────

pub fn print_results(items: &[ResultItem], full: bool) {
    if items.is_empty() {
        println!("{}", "no results found".dimmed());
        return;
    }
    for item in items {
        println!(
            "{} {} {}",
            exit_badge(item.exit_code),
            short_id(&item.cmd_id).cyan(),
            ts_ms_to_local(item.ts_ms).dimmed()
        );
        let stdout_lines: Vec<&str> = item.stdout.lines().collect();
        if !stdout_lines.is_empty() {
            if !full && stdout_lines.len() > TRUNCATE_LINES {
                for line in &stdout_lines[..TRUNCATE_LINES] {
                    println!("  {line}");
                }
                let extra = stdout_lines.len() - TRUNCATE_LINES;
                println!(
                    "  {}",
                    format!("… (+{} lines, --full로 전체 출력)", extra).dimmed()
                );
            } else {
                for line in &stdout_lines {
                    println!("  {line}");
                }
            }
        }
        if !item.stderr.is_empty() {
            for line in item.stderr.lines() {
                println!("  {}", line.red());
            }
        }
        println!("{}", separator());
    }
}

// ── History timeline ───────────────────────────────────────────────────────

pub fn print_history_timeline(items: &[ResultItem]) {
    if items.is_empty() {
        println!("{}", "no history".dimmed());
        return;
    }
    for item in items {
        println!(
            "{} {} {}",
            ts_ms_to_local(item.ts_ms).dimmed(),
            short_id(&item.cmd_id).cyan(),
            exit_badge(item.exit_code)
        );
        let stdout_first = item.stdout.lines().next().unwrap_or("").chars().take(80).collect::<String>();
        let stderr_first = item.stderr.lines().next().unwrap_or("").chars().take(80).collect::<String>();
        if !stdout_first.is_empty() {
            println!("  {stdout_first}");
        }
        if !stderr_first.is_empty() {
            println!("  {}", stderr_first.red());
        }
    }
}

// ── Audit ──────────────────────────────────────────────────────────────────

pub fn print_audit_entries(items: &[AuditEntry]) {
    if items.is_empty() {
        println!("{}", "no audit entries".dimmed());
        return;
    }
    for item in items {
        let mut ctx_str = serde_json::to_string(&item.context).unwrap_or_default();
        if ctx_str.len() > 120 {
            ctx_str.truncate(120);
            ctx_str.push_str("...");
        }
        println!(
            "{} {} {} {}:{}",
            item.ts.dimmed(),
            item.actor.bold(),
            action_colored(&item.action),
            item.target_type,
            short_id(&item.target_id).cyan()
        );
        if !ctx_str.is_empty() && ctx_str != "null" {
            println!("  {}", ctx_str.dimmed());
        }
    }
}

// ── Misc ───────────────────────────────────────────────────────────────────

pub fn print_success(msg: &str) {
    println!("{} {}", "✓".green(), msg);
}

pub fn print_dispatch(tag: &str, agent_id: &str, cmd: &str) {
    println!(
        "{} {} → {}",
        format!("[{}]", tag).cyan(),
        agent_id.dimmed(),
        cmd
    );
}

pub fn print_tail_header(agent: &str) {
    println!(
        "following results for {} (Ctrl+C to stop)…",
        agent.cyan()
    );
}

pub fn print_tail_item(cmd_id: &str, exit: i64, stdout: &str) {
    println!();
    println!("{} {}", exit_badge(exit), short_id(cmd_id).cyan());
    for line in stdout.lines() {
        println!("  {line}");
    }
    println!("{}", separator());
}

pub fn print_stopped() {
    println!("{}", "(stopped)".dimmed());
}
