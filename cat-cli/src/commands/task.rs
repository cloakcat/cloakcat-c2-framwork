//! Task/result commands: results, history, audit, tail.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use anyhow::{anyhow, Result};

use crate::display;
use crate::http::resolve_agent_identifier;
use crate::output::{print_audit, print_history};
use crate::types::ResultItem;

use super::CliCtx;

pub fn cmd_results(ctx: &CliCtx, agent: &str, limit: usize, full: bool) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let res = ctx
        .cli
        .get(format!(
            "{}/v1/admin/results?agent_id={}&limit={}",
            ctx.base, agent_id, limit
        ))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!("results fetch failed: status={} body={}", status, text));
    }
    let items: Vec<ResultItem> = serde_json::from_str(&text)?;
    display::print_results(&items, full);
    Ok(())
}

pub fn cmd_history(ctx: &CliCtx, agent: &str, limit: usize) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let res = ctx
        .cli
        .get(format!(
            "{}/v1/admin/results?agent_id={}&limit={}",
            ctx.base, agent_id, limit
        ))
        .send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!(
            "history fetch failed: status={} body={}",
            status,
            text
        ));
    }
    print_history(&text)?;
    Ok(())
}

pub fn cmd_audit(
    ctx: &CliCtx,
    limit: i64,
    actor: Option<&str>,
    agent: Option<&str>,
) -> Result<()> {
    let agent_resolved = if let Some(a) = agent {
        Some(resolve_agent_identifier(ctx.cli, ctx.base, a)?)
    } else {
        None
    };

    let mut qs: Vec<String> = vec![format!("limit={}", limit)];
    if let Some(a) = actor {
        qs.push(format!("actor={}", urlencoding::encode(a)));
    }
    if let Some(agent_id) = &agent_resolved {
        qs.push(format!("agent_id={}", urlencoding::encode(agent_id)));
    }
    let url = format!("{}/v1/admin/audit?{}", ctx.base, qs.join("&"));

    let res = ctx.cli.get(url).send()?;
    let status = res.status();
    let text = res.text()?;
    if !status.is_success() {
        return Err(anyhow!(
            "audit fetch failed: status={} body={}",
            status,
            text
        ));
    }
    print_audit(&text)?;
    Ok(())
}

pub fn cmd_tail(ctx: &CliCtx, agent: &str, interval: u64) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    ctx.cancel.store(false, Ordering::SeqCst);
    follow_results(ctx.cli, ctx.base, &agent_id, interval, ctx.cancel.clone())?;
    Ok(())
}

fn follow_results(
    cli: &reqwest::blocking::Client,
    base: &str,
    agent: &str,
    interval_s: u64,
    cancel: Arc<AtomicBool>,
) -> Result<()> {
    display::print_tail_header(agent);
    let mut seen: HashSet<String> = HashSet::new();

    while !cancel.load(Ordering::SeqCst) {
        let res = cli
            .get(format!(
                "{base}/v1/admin/results?agent_id={agent}&limit=200"
            ))
            .send()?;
        let text = res.text()?;
        let v: serde_json::Value = serde_json::from_str(&text)?;
        let arr = v
            .as_array()
            .ok_or_else(|| anyhow!("bad json from server"))?;
        for item in arr {
            let cmd_id = item
                .get("cmd_id")
                .and_then(|x| x.as_str())
                .unwrap_or("")
                .to_string();
            if cmd_id.is_empty() || seen.contains(&cmd_id) {
                continue;
            }
            seen.insert(cmd_id.clone());
            let exit = item.get("exit_code").and_then(|x| x.as_i64()).unwrap_or(0);
            let stdout = item.get("stdout").and_then(|x| x.as_str()).unwrap_or("");
            display::print_tail_item(&cmd_id, exit, stdout);
        }
        for _ in 0..interval_s {
            if cancel.load(Ordering::SeqCst) {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
    display::print_stopped();
    Ok(())
}
