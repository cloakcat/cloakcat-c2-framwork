//! CLI commands for reverse SOCKS5 proxy management.

use anyhow::Result;
use cloakcat_protocol::SocksListenerView;

use crate::http::resolve_agent_identifier;

use super::CliCtx;

pub fn cmd_socks_start(ctx: &CliCtx, agent: &str, port: u16) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let resp: serde_json::Value = ctx
        .cli
        .post(format!("{}/v1/admin/socks/start", ctx.base))
        .json(&serde_json::json!({ "agent_id": agent_id, "port": port }))
        .send()?
        .error_for_status()?
        .json()?;
    println!(
        "[socks] listener started on 0.0.0.0:{} for agent {}",
        resp["port"].as_u64().unwrap_or(port as u64),
        agent_id
    );
    println!("  use: proxychains -q <cmd>  (proxychains.conf: socks5 127.0.0.1 {})", port);
    Ok(())
}

pub fn cmd_socks_stop(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    ctx.cli
        .post(format!("{}/v1/admin/socks/stop", ctx.base))
        .json(&serde_json::json!({ "agent_id": agent_id }))
        .send()?
        .error_for_status()?;
    println!("[socks] listener stopped for agent {}", agent_id);
    Ok(())
}

pub fn cmd_socks_list(ctx: &CliCtx) -> Result<()> {
    let listeners: Vec<SocksListenerView> = ctx
        .cli
        .get(format!("{}/v1/admin/socks/list", ctx.base))
        .send()?
        .error_for_status()?
        .json()?;
    if listeners.is_empty() {
        println!("no active SOCKS5 listeners");
        return Ok(());
    }
    println!("{:<38} {:>6}", "AGENT", "PORT");
    println!("{}", "-".repeat(46));
    for l in &listeners {
        println!("{:<38} {:>6}", l.agent_id, l.port);
    }
    Ok(())
}
