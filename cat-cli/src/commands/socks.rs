//! CLI commands for reverse SOCKS5 proxy and port-forward management.

use anyhow::Result;
use cloakcat_protocol::{PortFwdView, SocksListenerView};

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

pub fn cmd_portfwd_start(ctx: &CliCtx, agent: &str, local_port: u16, remote_target: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    ctx.cli
        .post(format!("{}/v1/admin/portfwd/start", ctx.base))
        .json(&serde_json::json!({
            "agent_id": agent_id,
            "local_port": local_port,
            "remote_target": remote_target,
        }))
        .send()?
        .error_for_status()?;
    println!(
        "[portfwd] 0.0.0.0:{} → {} via agent {}",
        local_port, remote_target, agent_id
    );
    Ok(())
}

pub fn cmd_portfwd_stop(ctx: &CliCtx, agent: &str, local_port: u16) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    ctx.cli
        .post(format!("{}/v1/admin/portfwd/stop", ctx.base))
        .json(&serde_json::json!({ "agent_id": agent_id, "local_port": local_port }))
        .send()?
        .error_for_status()?;
    println!("[portfwd] stopped port {} for agent {}", local_port, agent_id);
    Ok(())
}

pub fn cmd_portfwd_list(ctx: &CliCtx) -> Result<()> {
    let fwds: Vec<PortFwdView> = ctx
        .cli
        .get(format!("{}/v1/admin/portfwd/list", ctx.base))
        .send()?
        .error_for_status()?
        .json()?;
    if fwds.is_empty() {
        println!("no active port-forwards");
        return Ok(());
    }
    println!("{:<38} {:>6}  {}", "AGENT", "LPORT", "REMOTE TARGET");
    println!("{}", "-".repeat(70));
    for f in &fwds {
        println!("{:<38} {:>6}  {}", f.agent_id, f.local_port, f.remote_target);
    }
    Ok(())
}
