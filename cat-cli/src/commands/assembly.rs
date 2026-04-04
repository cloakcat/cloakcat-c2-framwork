//! execute-assembly CLI command.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::display;
use crate::http::resolve_agent_identifier;

use super::CliCtx;

/// execute-assembly <agent> <file> [args...] [--inline]
pub fn cmd_execute_assembly(
    ctx: &CliCtx,
    agent: &str,
    assembly_path: &str,
    args: Vec<String>,
    inline: bool,
) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    let assembly = std::fs::read(assembly_path)
        .map_err(|e| anyhow!("cannot read assembly '{}': {}", assembly_path, e))?;
    if assembly.is_empty() {
        return Err(anyhow!("assembly file '{}' is empty", assembly_path));
    }

    let assembly_b64 = B64.encode(&assembly);

    let task_payload = serde_json::to_string(&serde_json::json!({
        "assembly_b64": assembly_b64,
        "args": args,
        "inline": inline,
    }))?;

    let res = ctx
        .cli
        .post(format!("{}/v1/command/{}", ctx.base, agent_id))
        .json(&serde_json::json!({
            "command": task_payload,
            "task_type": "execute_assembly",
        }))
        .send()?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "execute-assembly failed: status={} body={}",
            res.status(),
            res.text()?
        ));
    }

    let mode = if inline { "inline" } else { "spawn+execute" };
    let args_display = if args.is_empty() {
        String::new()
    } else {
        format!(" args=[{}]", args.join(", "))
    };
    display::print_success(&format!(
        "execute-assembly queued ({}): {} bytes{} on agent {}",
        mode,
        assembly.len(),
        args_display,
        agent_id
    ));
    Ok(())
}
