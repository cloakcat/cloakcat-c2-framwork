//! BOF command — upload and execute a Beacon Object File on an agent.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};

use crate::display;
use crate::http::resolve_agent_identifier;

use super::CliCtx;

/// Read a local .o file, base64-encode it, and send it to the agent as a BOF task.
pub fn cmd_bof(ctx: &CliCtx, agent: &str, bof_path: &str, args_b64: Option<&str>) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    let bof_bytes = std::fs::read(bof_path)
        .map_err(|e| anyhow!("cannot read BOF file '{}': {}", bof_path, e))?;
    if bof_bytes.is_empty() {
        return Err(anyhow!("BOF file '{}' is empty", bof_path));
    }
    if bof_bytes.len() > 10 * 1024 * 1024 {
        return Err(anyhow!(
            "BOF file too large ({} bytes); max 10 MB",
            bof_bytes.len()
        ));
    }

    let bof_b64 = B64.encode(&bof_bytes);
    let args = args_b64.unwrap_or("").to_string();

    let task_payload = serde_json::to_string(&serde_json::json!({
        "bof_b64": bof_b64,
        "args_b64": args,
    }))?;

    let res = ctx
        .cli
        .post(format!("{}/v1/command/{}", ctx.base, agent_id))
        .json(&serde_json::json!({
            "command": task_payload,
            "task_type": "bof",
        }))
        .send()?;

    if !res.status().is_success() {
        return Err(anyhow!(
            "BOF task failed: status={} body={}",
            res.status(),
            res.text()?
        ));
    }

    let filename = std::path::Path::new(bof_path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(bof_path);

    display::print_success(&format!(
        "BOF '{}' ({} bytes) queued to agent {}",
        filename,
        bof_bytes.len(),
        agent_id
    ));
    Ok(())
}
