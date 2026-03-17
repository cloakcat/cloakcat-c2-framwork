//! Agent configuration loading (embedded + optional file override).

use std::env;
use std::path::Path;

use cloakcat_protocol::AgentConfig;

#[cfg(embed_has_out_dir)]
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_config.rs"));
}

#[cfg(not(embed_has_out_dir))]
mod embedded {
    pub const EMBEDDED_CONFIG: &str = r#"{}"#;
}

pub fn load_agent_config() -> anyhow::Result<AgentConfig> {
    let embedded_cfg: AgentConfig = serde_json::from_str(embedded::EMBEDDED_CONFIG)
        .map_err(|e| anyhow::anyhow!("failed to parse embedded config: {}", e))?;

    let path = if let Ok(p) = env::var("CLOAKCAT_CONFIG") {
        Some(Path::new(&p).to_path_buf())
    } else {
        let exe = std::env::current_exe()?;
        Some(
            exe.parent()
                .unwrap_or_else(|| Path::new("."))
                .join("agent_config.json"),
        )
    };

    if let Some(path) = path {
        if path.exists() {
            let bytes = std::fs::read(&path)
                .map_err(|e| anyhow::anyhow!("failed to read config {:?}: {}", path, e))?;
            let cfg: AgentConfig = serde_json::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("failed to parse config {:?}: {}", path, e))?;
            return Ok(cfg);
        }
    }

    Ok(embedded_cfg)
}
