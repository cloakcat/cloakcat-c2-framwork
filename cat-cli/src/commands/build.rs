//! Build command: build-agent.

use std::path::PathBuf;

use anyhow::Result;

use crate::build::{build_agent, BuildAgentArgs, Format, Os};

#[allow(clippy::too_many_arguments)]
pub fn cmd_build_agent(
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
    build_agent(args)
}
