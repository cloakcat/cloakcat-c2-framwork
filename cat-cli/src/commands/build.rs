//! Build command: build-agent.

use std::path::PathBuf;

use anyhow::Result;

use crate::build::{build_agent, BuildAgentArgs, Os};

pub fn cmd_build_agent(
    os: Os,
    alias: String,
    c2_url: String,
    profile: String,
    shared_token: String,
    output_dir: PathBuf,
    name: String,
    note: Option<String>,
) -> Result<()> {
    let args = BuildAgentArgs {
        os,
        alias,
        c2_url,
        profile,
        shared_token,
        output_dir,
        name,
        note,
    };
    build_agent(args)
}
