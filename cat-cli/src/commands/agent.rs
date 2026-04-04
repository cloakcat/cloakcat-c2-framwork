//! Agent management commands: agents, alias, tags.

use anyhow::{anyhow, Result};

use crate::display;
use crate::http::{fetch_tags, resolve_agent_identifier, update_tags};
use crate::output::{print_agents, print_agents_with_tags, print_json};
use crate::types::AgentInfo;

use super::CliCtx;

pub fn cmd_agents(ctx: &CliCtx) -> Result<()> {
    let res = ctx.cli.get(format!("{}/v1/admin/agents", ctx.base)).send()?;
    let text = res.text()?;
    if let Err(e) = print_agents(&text) {
        eprintln!("failed to parse agents list: {e}");
        print_json(text);
    }
    Ok(())
}

pub fn cmd_alias(ctx: &CliCtx, agent: &str, alias_parts: Vec<String>) -> Result<()> {
    let alias = alias_parts.join(" ");
    let res = ctx
        .cli
        .post(format!("{}/v1/admin/agents/{agent}/alias", ctx.base))
        .json(&serde_json::json!({ "alias": alias, "note": serde_json::Value::Null }))
        .send()?;
    if res.status().is_success() {
        display::print_success(&format!("alias: {} → {}", agent, alias));
    } else {
        let body = res.text().unwrap_or_default();
        return Err(anyhow!("alias update failed: {}", body));
    }
    Ok(())
}

pub fn cmd_tags(ctx: &CliCtx, agent: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let tags = fetch_tags(ctx.cli, ctx.base, &agent_id)?;
    display::print_success(&format!("tags: {}", tags.join(", ")));
    Ok(())
}

pub fn cmd_tag_add(ctx: &CliCtx, agent: &str, tag: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let mut tags = fetch_tags(ctx.cli, ctx.base, &agent_id)?;
    if !tags.contains(&tag.to_string()) {
        tags.push(tag.to_string());
    }
    update_tags(ctx.cli, ctx.base, &agent_id, &tags)?;
    display::print_success(&format!("tags: {}", tags.join(", ")));
    Ok(())
}

pub fn cmd_tag_remove(ctx: &CliCtx, agent: &str, tag: &str) -> Result<()> {
    let agent_id = resolve_agent_identifier(ctx.cli, ctx.base, agent)?;
    let mut tags = fetch_tags(ctx.cli, ctx.base, &agent_id)?;
    tags.retain(|t| t != tag);
    update_tags(ctx.cli, ctx.base, &agent_id, &tags)?;
    display::print_success(&format!("tags: {}", tags.join(", ")));
    Ok(())
}

pub fn cmd_agents_tags(ctx: &CliCtx, filter_tag: Option<&str>) -> Result<()> {
    let res = ctx.cli.get(format!("{}/v1/admin/agents", ctx.base)).send()?;
    let text = res.text()?;
    let agents: Vec<AgentInfo> = serde_json::from_str(&text)?;
    let filtered: Vec<AgentInfo> = if let Some(tag) = filter_tag {
        agents
            .into_iter()
            .filter(|a| a.tags.iter().any(|t| t == tag))
            .collect()
    } else {
        agents
    };
    print_agents_with_tags(filtered);
    Ok(())
}
