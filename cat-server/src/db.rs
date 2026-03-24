use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AgentRecord {
    pub id: Uuid,
    pub agent_id: String,
    pub platform: String,
    pub alias: Option<String>,
    pub note: Option<String>,
    pub profile_name: Option<String>,
    pub beacon_min_ms: Option<i32>,
    pub beacon_max_ms: Option<i32>,
    pub backoff_max_ms: Option<i32>,
    pub kill_after_hours: Option<i32>,
    pub hostname: Option<String>,
    pub username: Option<String>,
    pub os_version: Option<String>,
    pub ip_addrs: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_seen_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct CommandRecord {
    pub id: Uuid,
    pub agent_id: String,
    pub command: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct ResultRecord {
    pub id: Uuid,
    pub agent_id: String,
    pub command_id: Uuid,
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AuditRecord {
    pub id: i64,
    pub ts: DateTime<Utc>,
    pub actor: String,
    pub action: String,
    pub target_type: String,
    pub target_id: String,
    pub context: serde_json::Value,
}

pub async fn upsert_agent(
    pool: &PgPool,
    agent_id: &str,
    platform: &str,
    alias: Option<&str>,
    note: Option<&str>,
    hostname: Option<&str>,
    username: Option<&str>,
    os_version: Option<&str>,
    ip_addrs: Option<&str>,
    tags: Option<&[String]>,
) -> Result<AgentRecord, anyhow::Error> {
    let record = sqlx::query_as!(
        AgentRecord,
        r#"
        INSERT INTO agents (agent_id, platform, alias, note, hostname, username, os_version, ip_addrs, tags, last_seen_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, COALESCE($9, '{}'::text[]), now())
        ON CONFLICT (agent_id)
        DO UPDATE
        SET platform = EXCLUDED.platform,
            alias = COALESCE(agents.alias, EXCLUDED.alias),
            note = COALESCE(agents.note, EXCLUDED.note),
            hostname = COALESCE(EXCLUDED.hostname, agents.hostname),
            username = COALESCE(EXCLUDED.username, agents.username),
            os_version = COALESCE(EXCLUDED.os_version, agents.os_version),
            ip_addrs = COALESCE(EXCLUDED.ip_addrs, agents.ip_addrs),
            tags = COALESCE($9, agents.tags),
            last_seen_at = now()
        RETURNING
            id,
            agent_id,
            platform,
            alias,
            note,
            profile_name,
            beacon_min_ms,
            beacon_max_ms,
            backoff_max_ms,
            kill_after_hours,
            hostname,
            username,
            os_version,
            ip_addrs,
            tags,
            created_at,
            last_seen_at
        "#,
        agent_id,
        platform,
        alias,
        note,
        hostname,
        username,
        os_version,
        ip_addrs,
        tags
    )
    .fetch_one(pool)
    .await?;

    Ok(record)
}

pub async fn get_agent_by_id(
    pool: &PgPool,
    agent_id: &str,
) -> Result<Option<AgentRecord>, anyhow::Error> {
    let record = sqlx::query_as!(
        AgentRecord,
        r#"
        SELECT
            id,
            agent_id,
            platform,
            alias,
            note,
            profile_name,
            beacon_min_ms,
            beacon_max_ms,
            backoff_max_ms,
            kill_after_hours,
            hostname,
            username,
            os_version,
            ip_addrs,
            tags,
            created_at,
            last_seen_at
        FROM agents
        WHERE agent_id = $1
        "#,
        agent_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

pub async fn insert_command(
    pool: &PgPool,
    agent_id: &str,
    command: &str,
) -> Result<CommandRecord, anyhow::Error> {
    let record = sqlx::query_as!(
        CommandRecord,
        r#"
        INSERT INTO commands (agent_id, command)
        VALUES ($1, $2)
        RETURNING id, agent_id, command, created_at
        "#,
        agent_id,
        command
    )
    .fetch_one(pool)
    .await?;

    Ok(record)
}

pub async fn get_oldest_command_for_agent(
    pool: &PgPool,
    agent_id: &str,
) -> Result<Option<CommandRecord>, anyhow::Error> {
    let record = sqlx::query_as!(
        CommandRecord,
        r#"
        SELECT id, agent_id, command, created_at
        FROM commands
        WHERE agent_id = $1
          AND NOT EXISTS (
              SELECT 1
              FROM results r
              WHERE r.command_id = commands.id
          )
        ORDER BY created_at ASC
        LIMIT 1
        "#,
        agent_id
    )
    .fetch_optional(pool)
    .await?;

    Ok(record)
}

#[allow(dead_code)]
pub async fn delete_command_by_id(
    pool: &PgPool,
    id: Uuid,
) -> Result<(), anyhow::Error> {
    sqlx::query!(
        r#"
        DELETE FROM commands
        WHERE id = $1
        "#,
        id
    )
    .execute(pool)
    .await?;

    Ok(())
}


pub async fn insert_result(
    pool: &PgPool,
    agent_id: &str,
    command_id: Uuid,
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> Result<ResultRecord> {
    let rec = sqlx::query_as!(
        ResultRecord,
        r#"
        insert into results (agent_id, command_id, exit_code, stdout, stderr)
        values ($1, $2, $3, $4, $5)
        returning id, agent_id, command_id, exit_code, stdout, stderr, created_at
        "#,
        agent_id,
        command_id,
        exit_code,
        stdout,
        stderr,
    )
    .fetch_one(pool)
    .await?;

    Ok(rec)
}

pub async fn list_agents(pool: &PgPool) -> Result<Vec<AgentRecord>, anyhow::Error> {
    let records = sqlx::query_as!(
        AgentRecord,
        r#"
        SELECT
            id,
            agent_id,
            platform,
            alias,
            note,
            profile_name,
            beacon_min_ms,
            beacon_max_ms,
            backoff_max_ms,
            kill_after_hours,
            hostname,
            username,
            os_version,
            ip_addrs,
            tags,
            created_at,
            last_seen_at
        FROM agents
        ORDER BY created_at ASC
        "#
    )
    .fetch_all(pool)
    .await?;

    Ok(records)
}

pub async fn update_agent_tags(
    pool: &PgPool,
    agent_id: &str,
    tags: &[String],
) -> Result<AgentRecord, anyhow::Error> {
    let record = sqlx::query_as!(
        AgentRecord,
        r#"
        UPDATE agents
        SET tags = $2
        WHERE agent_id = $1
        RETURNING
            id,
            agent_id,
            platform,
            alias,
            note,
            profile_name,
            beacon_min_ms,
            beacon_max_ms,
            backoff_max_ms,
            kill_after_hours,
            hostname,
            username,
            os_version,
            ip_addrs,
            tags,
            created_at,
            last_seen_at
        "#,
        agent_id,
        tags
    )
    .fetch_one(pool)
    .await?;

    Ok(record)
}

pub async fn list_results(
    pool: &PgPool,
    agent_id: Option<&str>,
    limit: i64,
) -> Result<Vec<ResultRecord>, anyhow::Error> {
    let limit = limit.max(1);

    let records = match agent_id {
        Some(agent_id) => {
            sqlx::query_as!(
                ResultRecord,
                r#"
                SELECT id, agent_id, command_id, exit_code, stdout, stderr, created_at
                FROM results
                WHERE agent_id = $1
                ORDER BY created_at DESC
                LIMIT $2
                "#,
                agent_id,
                limit
            )
            .fetch_all(pool)
            .await?
        }
        None => {
            sqlx::query_as!(
                ResultRecord,
                r#"
                SELECT id, agent_id, command_id, exit_code, stdout, stderr, created_at
                FROM results
                ORDER BY created_at DESC
                LIMIT $1
                "#,
                limit
            )
            .fetch_all(pool)
            .await?
        }
    };

    Ok(records)
}

pub async fn insert_audit(
    pool: &PgPool,
    actor: &str,
    action: &str,
    target_type: &str,
    target_id: &str,
    context: &serde_json::Value,
) -> Result<(), anyhow::Error> {
    sqlx::query(
        r#"
        INSERT INTO audit (ts, actor, action, target_type, target_id, context)
        VALUES (now(), $1, $2, $3, $4, $5)
        "#,
    )
    .bind(actor)
    .bind(action)
    .bind(target_type)
    .bind(target_id)
    .bind(context)
    .execute(pool)
    .await?;

    Ok(())
}

pub async fn list_audit(
    pool: &PgPool,
    limit: i64,
    actor: Option<&str>,
    target_agent_id: Option<&str>,
) -> Result<Vec<AuditRecord>, anyhow::Error> {
    if let Some(actor) = actor {
        if let Some(agent) = target_agent_id {
            let records = sqlx::query_as::<_, AuditRecord>(
                r#"
                SELECT id, ts, actor, action, target_type, target_id, context
                FROM audit
                WHERE actor = $1
                  AND context ->> 'agent_id' = $2
                ORDER BY ts DESC
                LIMIT $3
                "#,
            )
            .bind(actor)
            .bind(agent)
            .bind(limit)
            .fetch_all(pool)
            .await?;
            return Ok(records);
        }

        let records = sqlx::query_as::<_, AuditRecord>(
            r#"
            SELECT id, ts, actor, action, target_type, target_id, context
            FROM audit
            WHERE actor = $1
            ORDER BY ts DESC
            LIMIT $2
            "#,
        )
        .bind(actor)
        .bind(limit)
        .fetch_all(pool)
        .await?;
        return Ok(records);
    }

    if let Some(agent) = target_agent_id {
        let records = sqlx::query_as::<_, AuditRecord>(
            r#"
            SELECT id, ts, actor, action, target_type, target_id, context
            FROM audit
            WHERE context ->> 'agent_id' = $1
            ORDER BY ts DESC
            LIMIT $2
            "#,
        )
        .bind(agent)
        .bind(limit)
        .fetch_all(pool)
        .await?;
        return Ok(records);
    }

    let records = sqlx::query_as::<_, AuditRecord>(
        r#"
        SELECT id, ts, actor, action, target_type, target_id, context
        FROM audit
        ORDER BY ts DESC
        LIMIT $1
        "#,
    )
    .bind(limit)
    .fetch_all(pool)
    .await?;

    Ok(records)
}
pub async fn update_agent_alias(
    pool: &PgPool,
    agent_id: &str,
    alias: Option<&str>,
    note: Option<&str>,
) -> Result<AgentRecord> {
    let rec = sqlx::query_as!(
        AgentRecord,
        r#"
        UPDATE agents
        SET alias = $2,
            note = $3
        WHERE agent_id = $1
        RETURNING
            id,
            agent_id,
            platform,
            alias,
            note,
            profile_name,
            beacon_min_ms,
            beacon_max_ms,
            backoff_max_ms,
            kill_after_hours,
            hostname,
            username,
            os_version,
            ip_addrs,
            tags,
            created_at,
            last_seen_at
        "#,
        agent_id,
        alias,
        note
    )
    .fetch_one(pool)
    .await?;

    Ok(rec)
}

