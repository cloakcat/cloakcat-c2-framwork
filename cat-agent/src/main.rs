//! CloakCat agent binary entry point — thin wrapper around the library.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    cat_agent::beacon_main().await
}
