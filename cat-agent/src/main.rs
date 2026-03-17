//! CloakCat agent entry point.

mod beacon;
mod config;
mod exec;
mod host;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    beacon::run().await
}
