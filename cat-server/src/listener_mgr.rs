//! Dynamic listener management — each listener runs as an independent tokio task.
//!
//! `ListenerManager` tracks active listeners by name and provides cancel-on-remove
//! semantics via `tokio_util::sync::CancellationToken`.

use std::collections::HashMap;

use anyhow::{Context, Result};
use tokio_util::sync::CancellationToken;

use crate::config::ListenerEntry;

/// Runtime handle for one active listener.
pub struct ListenerHandle {
    pub entry: ListenerEntry,
    cancel: CancellationToken,
}

/// Tracks all running listeners by name.
#[derive(Default)]
pub struct ListenerManager {
    handles: HashMap<String, ListenerHandle>,
}

impl ListenerManager {
    pub fn new() -> Self {
        Self::default()
    }

    /// Sorted list of active listener entries.
    pub fn list(&self) -> Vec<&ListenerEntry> {
        let mut v: Vec<&ListenerEntry> = self.handles.values().map(|h| &h.entry).collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        v
    }

    pub fn contains(&self, name: &str) -> bool {
        self.handles.contains_key(name)
    }

    /// Insert a newly spawned listener handle.
    pub fn insert(&mut self, entry: ListenerEntry, cancel: CancellationToken) {
        self.handles
            .insert(entry.name.clone(), ListenerHandle { entry, cancel });
    }

    /// Cancel and remove the named listener. Returns `true` if it existed.
    pub fn remove(&mut self, name: &str) -> bool {
        if let Some(h) = self.handles.remove(name) {
            h.cancel.cancel();
            true
        } else {
            false
        }
    }
}

/// Spawn a background plain-HTTP listener task.
/// Returns the `CancellationToken` used to stop it later.
pub async fn spawn_http(entry: &ListenerEntry, app: axum::Router) -> Result<CancellationToken> {
    let addr: std::net::SocketAddr = entry
        .bind_addr()
        .parse()
        .with_context(|| format!("invalid bind addr: {}", entry.bind_addr()))?;

    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    let name = entry.name.clone();

    tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("[listener] '{name}' bind failed: {e}");
                return;
            }
        };
        println!("[listener] '{name}' HTTP on http://{addr}");
        tokio::select! {
            res = axum::serve(listener, app) => {
                if let Err(e) = res {
                    eprintln!("[listener] '{name}' error: {e}");
                }
            }
            _ = cancel_child.cancelled() => {
                println!("[listener] '{name}' stopped");
            }
        }
    });

    Ok(cancel)
}

/// Spawn a background HTTPS listener task.
/// Returns the `CancellationToken` used to stop it later.
pub async fn spawn_https(
    entry: &ListenerEntry,
    app: axum::Router,
    tls_config: axum_server::tls_rustls::RustlsConfig,
) -> Result<CancellationToken> {
    let addr: std::net::SocketAddr = entry
        .bind_addr()
        .parse()
        .with_context(|| format!("invalid bind addr: {}", entry.bind_addr()))?;

    let cancel = CancellationToken::new();
    let cancel_child = cancel.clone();
    let name = entry.name.clone();

    tokio::spawn(async move {
        let handle = axum_server::Handle::new();
        let handle2 = handle.clone();
        let name2 = name.clone();

        tokio::spawn(async move {
            cancel_child.cancelled().await;
            println!("[listener] '{name2}' graceful shutdown…");
            handle2.graceful_shutdown(Some(std::time::Duration::from_secs(2)));
        });

        println!("[listener] '{name}' HTTPS on https://{addr}");
        if let Err(e) = axum_server::bind_rustls(addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service())
            .await
        {
            eprintln!("[listener] '{name}' exited: {e}");
        }
    });

    Ok(cancel)
}
