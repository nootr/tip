mod adapters;
mod http;

use anyhow::Context;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use adapters::{node_key_file, sqlite_event_store::SqliteEventStore};
use http::{router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let bind = std::env::var("TIP_NODE_BIND").unwrap_or_else(|_| "127.0.0.1:8080".to_string());
    let db_path = std::env::var("TIP_NODE_DB").unwrap_or_else(|_| "tip-node.sqlite3".to_string());
    let key_path =
        std::env::var("TIP_NODE_KEY").unwrap_or_else(|_| "tip-node-key.json".to_string());

    let node_key = node_key_file::load_or_generate(&key_path).context("load node identity key")?;
    let store = SqliteEventStore::open(&db_path).context("open SQLite event store")?;
    let state = AppState::new(node_key, Arc::new(Mutex::new(store)));

    let addr: SocketAddr = bind.parse().context("parse TIP_NODE_BIND")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("TIP node listening on http://{}", addr);
    axum::serve(listener, router(state)).await?;
    Ok(())
}
