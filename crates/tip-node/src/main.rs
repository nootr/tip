use anyhow::Context;
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tip_core::{crypto::Ed25519Verifier, use_cases};

use tip_node::{
    adapters::{
        http_peer_event_client::HttpPeerEventClient, node_key_file,
        sqlite_event_store::SqliteEventStore,
    },
    http::{router, AppState},
};

#[derive(Parser)]
#[command(
    name = "tip-node",
    version,
    about = "Trust Infrastructure Protocol node"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Serve(ServeCommand),
    Sync(SyncCommand),
}

#[derive(Parser)]
struct ServeCommand {
    #[arg(long, env = "TIP_NODE_BIND", default_value = "127.0.0.1:8080")]
    bind: String,
    #[arg(long, env = "TIP_NODE_DB", default_value = "tip-node.sqlite3")]
    db: String,
    #[arg(long, env = "TIP_NODE_KEY", default_value = "tip-node-key.json")]
    key: String,
}

#[derive(Parser)]
struct SyncCommand {
    #[arg(long)]
    peer: String,
    #[arg(long, env = "TIP_NODE_DB", default_value = "tip-node.sqlite3")]
    db: String,
    #[arg(long, default_value_t = 500)]
    limit: usize,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Some(Command::Serve(command)) => run_server(command),
        Some(Command::Sync(command)) => sync(command),
        None => run_server(ServeCommand::parse_from(["tip-node"])),
    }
}

fn run_server(command: ServeCommand) -> anyhow::Result<()> {
    tokio::runtime::Runtime::new()?.block_on(serve(command))
}

async fn serve(command: ServeCommand) -> anyhow::Result<()> {
    let node_key =
        node_key_file::load_or_generate(&command.key).context("load node identity key")?;
    let store = SqliteEventStore::open(&command.db).context("open SQLite event store")?;
    let state = AppState::new(node_key, Arc::new(Mutex::new(store)));

    let addr: SocketAddr = command.bind.parse().context("parse bind address")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("TIP node listening on http://{}", addr);
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn sync(command: SyncCommand) -> anyhow::Result<()> {
    let peer = HttpPeerEventClient::new(command.peer);
    let store = SqliteEventStore::open(&command.db).context("open SQLite event store")?;
    let summary = use_cases::sync_from_peer(&peer, &store, &Ed25519Verifier, command.limit)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "pulled": summary.pulled,
            "accepted": summary.accepted,
            "rejected": summary.rejected,
        }))?
    );

    Ok(())
}
