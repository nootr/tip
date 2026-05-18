use anyhow::{bail, Context};
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
    config::NodeConfig,
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
    peer: Vec<String>,
    #[arg(long)]
    config: Option<String>,
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
    let peer_urls = sync_peer_urls(&command)?;
    let store = SqliteEventStore::open(&command.db).context("open SQLite event store")?;
    let mut peer_summaries = Vec::with_capacity(peer_urls.len());
    let mut total_pulled = 0usize;
    let mut total_accepted = 0usize;
    let mut total_rejected = 0usize;

    for peer_url in peer_urls {
        let peer = HttpPeerEventClient::new(&peer_url);
        let summary = use_cases::sync_from_peer(&peer, &store, &Ed25519Verifier, command.limit)
            .with_context(|| format!("sync from peer {}", peer_url))?;
        total_pulled += summary.pulled;
        total_accepted += summary.accepted;
        total_rejected += summary.rejected;
        peer_summaries.push(json!({
            "peer": peer_url,
            "pulled": summary.pulled,
            "accepted": summary.accepted,
            "rejected": summary.rejected,
        }));
    }

    let output = if peer_summaries.len() == 1 && command.config.is_none() && command.peer.len() == 1
    {
        json!({
            "pulled": total_pulled,
            "accepted": total_accepted,
            "rejected": total_rejected,
        })
    } else {
        json!({
            "pulled": total_pulled,
            "accepted": total_accepted,
            "rejected": total_rejected,
            "peers": peer_summaries,
        })
    };

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

fn sync_peer_urls(command: &SyncCommand) -> anyhow::Result<Vec<String>> {
    let mut peers = command.peer.clone();

    if let Some(config_path) = &command.config {
        let config = NodeConfig::load(config_path)
            .with_context(|| format!("load config {}", config_path))?;
        peers.extend(config.peers.urls);
    }

    peers.sort();
    peers.dedup();

    if peers.is_empty() {
        bail!("sync requires at least one --peer or --config with [peers].urls");
    }

    Ok(peers)
}
