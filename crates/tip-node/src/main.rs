use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};
use tip_core::{
    crypto::Ed25519Verifier,
    ports::Clock,
    use_cases::{self, SyncFromPeerOptions},
};

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
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    sync_on_start: bool,
    #[arg(long, default_value_t = 500)]
    sync_limit: usize,
    #[arg(long)]
    sync_from_beginning: bool,
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
    #[arg(long)]
    from_beginning: bool,
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

    if command.sync_on_start {
        let peer_urls = config_peer_urls(command.config.as_deref())?;
        let summary = tokio::task::block_in_place(|| {
            sync_peers(
                &peer_urls,
                &store,
                command.sync_limit,
                command.sync_from_beginning,
            )
        })?;
        eprintln!(
            "TIP startup sync completed: pulled={}, accepted={}, rejected={}",
            summary.pulled, summary.accepted, summary.rejected
        );
    }

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
    let summary = sync_peers(&peer_urls, &store, command.limit, command.from_beginning)?;

    let output = if peer_urls.len() == 1 && command.config.is_none() && command.peer.len() == 1 {
        json!({
            "pulled": summary.pulled,
            "accepted": summary.accepted,
            "rejected": summary.rejected,
        })
    } else {
        json!({
            "pulled": summary.pulled,
            "accepted": summary.accepted,
            "rejected": summary.rejected,
            "peers": summary.peers,
        })
    };

    println!("{}", serde_json::to_string_pretty(&output)?);

    Ok(())
}

#[derive(Debug)]
struct MultiPeerSyncSummary {
    pulled: usize,
    accepted: usize,
    rejected: usize,
    peers: Vec<serde_json::Value>,
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64
    }
}

fn sync_peers(
    peer_urls: &[String],
    store: &SqliteEventStore,
    limit: usize,
    from_beginning: bool,
) -> anyhow::Result<MultiPeerSyncSummary> {
    let mut peer_summaries = Vec::with_capacity(peer_urls.len());
    let mut total_pulled = 0usize;
    let mut total_accepted = 0usize;
    let mut total_rejected = 0usize;

    for peer_url in peer_urls {
        let peer = HttpPeerEventClient::new(peer_url);
        let summary = use_cases::sync_from_peer_with_state(
            peer_url,
            &peer,
            store,
            store,
            &Ed25519Verifier,
            &SystemClock,
            SyncFromPeerOptions {
                page_limit: limit,
                from_beginning,
            },
        )
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

    Ok(MultiPeerSyncSummary {
        pulled: total_pulled,
        accepted: total_accepted,
        rejected: total_rejected,
        peers: peer_summaries,
    })
}

fn sync_peer_urls(command: &SyncCommand) -> anyhow::Result<Vec<String>> {
    let mut peers = command.peer.clone();

    if let Some(config_path) = &command.config {
        peers.extend(load_config_peer_urls(config_path)?);
    }

    normalize_peer_urls(
        peers,
        "sync requires at least one --peer or --config with [peers].urls",
    )
}

fn config_peer_urls(config_path: Option<&str>) -> anyhow::Result<Vec<String>> {
    let config_path = config_path
        .ok_or_else(|| anyhow::anyhow!("--sync-on-start requires --config with [peers].urls"))?;
    normalize_peer_urls(
        load_config_peer_urls(config_path)?,
        "--sync-on-start requires --config with [peers].urls",
    )
}

fn load_config_peer_urls(config_path: &str) -> anyhow::Result<Vec<String>> {
    let config =
        NodeConfig::load(config_path).with_context(|| format!("load config {}", config_path))?;
    Ok(config.peers.urls)
}

fn normalize_peer_urls(mut peers: Vec<String>, empty_message: &str) -> anyhow::Result<Vec<String>> {
    peers.sort();
    peers.dedup();

    if peers.is_empty() {
        bail!(empty_message.to_string());
    }

    Ok(peers)
}
