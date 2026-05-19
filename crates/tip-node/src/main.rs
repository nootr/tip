use anyhow::{bail, Context};
use clap::{Parser, Subcommand};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
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
    #[arg(long, env = "TIP_NODE_BIND")]
    bind: Option<String>,
    #[arg(long, env = "TIP_NODE_DB")]
    db: Option<String>,
    #[arg(long, env = "TIP_NODE_KEY")]
    key: Option<String>,
    #[arg(long)]
    config: Option<String>,
    #[arg(long)]
    sync_on_start: bool,
    #[arg(long)]
    sync_limit: Option<usize>,
    #[arg(long)]
    sync_from_beginning: bool,
    #[arg(long)]
    sync_periodic_seconds: Option<u64>,
    #[arg(long)]
    sync_full_resync_seconds: Option<u64>,
}

#[derive(Parser)]
struct SyncCommand {
    #[arg(long)]
    peer: Vec<String>,
    #[arg(long)]
    config: Option<String>,
    #[arg(long, env = "TIP_NODE_DB")]
    db: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
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
    let config = load_optional_config(command.config.as_deref())?;
    let resolved = resolve_serve_config(&command, config.as_ref())?;
    let peer_urls = if resolved.sync_on_start || resolved.sync_periodic_seconds.is_some() {
        Some(config_peer_urls(
            config.as_ref(),
            "configured sync requires [peers].urls",
        )?)
    } else {
        None
    };

    let node_key =
        node_key_file::load_or_generate(&resolved.key).context("load node identity key")?;
    let store = SqliteEventStore::open(&resolved.db).context("open SQLite event store")?;

    if resolved.sync_on_start {
        let summary = tokio::task::block_in_place(|| {
            sync_peers(
                peer_urls.as_ref().expect("peer URLs are loaded"),
                &store,
                resolved.sync_limit,
                resolved.sync_from_beginning,
            )
        })?;
        eprintln!(
            "TIP startup sync completed: pulled={}, accepted={}, rejected={}",
            summary.pulled, summary.accepted, summary.rejected
        );
    }

    let store = Arc::new(Mutex::new(store));
    if let Some(periodic_seconds) = resolved.sync_periodic_seconds {
        spawn_periodic_sync(
            peer_urls.expect("peer URLs are loaded"),
            Arc::clone(&store),
            resolved.sync_limit,
            periodic_seconds,
            resolved.sync_full_resync_seconds,
        );
    }

    let metadata = config
        .as_ref()
        .map(|config| config.node.metadata())
        .unwrap_or_default();
    let state = AppState::new_with_metadata(node_key, store, metadata);

    let addr: SocketAddr = resolved.bind.parse().context("parse bind address")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    eprintln!("TIP node listening on http://{}", addr);
    axum::serve(listener, router(state)).await?;
    Ok(())
}

fn sync(command: SyncCommand) -> anyhow::Result<()> {
    let config = load_optional_config(command.config.as_deref())?;
    let peer_urls = sync_peer_urls(&command, config.as_ref())?;
    let db = command
        .db
        .clone()
        .or_else(|| config.as_ref().and_then(|config| config.node.db.clone()))
        .unwrap_or_else(|| "tip-node.sqlite3".to_string());
    let limit = command
        .limit
        .or_else(|| config.as_ref().and_then(|config| config.sync.limit))
        .unwrap_or(500);
    let from_beginning = command.from_beginning
        || config
            .as_ref()
            .and_then(|config| config.sync.from_beginning)
            .unwrap_or(false);

    let store = SqliteEventStore::open(&db).context("open SQLite event store")?;
    let summary = sync_peers(&peer_urls, &store, limit, from_beginning)?;

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

struct ResolvedServeConfig {
    bind: String,
    db: String,
    key: String,
    sync_on_start: bool,
    sync_limit: usize,
    sync_from_beginning: bool,
    sync_periodic_seconds: Option<u64>,
    sync_full_resync_seconds: Option<u64>,
}

fn load_optional_config(path: Option<&str>) -> anyhow::Result<Option<NodeConfig>> {
    path.map(NodeConfig::load).transpose()
}

fn resolve_serve_config(
    command: &ServeCommand,
    config: Option<&NodeConfig>,
) -> anyhow::Result<ResolvedServeConfig> {
    let sync_periodic_seconds = command
        .sync_periodic_seconds
        .or_else(|| config.and_then(|config| config.sync.periodic_seconds));
    let sync_full_resync_seconds = command
        .sync_full_resync_seconds
        .or_else(|| config.and_then(|config| config.sync.full_resync_seconds));

    if matches!(sync_periodic_seconds, Some(0)) {
        bail!("sync_periodic_seconds must be greater than zero");
    }
    if matches!(sync_full_resync_seconds, Some(0)) {
        bail!("sync_full_resync_seconds must be greater than zero");
    }
    if sync_full_resync_seconds.is_some() && sync_periodic_seconds.is_none() {
        bail!("sync_full_resync_seconds requires sync_periodic_seconds");
    }

    Ok(ResolvedServeConfig {
        bind: command
            .bind
            .clone()
            .or_else(|| config.and_then(|config| config.node.bind.clone()))
            .unwrap_or_else(|| "127.0.0.1:8080".to_string()),
        db: command
            .db
            .clone()
            .or_else(|| config.and_then(|config| config.node.db.clone()))
            .unwrap_or_else(|| "tip-node.sqlite3".to_string()),
        key: command
            .key
            .clone()
            .or_else(|| config.and_then(|config| config.node.key.clone()))
            .unwrap_or_else(|| "tip-node-key.json".to_string()),
        sync_on_start: command.sync_on_start
            || config
                .and_then(|config| config.sync.on_start)
                .unwrap_or(false),
        sync_limit: command
            .sync_limit
            .or_else(|| config.and_then(|config| config.sync.limit))
            .unwrap_or(500),
        sync_from_beginning: command.sync_from_beginning
            || config
                .and_then(|config| config.sync.from_beginning)
                .unwrap_or(false),
        sync_periodic_seconds,
        sync_full_resync_seconds,
    })
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

fn spawn_periodic_sync(
    peer_urls: Vec<String>,
    store: Arc<Mutex<SqliteEventStore>>,
    limit: usize,
    periodic_seconds: u64,
    full_resync_seconds: Option<u64>,
) {
    tokio::spawn(async move {
        let periodic = Duration::from_secs(periodic_seconds);
        let full_resync = full_resync_seconds.map(Duration::from_secs);
        let mut last_full_resync = SystemTime::now();

        loop {
            tokio::time::sleep(periodic).await;

            let from_beginning = full_resync
                .and_then(|interval| {
                    SystemTime::now()
                        .duration_since(last_full_resync)
                        .ok()
                        .map(|elapsed| elapsed >= interval)
                })
                .unwrap_or(false);
            if from_beginning {
                last_full_resync = SystemTime::now();
            }

            let peer_urls = peer_urls.clone();
            let store = Arc::clone(&store);
            let result = tokio::task::spawn_blocking(move || {
                let store = store
                    .lock()
                    .map_err(|_| anyhow::anyhow!("store lock poisoned"))?;
                sync_peers(&peer_urls, &store, limit, from_beginning)
            })
            .await;

            match result {
                Ok(Ok(summary)) => eprintln!(
                    "TIP periodic sync completed: pulled={}, accepted={}, rejected={}, full_resync={}",
                    summary.pulled, summary.accepted, summary.rejected, from_beginning
                ),
                Ok(Err(err)) => eprintln!("TIP periodic sync failed: {err:#}"),
                Err(err) => eprintln!("TIP periodic sync task failed: {err:#}"),
            }
        }
    });
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

fn sync_peer_urls(
    command: &SyncCommand,
    config: Option<&NodeConfig>,
) -> anyhow::Result<Vec<String>> {
    let mut peers = command.peer.clone();

    if let Some(config) = config {
        peers.extend(config.peers.urls.clone());
    }

    normalize_peer_urls(
        peers,
        "sync requires at least one --peer or --config with [peers].urls",
    )
}

fn config_peer_urls(
    config: Option<&NodeConfig>,
    empty_message: &str,
) -> anyhow::Result<Vec<String>> {
    let peers = config
        .ok_or_else(|| anyhow::anyhow!(empty_message.to_string()))?
        .peers
        .urls
        .clone();

    normalize_peer_urls(peers, empty_message)
}

fn normalize_peer_urls(mut peers: Vec<String>, empty_message: &str) -> anyhow::Result<Vec<String>> {
    peers.sort();
    peers.dedup();

    if peers.is_empty() {
        bail!(empty_message.to_string());
    }

    Ok(peers)
}
