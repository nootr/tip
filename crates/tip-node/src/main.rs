use anyhow::Context;
use clap::{Parser, Subcommand};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use tip_node::{
    adapters::{node_key_file, sqlite_event_store::SqliteEventStore},
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let command = match cli.command {
        Some(Command::Serve(command)) => command,
        None => ServeCommand::parse_from(["tip-node"]),
    };

    serve(command).await
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
