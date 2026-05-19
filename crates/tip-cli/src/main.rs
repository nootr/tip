mod file_key_store;

use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};
use tip_core::{crypto::Ed25519Verifier, ports::Clock, use_cases, SignedEvent};

use file_key_store::FileKeyStore;

#[derive(Parser)]
#[command(name = "tip", version, about = "Trust Infrastructure Protocol CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(subcommand)]
    Key(KeyCommand),
    #[command(subcommand)]
    Identity(IdentityCommand),
    #[command(subcommand)]
    Claim(ClaimCommand),
    #[command(subcommand)]
    Attest(AttestCommand),
    #[command(subcommand)]
    Event(EventCommand),
    Query(QueryCommand),
}

#[derive(Subcommand)]
enum KeyCommand {
    Generate(KeyGenerate),
}

#[derive(Args)]
struct KeyGenerate {
    #[arg(long, default_value = "default")]
    name: String,
}

#[derive(Subcommand)]
enum IdentityCommand {
    Create(EventOutput),
}

#[derive(Subcommand)]
enum ClaimCommand {
    Add(ClaimAdd),
    Revoke(ClaimRevoke),
}

#[derive(Args)]
struct ClaimAdd {
    claim_type: String,
    value: String,
    #[arg(long)]
    proof_url: Option<String>,
    #[command(flatten)]
    output: EventOutput,
}

#[derive(Args)]
struct ClaimRevoke {
    claim_id: String,
    #[command(flatten)]
    output: EventOutput,
}

#[derive(Subcommand)]
enum AttestCommand {
    Issue(AttestIssue),
    Revoke(AttestRevoke),
}

#[derive(Args)]
struct AttestIssue {
    #[arg(allow_hyphen_values = true)]
    subject: String,
    claim: String,
    #[arg(long)]
    message: Option<String>,
    #[command(flatten)]
    output: EventOutput,
}

#[derive(Args)]
struct AttestRevoke {
    #[arg(allow_hyphen_values = true)]
    subject: String,
    attestation_id: String,
    #[command(flatten)]
    output: EventOutput,
}

#[derive(Subcommand)]
enum EventCommand {
    Verify(EventFile),
    Validate(EventSubmit),
    Submit(EventSubmit),
    SubmitBatch(EventSubmitBatch),
}

#[derive(Args)]
struct EventFile {
    path: PathBuf,
}

#[derive(Args)]
struct EventSubmit {
    path: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node: String,
}

#[derive(Args)]
struct EventSubmitBatch {
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node: String,
}

#[derive(Args)]
struct QueryCommand {
    #[command(subcommand)]
    command: Option<QuerySubcommand>,
    #[command(flatten)]
    events: QueryEventsArgs,
}

#[derive(Subcommand)]
enum QuerySubcommand {
    Claims(IdentityProjectionQuery),
    Attestations(IdentityProjectionQuery),
}

#[derive(Args)]
struct QueryEventsArgs {
    #[arg(long, allow_hyphen_values = true)]
    subject: Option<String>,
    #[arg(long, allow_hyphen_values = true)]
    issuer: Option<String>,
    #[arg(long = "type")]
    kind: Option<String>,
    #[arg(long)]
    after_created_at: Option<i64>,
    #[arg(long, allow_hyphen_values = true)]
    after_id: Option<String>,
    #[arg(long)]
    limit: Option<usize>,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node: String,
}

#[derive(Args)]
struct IdentityProjectionQuery {
    #[arg(long, allow_hyphen_values = true)]
    subject: String,
    #[arg(long, default_value = "http://127.0.0.1:8080")]
    node: String,
}

#[derive(Args, Clone)]
struct EventOutput {
    #[arg(long, default_value = "default")]
    key: String,
    #[arg(long)]
    out: Option<PathBuf>,
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

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let key_store = FileKeyStore::default()?;

    match cli.command {
        Command::Key(KeyCommand::Generate(args)) => {
            let public_key = key_store.generate(&args.name)?;
            println!("{}", json!({ "name": args.name, "public_key": public_key }));
        }
        Command::Identity(IdentityCommand::Create(output)) => {
            let signer = key_store.load(&output.key)?;
            let event = use_cases::create_identity(&SystemClock, &signer)?;
            write_event(&event, output.out)?;
        }
        Command::Claim(ClaimCommand::Add(args)) => {
            let signer = key_store.load(&args.output.key)?;
            let proof = args.proof_url.map(|url| json!({ "url": url }));
            let event =
                use_cases::add_claim(&SystemClock, &signer, args.claim_type, args.value, proof)?;
            write_event(&event, args.output.out)?;
        }
        Command::Claim(ClaimCommand::Revoke(args)) => {
            let signer = key_store.load(&args.output.key)?;
            let event = use_cases::revoke_claim(&SystemClock, &signer, args.claim_id)?;
            write_event(&event, args.output.out)?;
        }
        Command::Attest(AttestCommand::Issue(args)) => {
            let signer = key_store.load(&args.output.key)?;
            let event = use_cases::issue_attestation(
                &SystemClock,
                &signer,
                args.subject,
                args.claim,
                args.message,
            )?;
            write_event(&event, args.output.out)?;
        }
        Command::Attest(AttestCommand::Revoke(args)) => {
            let signer = key_store.load(&args.output.key)?;
            let event = use_cases::revoke_attestation(
                &SystemClock,
                &signer,
                args.subject,
                args.attestation_id,
            )?;
            write_event(&event, args.output.out)?;
        }
        Command::Event(EventCommand::Verify(args)) => {
            let event = read_event(&args.path)?;
            use_cases::verify_event(&event, &Ed25519Verifier)?;
            println!("ok");
        }
        Command::Event(EventCommand::Validate(args)) => {
            let event = read_event(&args.path)?;
            let url = format!("{}/events/validate", args.node.trim_end_matches('/'));
            let client = reqwest::blocking::Client::new();
            let response = client.post(url).json(&event).send()?.error_for_status()?;
            let validation: Value = response.json()?;
            println!("{}", serde_json::to_string_pretty(&validation)?);
        }
        Command::Event(EventCommand::Submit(args)) => {
            let event = read_event(&args.path)?;
            let url = format!("{}/events", args.node.trim_end_matches('/'));
            let client = reqwest::blocking::Client::new();
            let response = client.post(url).json(&event).send()?.error_for_status()?;
            let accepted: Value = response.json()?;
            println!("{}", serde_json::to_string_pretty(&accepted)?);
        }
        Command::Event(EventCommand::SubmitBatch(args)) => {
            let events = args
                .paths
                .iter()
                .map(read_event)
                .collect::<anyhow::Result<Vec<_>>>()?;
            let url = format!("{}/events/batch", args.node.trim_end_matches('/'));
            let client = reqwest::blocking::Client::new();
            let response = client.post(url).json(&events).send()?.error_for_status()?;
            let accepted: Value = response.json()?;
            println!("{}", serde_json::to_string_pretty(&accepted)?);
        }
        Command::Query(args) => match args.command {
            Some(QuerySubcommand::Claims(query)) => {
                let url = format!(
                    "{}/identities/{}/claims",
                    query.node.trim_end_matches('/'),
                    url_encode(&query.subject)
                );
                let claims: Value = reqwest::blocking::get(url)?.error_for_status()?.json()?;
                println!("{}", serde_json::to_string_pretty(&claims)?);
            }
            Some(QuerySubcommand::Attestations(query)) => {
                let url = format!(
                    "{}/identities/{}/attestations",
                    query.node.trim_end_matches('/'),
                    url_encode(&query.subject)
                );
                let attestations: Value =
                    reqwest::blocking::get(url)?.error_for_status()?.json()?;
                println!("{}", serde_json::to_string_pretty(&attestations)?);
            }
            None => {
                let args = args.events;
                let mut url = format!("{}/events", args.node.trim_end_matches('/'));
                let mut query = Vec::new();
                if let Some(subject) = args.subject {
                    query.push(("subject", subject));
                }
                if let Some(issuer) = args.issuer {
                    query.push(("issuer", issuer));
                }
                if let Some(kind) = args.kind {
                    query.push(("type", kind));
                }
                if let Some(after_created_at) = args.after_created_at {
                    query.push(("after_created_at", after_created_at.to_string()));
                }
                if let Some(after_id) = args.after_id {
                    query.push(("after_id", after_id));
                }
                if let Some(limit) = args.limit {
                    query.push(("limit", limit.to_string()));
                }
                if !query.is_empty() {
                    let encoded = query
                        .into_iter()
                        .map(|(k, v)| format!("{}={}", k, url_encode(&v)))
                        .collect::<Vec<_>>()
                        .join("&");
                    url.push('?');
                    url.push_str(&encoded);
                }
                let events: Value = reqwest::blocking::get(url)?.error_for_status()?.json()?;
                println!("{}", serde_json::to_string_pretty(&events)?);
            }
        },
    }

    Ok(())
}

fn read_event(path: &PathBuf) -> anyhow::Result<SignedEvent> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    Ok(serde_json::from_str(&raw)?)
}

fn write_event(event: &SignedEvent, out: Option<PathBuf>) -> anyhow::Result<()> {
    let raw = serde_json::to_string_pretty(event)?;
    match out {
        Some(path) => fs::write(&path, raw).with_context(|| format!("write {}", path.display()))?,
        None => println!("{}", raw),
    }
    Ok(())
}

fn url_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{:02X}", byte).chars().collect(),
        })
        .collect()
}
