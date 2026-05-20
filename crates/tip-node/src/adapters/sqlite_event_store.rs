use rusqlite::{params, Connection, OptionalExtension, ToSql};
use tip_core::{
    domain::{EventFilter, EventType},
    ports::{EventStore, PeerSyncState, PeerSyncStateStore, StoreError},
    SignedEvent,
};

pub struct SqliteEventStore {
    connection: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SequencedEvent {
    pub sequence: i64,
    pub event: SignedEvent,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct KnownPeer {
    pub url: String,
    pub claimed_node_public_key: Option<String>,
    pub name: Option<String>,
    pub source_peer_url: Option<String>,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub last_verified_at: Option<i64>,
    pub status: String,
    pub failure_count: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownPeerUpdate {
    pub url: String,
    pub claimed_node_public_key: Option<String>,
    pub name: Option<String>,
    pub source_peer_url: Option<String>,
    pub seen_at: i64,
    pub verified_at: Option<i64>,
    pub status: String,
    pub failed: bool,
}

impl SqliteEventStore {
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let connection = Connection::open(path).map_err(to_store_error)?;
        let store = Self { connection };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.connection
            .execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY NOT NULL,
                    sequence INTEGER NOT NULL,
                    type TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    raw_json TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_subject ON events(subject);
                CREATE INDEX IF NOT EXISTS idx_events_issuer ON events(issuer);
                CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);

                CREATE TABLE IF NOT EXISTS peer_sync_state (
                    peer_url TEXT PRIMARY KEY NOT NULL,
                    last_sequence INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS known_peers (
                    url TEXT PRIMARY KEY NOT NULL,
                    claimed_node_public_key TEXT,
                    name TEXT,
                    source_peer_url TEXT,
                    first_seen_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    last_verified_at INTEGER,
                    status TEXT NOT NULL,
                    failure_count INTEGER NOT NULL
                );
                "#,
            )
            .map_err(to_store_error)?;

        self.ensure_sequence_column()
    }

    fn ensure_sequence_column(&self) -> Result<(), StoreError> {
        let has_sequence = self
            .connection
            .prepare("PRAGMA table_info(events)")
            .map_err(to_store_error)?
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(to_store_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(to_store_error)?
            .iter()
            .any(|name| name == "sequence");

        if !has_sequence {
            self.connection
                .execute("ALTER TABLE events ADD COLUMN sequence INTEGER", [])
                .map_err(to_store_error)?;
            self.connection
                .execute(
                    "UPDATE events SET sequence = rowid WHERE sequence IS NULL",
                    [],
                )
                .map_err(to_store_error)?;
        }

        self.connection
            .execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS idx_events_sequence ON events(sequence)",
                [],
            )
            .map_err(to_store_error)?;

        Ok(())
    }

    pub fn upsert_known_peer(&self, update: &KnownPeerUpdate) -> Result<(), StoreError> {
        let existing = self
            .connection
            .query_row(
                "SELECT first_seen_at, failure_count FROM known_peers WHERE url = ?1",
                params![update.url],
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(to_store_error)?;
        let (first_seen_at, existing_failures) = existing.unwrap_or((update.seen_at, 0));
        let failure_count = if update.failed {
            existing_failures + 1
        } else {
            0
        };

        self.connection
            .execute(
                r#"
                INSERT INTO known_peers (
                    url,
                    claimed_node_public_key,
                    name,
                    source_peer_url,
                    first_seen_at,
                    last_seen_at,
                    last_verified_at,
                    status,
                    failure_count
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
                ON CONFLICT(url) DO UPDATE SET
                    claimed_node_public_key = excluded.claimed_node_public_key,
                    name = COALESCE(excluded.name, known_peers.name),
                    source_peer_url = COALESCE(excluded.source_peer_url, known_peers.source_peer_url),
                    last_seen_at = excluded.last_seen_at,
                    last_verified_at = excluded.last_verified_at,
                    status = excluded.status,
                    failure_count = excluded.failure_count
                "#,
                params![
                    update.url,
                    update.claimed_node_public_key,
                    update.name,
                    update.source_peer_url,
                    first_seen_at,
                    update.seen_at,
                    update.verified_at,
                    update.status,
                    failure_count,
                ],
            )
            .map_err(to_store_error)?;
        Ok(())
    }

    pub fn list_known_peers(&self) -> Result<Vec<KnownPeer>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT
                    url,
                    claimed_node_public_key,
                    name,
                    source_peer_url,
                    first_seen_at,
                    last_seen_at,
                    last_verified_at,
                    status,
                    failure_count
                FROM known_peers
                ORDER BY url ASC
                "#,
            )
            .map_err(to_store_error)?;
        let rows = statement
            .query_map([], |row| {
                Ok(KnownPeer {
                    url: row.get(0)?,
                    claimed_node_public_key: row.get(1)?,
                    name: row.get(2)?,
                    source_peer_url: row.get(3)?,
                    first_seen_at: row.get(4)?,
                    last_seen_at: row.get(5)?,
                    last_verified_at: row.get(6)?,
                    status: row.get(7)?,
                    failure_count: row.get(8)?,
                })
            })
            .map_err(to_store_error)?;

        let mut peers = Vec::new();
        for row in rows {
            peers.push(row.map_err(to_store_error)?);
        }
        Ok(peers)
    }

    pub fn list_after_sequence(
        &self,
        after_sequence: i64,
        limit: usize,
    ) -> Result<Vec<SequencedEvent>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT sequence, raw_json FROM events WHERE sequence > ?1 ORDER BY sequence ASC LIMIT ?2",
            )
            .map_err(to_store_error)?;
        let rows = statement
            .query_map(params![after_sequence, limit as i64], |row| {
                Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(to_store_error)?;

        let mut events = Vec::new();
        for row in rows {
            let (sequence, raw) = row.map_err(to_store_error)?;
            events.push(SequencedEvent {
                sequence,
                event: serde_json::from_str(&raw).map_err(to_store_error)?,
            });
        }
        Ok(events)
    }
}

impl PeerSyncStateStore for SqliteEventStore {
    fn get_peer_sync_state(&self, peer_url: &str) -> Result<Option<PeerSyncState>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT peer_url, last_sequence, updated_at FROM peer_sync_state WHERE peer_url = ?1",
            )
            .map_err(to_store_error)?;

        let mut rows = statement.query(params![peer_url]).map_err(to_store_error)?;
        if let Some(row) = rows.next().map_err(to_store_error)? {
            Ok(Some(PeerSyncState {
                peer_url: row.get(0).map_err(to_store_error)?,
                last_sequence: row.get(1).map_err(to_store_error)?,
                updated_at: row.get(2).map_err(to_store_error)?,
            }))
        } else {
            Ok(None)
        }
    }

    fn put_peer_sync_state(&self, state: &PeerSyncState) -> Result<(), StoreError> {
        self.connection
            .execute(
                r#"
                INSERT INTO peer_sync_state (peer_url, last_sequence, updated_at)
                VALUES (?1, ?2, ?3)
                ON CONFLICT(peer_url) DO UPDATE SET
                    last_sequence = excluded.last_sequence,
                    updated_at = excluded.updated_at
                "#,
                params![state.peer_url, state.last_sequence, state.updated_at,],
            )
            .map_err(to_store_error)?;
        Ok(())
    }
}

impl EventStore for SqliteEventStore {
    fn append(&self, event: &SignedEvent) -> Result<(), StoreError> {
        let raw_json = serde_json::to_string(event).map_err(to_store_error)?;
        self.connection
            .execute(
                r#"
                INSERT OR IGNORE INTO events (id, sequence, type, subject, issuer, created_at, raw_json)
                VALUES (?1, (SELECT COALESCE(MAX(sequence), 0) + 1 FROM events), ?2, ?3, ?4, ?5, ?6)
                "#,
                params![
                    event.id,
                    event.unsigned.kind.to_string(),
                    event.unsigned.subject,
                    event.unsigned.issuer,
                    event.unsigned.created_at,
                    raw_json,
                ],
            )
            .map_err(to_store_error)?;
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<SignedEvent>, StoreError> {
        let mut statement = self
            .connection
            .prepare("SELECT raw_json FROM events WHERE id = ?1")
            .map_err(to_store_error)?;

        let mut rows = statement.query(params![id]).map_err(to_store_error)?;
        if let Some(row) = rows.next().map_err(to_store_error)? {
            let raw: String = row.get(0).map_err(to_store_error)?;
            let event = serde_json::from_str(&raw).map_err(to_store_error)?;
            Ok(Some(event))
        } else {
            Ok(None)
        }
    }

    fn query(&self, filter: &EventFilter) -> Result<Vec<SignedEvent>, StoreError> {
        let mut sql = "SELECT raw_json FROM events WHERE 1=1".to_string();
        let mut values: Vec<Box<dyn ToSql>> = Vec::new();

        if let Some(subject) = &filter.subject {
            sql.push_str(" AND subject = ?");
            values.push(Box::new(subject.clone()));
        }
        if let Some(issuer) = &filter.issuer {
            sql.push_str(" AND issuer = ?");
            values.push(Box::new(issuer.clone()));
        }
        if let Some(kind) = &filter.kind {
            sql.push_str(" AND type = ?");
            values.push(Box::new(kind.to_string()));
        }
        match (filter.after_created_at, filter.after_id.as_ref()) {
            (Some(after_created_at), Some(after_id)) => {
                sql.push_str(" AND (created_at > ? OR (created_at = ? AND id > ?))");
                values.push(Box::new(after_created_at));
                values.push(Box::new(after_created_at));
                values.push(Box::new(after_id.clone()));
            }
            (Some(after_created_at), None) => {
                sql.push_str(" AND created_at > ?");
                values.push(Box::new(after_created_at));
            }
            (None, _) => {}
        }
        sql.push_str(" ORDER BY created_at ASC, id ASC LIMIT ?");
        values.push(Box::new(filter.limit.unwrap_or(500) as i64));

        let mut statement = self.connection.prepare(&sql).map_err(to_store_error)?;
        let value_refs: Vec<&dyn ToSql> = values.iter().map(|value| value.as_ref()).collect();
        let rows = statement
            .query_map(value_refs.as_slice(), |row| row.get::<_, String>(0))
            .map_err(to_store_error)?;

        let mut events = Vec::new();
        for row in rows {
            let raw = row.map_err(to_store_error)?;
            events.push(serde_json::from_str(&raw).map_err(to_store_error)?);
        }
        Ok(events)
    }
}

fn to_store_error(error: impl std::fmt::Display) -> StoreError {
    StoreError::Failure(error.to_string())
}

#[allow(dead_code)]
fn _assert_event_type_is_used(_: EventType) {}
