use rusqlite::{params, Connection, ToSql};
use tip_core::{
    domain::{EventFilter, EventType},
    ports::{EventStore, PeerSyncState, PeerSyncStateStore, StoreError},
    SignedEvent,
};

pub struct SqliteEventStore {
    connection: Connection,
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
                    last_created_at INTEGER NOT NULL,
                    last_id TEXT NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                "#,
            )
            .map_err(to_store_error)
    }
}

impl PeerSyncStateStore for SqliteEventStore {
    fn get_peer_sync_state(&self, peer_url: &str) -> Result<Option<PeerSyncState>, StoreError> {
        let mut statement = self
            .connection
            .prepare(
                "SELECT peer_url, last_created_at, last_id, updated_at FROM peer_sync_state WHERE peer_url = ?1",
            )
            .map_err(to_store_error)?;

        let mut rows = statement.query(params![peer_url]).map_err(to_store_error)?;
        if let Some(row) = rows.next().map_err(to_store_error)? {
            Ok(Some(PeerSyncState {
                peer_url: row.get(0).map_err(to_store_error)?,
                last_created_at: row.get(1).map_err(to_store_error)?,
                last_id: row.get(2).map_err(to_store_error)?,
                updated_at: row.get(3).map_err(to_store_error)?,
            }))
        } else {
            Ok(None)
        }
    }

    fn put_peer_sync_state(&self, state: &PeerSyncState) -> Result<(), StoreError> {
        self.connection
            .execute(
                r#"
                INSERT INTO peer_sync_state (peer_url, last_created_at, last_id, updated_at)
                VALUES (?1, ?2, ?3, ?4)
                ON CONFLICT(peer_url) DO UPDATE SET
                    last_created_at = excluded.last_created_at,
                    last_id = excluded.last_id,
                    updated_at = excluded.updated_at
                "#,
                params![
                    state.peer_url,
                    state.last_created_at,
                    state.last_id,
                    state.updated_at,
                ],
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
                INSERT OR IGNORE INTO events (id, type, subject, issuer, created_at, raw_json)
                VALUES (?1, ?2, ?3, ?4, ?5, ?6)
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
