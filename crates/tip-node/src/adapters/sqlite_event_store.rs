use rusqlite::{params, Connection};
use tip_core::{
    domain::{EventFilter, EventType},
    ports::{EventStore, StoreError},
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
                "#,
            )
            .map_err(to_store_error)
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
        let mut values: Vec<String> = Vec::new();

        if let Some(subject) = &filter.subject {
            sql.push_str(" AND subject = ?");
            values.push(subject.clone());
        }
        if let Some(issuer) = &filter.issuer {
            sql.push_str(" AND issuer = ?");
            values.push(issuer.clone());
        }
        if let Some(kind) = &filter.kind {
            sql.push_str(" AND type = ?");
            values.push(kind.to_string());
        }
        sql.push_str(" ORDER BY created_at ASC, id ASC LIMIT 500");

        let mut statement = self.connection.prepare(&sql).map_err(to_store_error)?;
        let value_refs: Vec<&dyn rusqlite::ToSql> =
            values.iter().map(|v| v as &dyn rusqlite::ToSql).collect();
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
