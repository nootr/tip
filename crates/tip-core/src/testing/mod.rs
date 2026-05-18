use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    domain::{EventFilter, SignedEvent},
    ports::{EventStore, PeerSyncState, PeerSyncStateStore, StoreError},
};

#[derive(Default)]
pub struct InMemoryEventStore {
    events: RefCell<BTreeMap<String, SignedEvent>>,
    peer_sync_states: RefCell<BTreeMap<String, PeerSyncState>>,
}

impl InMemoryEventStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl PeerSyncStateStore for InMemoryEventStore {
    fn get_peer_sync_state(&self, peer_url: &str) -> Result<Option<PeerSyncState>, StoreError> {
        Ok(self.peer_sync_states.borrow().get(peer_url).cloned())
    }

    fn put_peer_sync_state(&self, state: &PeerSyncState) -> Result<(), StoreError> {
        self.peer_sync_states
            .borrow_mut()
            .insert(state.peer_url.clone(), state.clone());
        Ok(())
    }
}

impl EventStore for InMemoryEventStore {
    fn append(&self, event: &SignedEvent) -> Result<(), StoreError> {
        self.events
            .borrow_mut()
            .entry(event.id.clone())
            .or_insert_with(|| event.clone());
        Ok(())
    }

    fn get(&self, id: &str) -> Result<Option<SignedEvent>, StoreError> {
        Ok(self.events.borrow().get(id).cloned())
    }

    fn query(&self, filter: &EventFilter) -> Result<Vec<SignedEvent>, StoreError> {
        let mut events = self
            .events
            .borrow()
            .values()
            .filter(|event| {
                filter
                    .subject
                    .as_ref()
                    .map_or(true, |subject| subject == &event.unsigned.subject)
                    && filter
                        .issuer
                        .as_ref()
                        .map_or(true, |issuer| issuer == &event.unsigned.issuer)
                    && filter
                        .kind
                        .as_ref()
                        .map_or(true, |kind| kind == &event.unsigned.kind)
                    && matches_cursor(filter, event)
            })
            .cloned()
            .collect::<Vec<_>>();

        events.sort_by(|left, right| {
            left.unsigned
                .created_at
                .cmp(&right.unsigned.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        if let Some(limit) = filter.limit {
            events.truncate(limit);
        }

        Ok(events)
    }
}

fn matches_cursor(filter: &EventFilter, event: &SignedEvent) -> bool {
    match (filter.after_created_at, filter.after_id.as_ref()) {
        (Some(after_created_at), Some(after_id)) => {
            event.unsigned.created_at > after_created_at
                || (event.unsigned.created_at == after_created_at
                    && event.id.as_str() > after_id.as_str())
        }
        (Some(after_created_at), None) => event.unsigned.created_at > after_created_at,
        (None, _) => true,
    }
}
