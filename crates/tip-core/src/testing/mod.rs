use std::{cell::RefCell, collections::BTreeMap};

use crate::{
    domain::{EventFilter, SignedEvent},
    ports::{EventStore, StoreError},
};

#[derive(Default)]
pub struct InMemoryEventStore {
    events: RefCell<BTreeMap<String, SignedEvent>>,
}

impl InMemoryEventStore {
    pub fn new() -> Self {
        Self::default()
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
            })
            .cloned()
            .collect::<Vec<_>>();

        events.sort_by(|left, right| {
            left.unsigned
                .created_at
                .cmp(&right.unsigned.created_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(events)
    }
}
