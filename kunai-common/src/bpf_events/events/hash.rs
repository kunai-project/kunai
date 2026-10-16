use super::{ExecveEvent, MmapExecEvent};
use crate::bpf_events::{Event, EventInfo, Type};
use crate::path::Path;

pub type HashEvent = Event<HashData>;

pub struct HashData {
    pub path: Path,
}

impl From<Path> for HashData {
    fn from(value: Path) -> Self {
        Self { path: value }
    }
}

impl From<&MmapExecEvent> for HashEvent {
    fn from(value: &MmapExecEvent) -> Self {
        Self {
            info: value.info,
            data: value.data.filename.into(),
        }
        .with_type(Type::CacheHash)
    }
}

impl HashEvent {
    pub fn new(info: EventInfo, p: Path) -> Self {
        Self {
            info,
            data: p.into(),
        }
        .with_type(Type::CacheHash)
    }

    pub fn all_from_execve(event: &ExecveEvent) -> Vec<HashEvent> {
        let mut v = vec![Self::new(event.info, event.data.executable)];

        if event.data.interpreter != event.data.executable {
            v.push(Self::new(event.info, event.data.interpreter));
        }

        v
    }
}
