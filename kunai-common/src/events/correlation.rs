use super::{CloneEvent, MmapExecEvent, ScheduleEvent};
use crate::path::Path;
use crate::{buffer::Buffer, cgroup::Cgroup};

use super::{Event, ExecveEvent, Type, MAX_ARGV_SIZE};

/// CorrelationEvent is a very specific type of event
/// that is not supposed to be used in eBPF. It is
/// an event that is meant to forward as quick as possible
/// correlation information between the EventReader and the
/// EventProcessor. As a consequence it should hold any
/// information the EventProcessor would need to maintain
/// a fresh cache.

pub type CorrelationEvent = Event<CorrelationData>;

#[repr(C)]
// the data in this structure should always be serializable
// to a byte array, it should not contain any pointers
pub struct CorrelationData {
    //pub origin: Type,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub exe: Path,
    pub paths: [Option<Path>; 1],
    pub cgroup: Cgroup,
}

impl From<&ExecveEvent> for CorrelationEvent {
    fn from(value: &ExecveEvent) -> Self {
        Self {
            info: value.info,
            data: CorrelationData {
                argv: value.data.argv,
                exe: value.data.executable,
                paths: [Some(value.data.interpreter)],
                cgroup: value.data.cgroup,
            },
        }
        .switch_type(Type::Correlation)
    }
}

impl From<&CloneEvent> for CorrelationEvent {
    fn from(value: &CloneEvent) -> Self {
        Self {
            info: value.info,
            data: CorrelationData {
                argv: value.data.argv,
                exe: value.data.executable,
                paths: [None],
                cgroup: value.data.cgroup,
            },
        }
        .switch_type(Type::Correlation)
    }
}

impl From<&ScheduleEvent> for CorrelationEvent {
    fn from(value: &ScheduleEvent) -> Self {
        Self {
            info: value.info,
            data: CorrelationData {
                argv: value.data.argv,
                exe: value.data.exe,
                paths: [None],
                cgroup: value.data.cgroup,
            },
        }
        .switch_type(Type::Correlation)
    }
}

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
        .switch_type(Type::CacheHash)
    }
}

impl HashEvent {
    pub fn from_execve_with_path(event: &ExecveEvent, p: Path) -> Self {
        Self {
            info: event.info,
            data: p.into(),
        }
        .switch_type(Type::CacheHash)
    }

    pub fn all_from_execve(event: &ExecveEvent) -> Vec<HashEvent> {
        let mut v = vec![Self::from_execve_with_path(event, event.data.executable)];

        if event.data.interpreter != event.data.executable {
            v.push(Self::from_execve_with_path(event, event.data.interpreter));
        }

        v
    }
}
