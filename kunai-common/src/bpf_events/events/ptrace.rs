use crate::bpf_events::{Event, TaskInfo};

pub type PtraceEvent = Event<PtraceData>;

#[repr(C)]
pub struct PtraceData {
    pub mode: u32,
    pub target: TaskInfo,
}
