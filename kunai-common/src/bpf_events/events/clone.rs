use crate::{bpf_events::Event, buffer::Buffer, cgroup::Cgroup, path::Path};

use super::MAX_ARGV_SIZE;

pub type CloneEvent = Event<CloneData>;

#[repr(C)]
pub struct CloneData {
    pub flags: u64,
    pub executable: Path,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub cgroup: Cgroup,
}
