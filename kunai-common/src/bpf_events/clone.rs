use crate::{buffer::Buffer, cgroup::Cgroup, path::Path};

use super::{Event, MAX_ARGV_SIZE};

pub type CloneEvent = Event<CloneData>;

#[repr(C)]
pub struct CloneData {
    pub flags: u64,
    pub executable: Path,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub cgroup: Cgroup,
}
