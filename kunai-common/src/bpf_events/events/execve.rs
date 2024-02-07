use crate::bpf_events::Event;
use crate::buffer::Buffer;
use crate::cgroup::Cgroup;
use crate::path::Path;

pub const MAX_ARGV_SIZE: usize = 512;

pub type ExecveEvent = Event<ExecveData>;

#[repr(C)]
pub struct ExecveData {
    pub executable: Path,
    pub interpreter: Path,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub cgroup: Cgroup,
    pub rc: i32,
}
