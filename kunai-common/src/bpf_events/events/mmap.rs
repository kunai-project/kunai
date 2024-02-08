use crate::bpf_events::Event;
use crate::path::Path;

pub type MmapExecEvent = Event<MmapExecData>;

#[repr(C)]
pub struct MmapExecData {
    pub filename: Path,
}
