use crate::bpf_events::Event;

use crate::buffer::Buffer;
use crate::cgroup::Cgroup;
use crate::path::Path;

pub type ScheduleEvent = Event<ScheduleData>;

pub struct ScheduleData {
    pub exe: Path,
    pub argv: Buffer<512>,
    pub cgroup: Cgroup,
}
