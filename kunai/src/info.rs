use chrono::{DateTime, Utc};
use kunai_common::{
    bpf_events::{self, EventInfo},
    uuid::TaskUuid,
};

use crate::{containers::Container, util::get_clk_tck};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct TaskKey {
    start_time_sec: u64,
    pid: u32,
}

impl From<TaskUuid> for TaskKey {
    fn from(value: TaskUuid) -> Self {
        // in task_struct start_time has a higher resolution so we need to scale it
        // down in order to have a comparable value with the procfs one
        Self {
            start_time_sec: value.start_time_ns / 1_000_000_000,
            pid: value.pid,
        }
    }
}

impl TryFrom<&procfs::process::Process> for TaskKey {
    type Error = procfs::ProcError;
    fn try_from(p: &procfs::process::Process) -> Result<Self, Self::Error> {
        let stat = p.stat()?;
        let clk_tck = get_clk_tck() as u64;

        Ok(Self {
            start_time_sec: stat.starttime / clk_tck,
            pid: p.pid as u32,
        })
    }
}

#[derive(Default, Debug, Clone)]
pub struct HostInfo {
    pub name: String,
    pub uuid: uuid::Uuid,
}

#[derive(Default, Debug, Clone)]
pub struct ContainerInfo {
    pub name: String,
    pub ty: Option<Container>,
}

#[derive(Default, Debug, Clone)]
pub struct AdditionalInfo {
    pub host: HostInfo,
    pub container: Option<ContainerInfo>,
}

#[derive(Default, Debug, Clone)]
pub struct StdEventInfo {
    pub info: bpf_events::EventInfo,
    pub additional: AdditionalInfo,
    pub utc_timestamp: DateTime<Utc>,
}

impl StdEventInfo {
    #[inline(always)]
    pub fn task_key(&self) -> TaskKey {
        TaskKey::from(self.info.process.tg_uuid)
    }

    #[inline(always)]
    pub fn parent_key(&self) -> TaskKey {
        TaskKey::from(self.info.parent.tg_uuid)
    }

    #[inline]
    pub fn from_bpf(mut info: EventInfo, rand: u32) -> Self {
        // we set the random part needed to generate uuids for events
        info.set_uuid_random(rand);

        StdEventInfo {
            info,
            // on older kernels bpf_ktime_get_boot_ns() is not available so it is not
            // easy to compute correct event timestamp from eBPF so utc_timestamp is
            // the time at which the event is processed.
            utc_timestamp: chrono::Utc::now(),
            ..Default::default()
        }
    }

    #[inline]
    pub fn with_additional_info(mut self, info: AdditionalInfo) -> Self {
        self.additional = info;
        self
    }
}
