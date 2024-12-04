use std::io;

use chrono::{DateTime, Utc};
use kunai_common::{
    bpf_events::{self, EventInfo, TaskInfo},
    uuid::ProcUuid,
};
use thiserror::Error;

use crate::{
    containers::Container,
    util::{
        account::{Group, User},
        get_clk_tck,
    },
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ProcKey {
    start_time_sec: u64,
    // this is the userland process ID in kernel
    // it corresponds to the task's tgid (task group id)
    pid: u32,
}

impl From<ProcUuid> for ProcKey {
    #[inline(always)]
    fn from(value: ProcUuid) -> Self {
        // in task_struct start_time has a higher resolution so we need to scale it
        // down in order to have a comparable value with the procfs one
        Self {
            start_time_sec: value.leader_start_time_ns / 1_000_000_000,
            pid: value.tgid,
        }
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("procfs: {0}")]
    ProcFs(#[from] procfs::ProcError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
}

impl TryFrom<&procfs::process::Process> for ProcKey {
    type Error = KeyError;
    #[inline(always)]
    fn try_from(p: &procfs::process::Process) -> Result<Self, Self::Error> {
        let stat = p.stat()?;
        // panic here if we cannot get CLK_TCK
        let clk_tck = get_clk_tck()? as u64;

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
pub struct TaskAdditionalInfo {
    pub user: Option<User>,
    pub group: Option<Group>,
}

#[derive(Default, Debug, Clone)]
pub struct AdditionalInfo {
    pub host: HostInfo,
    pub container: Option<ContainerInfo>,
    pub task: TaskAdditionalInfo,
    pub parent: TaskAdditionalInfo,
}

#[derive(Default, Debug, Clone)]
pub struct StdEventInfo {
    pub bpf: bpf_events::EventInfo,
    pub additional: AdditionalInfo,
    pub utc_timestamp: DateTime<Utc>,
}

impl StdEventInfo {
    #[inline(always)]
    pub fn task_info(&self) -> &TaskInfo {
        &self.bpf.process
    }

    #[inline(always)]
    pub fn parent_info(&self) -> &TaskInfo {
        &self.bpf.parent
    }

    #[inline(always)]
    pub fn process_key(&self) -> ProcKey {
        ProcKey::from(self.task_info().tg_uuid)
    }

    #[inline(always)]
    pub fn parent_key(&self) -> ProcKey {
        ProcKey::from(self.parent_info().tg_uuid)
    }

    #[inline]
    pub fn from_bpf(mut info: EventInfo, rand: u32) -> Self {
        // we set the random part needed to generate uuids for events
        info.set_uuid_random(rand);

        StdEventInfo {
            bpf: info,
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
