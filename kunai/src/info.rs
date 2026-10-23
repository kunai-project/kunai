use std::{io, sync::Arc};

use chrono::{DateTime, Utc};
use kunai_common::{
    bpf_events::{self, EventInfo, TaskInfo, Type},
    user_ns::UserNs,
    uuid::ProcUuid,
};
use thiserror::Error;

use crate::{
    containers::Container,
    util::{
        account::{Groups, Users},
        get_clk_tck,
    },
};

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct ProcKey {
    start_time_sec: u64,
    // this is the userland process ID in kernel
    // it corresponds to the task's tgid (task group id)
    pid: i32,
}

impl ProcKey {
    /// Key of the process leader (tid == tgid), which may have exited while
    /// the process lives on.
    pub fn to_thread_leader_key(self) -> TaskKey {
        TaskKey {
            start_time_sec: self.start_time_sec,
            pid: self.pid,
        }
    }

    /// Builds the key of the process identified by `value`.
    ///
    /// The leader start time is truncated from nanoseconds to seconds, so
    /// the key compares equal to one built from procfs, whose start time
    /// is in `CLK_TCK` ticks.
    pub fn from_proc_uuid(value: ProcUuid) -> Self {
        Self {
            start_time_sec: value.leader_start_time_ns / 1_000_000_000,
            pid: value.tgid,
        }
    }
}

impl From<&TaskInfo> for ProcKey {
    fn from(ti: &TaskInfo) -> Self {
        Self::from_proc_uuid(ti.tg_uuid)
    }
}

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("procfs: {0}")]
    ProcFs(#[from] procfs::ProcError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("CLK_TCK is 0, cannot scale ticks to seconds")]
    InvalidClkTck,
}

/// Scales a `starttime` expressed in `CLK_TCK` ticks (as reported by procfs) down
/// to seconds, the unit [ProcKey] and [TaskKey] compare on.
fn start_time_sec_from_ticks(ticks: u64) -> Result<u64, KeyError> {
    let clk_tck = get_clk_tck()? as u64;
    ticks.checked_div(clk_tck).ok_or(KeyError::InvalidClkTck)
}

impl TryFrom<&procfs::process::Process> for ProcKey {
    type Error = KeyError;
    fn try_from(p: &procfs::process::Process) -> Result<Self, Self::Error> {
        let stat = p.stat()?;

        Ok(Self {
            start_time_sec: start_time_sec_from_ticks(stat.starttime)?,
            pid: p.pid,
        })
    }
}

/// Same idea as [ProcKey] but identifies an individual task (thread) rather
/// than a process, so it survives pid reuse: a dead thread's pid being
/// recycled by an unrelated task will not collide with a stale entry, since
/// the recycled task has a different start time.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct TaskKey {
    start_time_sec: u64,
    pid: i32,
}

impl TaskKey {
    pub fn start_time_sec(&self) -> u64 {
        self.start_time_sec
    }
}

impl From<&TaskInfo> for TaskKey {
    fn from(ti: &TaskInfo) -> Self {
        // same reasoning as ProcKey: task_struct start_time has a higher
        // resolution than procfs, scale it down to be comparable
        Self {
            start_time_sec: ti.start_time / 1_000_000_000,
            pid: ti.pid,
        }
    }
}

impl TryFrom<&procfs::process::Process> for TaskKey {
    type Error = KeyError;
    fn try_from(p: &procfs::process::Process) -> Result<Self, Self::Error> {
        let stat = p.stat()?;

        Ok(Self {
            start_time_sec: start_time_sec_from_ticks(stat.starttime)?,
            pid: p.pid,
        })
    }
}

impl TryFrom<&procfs::process::Task> for TaskKey {
    type Error = KeyError;
    fn try_from(t: &procfs::process::Task) -> Result<Self, Self::Error> {
        let stat = t.stat()?;

        Ok(Self {
            start_time_sec: start_time_sec_from_ticks(stat.starttime)?,
            pid: t.tid,
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

/// Holds the user and group tables of the mount namespace a task lives in and
/// of the host, and the task's user namespace, so that both namespace and host
/// ids can be resolved. Sharing them behind an [Arc] keeps this structure owned
/// (no lifetime tied to the cache) while avoiding any copy.
#[derive(Default, Debug, Clone)]
pub struct TaskAdditionalInfo {
    pub users: Option<Arc<Users>>,
    pub groups: Option<Arc<Groups>>,
    pub host_users: Option<Arc<Users>>,
    pub host_groups: Option<Arc<Groups>>,
    pub user_ns: Option<Arc<UserNs>>,
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
    pub fn task_info(&self) -> &TaskInfo {
        &self.bpf.process
    }

    pub fn parent_info(&self) -> &TaskInfo {
        &self.bpf.parent
    }

    pub fn process_key(&self) -> ProcKey {
        ProcKey::from(self.task_info())
    }

    pub fn parent_key(&self) -> ProcKey {
        ProcKey::from(self.parent_info())
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

    #[inline]
    pub fn override_type(&mut self, ty: Type) {
        self.bpf.etype = ty
    }
}
