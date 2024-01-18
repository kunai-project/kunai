use chrono::{DateTime, Utc};
use kunai_common::{
    bpf_events::{self, EventInfo},
    uuid::TaskUuid,
};

use crate::util::get_clk_tck;

#[derive(Debug, Clone, Copy)]
pub struct ProcFsTaskInfo {
    pid: i32,
    uuid: TaskUuid,
}

impl ProcFsTaskInfo {
    pub fn new(start_time_clk_tck: u64, random: u32, pid: i32) -> Self {
        // starttime in procfs is measured in tick count so we need to convert it
        let clk_tck = get_clk_tck() as u64;

        Self {
            pid,
            uuid: TaskUuid::new(
                // convert time to the same scale as starttime in task_struct
                start_time_clk_tck * 1_000_000_000 / clk_tck,
                random,
                pid as u32,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ProcFsInfo {
    task: ProcFsTaskInfo,
    parent: Option<ProcFsTaskInfo>,
}

impl ProcFsInfo {
    pub fn new(task: ProcFsTaskInfo, parent: Option<ProcFsTaskInfo>) -> Self {
        ProcFsInfo { task, parent }
    }
}

#[derive(Debug, Clone)]
pub enum CorrInfo {
    ProcFs(ProcFsInfo),
    Event(StdEventInfo),
}

impl From<ProcFsInfo> for CorrInfo {
    fn from(value: ProcFsInfo) -> Self {
        Self::ProcFs(value)
    }
}

impl CorrInfo {
    fn corr_key(tuuid: TaskUuid) -> u128 {
        // in task_struct start_time has a higher resolution so we need to scale it
        // down in order to have a comparable value with the procfs one
        let start_time_sec = tuuid.start_time_ns / 1_000_000_000;
        TaskUuid::new(start_time_sec, tuuid.random, tuuid.pid).into()
    }

    #[inline]
    pub fn pid(&self) -> i32 {
        match self {
            Self::ProcFs(pi) => pi.task.pid,
            Self::Event(si) => si.info.process.tgid,
        }
    }

    #[inline]
    pub fn correlation_key(&self) -> u128 {
        match self {
            Self::ProcFs(pi) => Self::corr_key(pi.task.uuid),
            Self::Event(si) => Self::corr_key(si.info.process.tg_uuid),
        }
    }

    #[inline]
    pub fn parent_correlation_key(&self) -> Option<u128> {
        match self {
            Self::ProcFs(pi) => Some(Self::corr_key(pi.parent?.uuid)),
            Self::Event(si) => Some(Self::corr_key(si.info.parent.tg_uuid)),
        }
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
    pub ty: Option<String>,
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
    pub fn correlation_key(&self) -> u128 {
        CorrInfo::corr_key(self.info.process.tg_uuid)
    }

    #[inline(always)]
    pub fn parent_correlation_key(&self) -> u128 {
        CorrInfo::corr_key(self.info.parent.tg_uuid)
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
