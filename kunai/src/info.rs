use chrono::{DateTime, SecondsFormat, Utc};
use json::{object, JsonValue};
use kunai_common::{
    events::{self, EventInfo},
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
pub struct AdditionalFields {
    pub hostname: String,
    pub container: Option<String>,
}

#[derive(Default, Debug, Clone)]
pub struct StdEventInfo {
    pub info: events::EventInfo,
    pub additional: AdditionalFields,
    pub utc_timestamp: DateTime<Utc>,
}

impl StdEventInfo {
    pub fn correlation_key(&self) -> u128 {
        CorrInfo::corr_key(self.info.process.tg_uuid)
    }

    pub fn parent_correlation_key(&self) -> u128 {
        CorrInfo::corr_key(self.info.parent.tg_uuid)
    }

    pub fn with_event_info(mut info: EventInfo, rand: u32) -> Self {
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

    pub fn with_additional_fields(mut self, fields: AdditionalFields) -> Self {
        self.additional = fields;
        self
    }
}

impl From<StdEventInfo> for JsonValue {
    fn from(value: StdEventInfo) -> Self {
        Self::from(&value)
    }
}

impl From<&StdEventInfo> for JsonValue {
    fn from(i: &StdEventInfo) -> Self {
        let ts = i.utc_timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let info = i.info;

        object! {
            // host information
            host: object!{
                hostname: i.additional.hostname.as_str(),
                container: i.additional.container.clone(),
            },
            // event information
            event: object!{
                // this field can be used by other tools to identify that event comes from kunai
                source: "kunai",
                id: info.etype.id(),
                name: info.etype.as_str(),
                uuid: info.uuid.into_uuid().hyphenated().to_string(),
                batch: info.batch,
            },
            // current task
            task: object!{
                name: info.process.comm_string(),
                // start_time
                // start_time: info.process.start_time,
                // task pid
                pid: info.process.pid,
                // task group id -> equals to pid when single threaded
                tgid: info.process.tgid,
                // group uuid
                guuid: info.process.tg_uuid.into_uuid().hyphenated().to_string(),
                uid: info.process.uid,
                gid: info.process.gid,
                namespaces: object!{
                    mnt: info.process.namespaces.mnt,
                },
            },
            // parent task
            parent_task: object!{
                name: info.parent.comm_string(),
                // start_time
                // start_time: info.parent.start_time,
                // task pid
                pid: info.parent.pid,
                // task group id -> equals to pid when single threaded
                tgid: info.parent.tgid,
                // group uuid
                guuid: info.parent.tg_uuid.into_uuid().hyphenated().to_string(),
                uid: info.parent.uid,
                gid: info.parent.gid,
                namespaces: object!{
                    mnt: info.process.namespaces.mnt,
                },
            },
            utc_time: ts,
        }
    }
}
