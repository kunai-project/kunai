use aya::Pod;
use core::fmt::{Debug, Display};
use core::str::FromStr;
use serde::{Deserialize, Serialize};

use thiserror::Error;

use crate::bpf_events::{CorrelationEvent, HashEvent};

use super::{
    BpfProgLoadEvent, BpfSocketFilterEvent, CloneEvent, ConnectEvent, DnsQueryEvent, ErrorEvent,
    Event, EventInfo, ExecveEvent, ExitEvent, FileEvent, FileRenameEvent, InitModuleEvent,
    IoUringSqeEvent, KillEvent, LogEvent, LossEvent, MmapExecEvent, MprotectEvent, PrctlEvent,
    PtraceEvent, ScheduleEvent, SendEntropyEvent, SysCoreResumeEvent, Type, UnlinkEvent,
};

unsafe impl Pod for Type {}

impl Display for Type {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Serialize for Type {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Type {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Type::from_str(&s).map_err(serde::de::Error::custom)
    }
}

#[derive(Error, Debug)]
pub enum DecoderError {
    #[error("not enough bytes to decode")]
    NotEnoughBytes,
    #[error("size of buffer does not match with size of event")]
    SizeDontMatch,
    #[error("unsupported event type: {0}")]
    Unsupported(Type),
}

pub enum EbpfEvent {
    Execve(Box<ExecveEvent>),
    Exit(Box<ExitEvent>),
    Clone(Box<CloneEvent>),
    Prctl(Box<PrctlEvent>),
    Kill(Box<KillEvent>),
    Ptrace(Box<PtraceEvent>),
    InitModule(Box<InitModuleEvent>),
    BpfProgLoad(Box<BpfProgLoadEvent>),
    BpfSocketFilter(Box<BpfSocketFilterEvent>),
    Mprotect(Box<MprotectEvent>),
    MmapExec(Box<MmapExecEvent>),
    Connect(Box<ConnectEvent>),
    DnsQuery(Box<DnsQueryEvent>),
    SendEntropy(Box<SendEntropyEvent>),
    File(Box<FileEvent>),
    FileRename(Box<FileRenameEvent>),
    Unlink(Box<UnlinkEvent>),
    IoUringSqe(Box<IoUringSqeEvent>),
    // not configurable but filterable
    Error(Box<ErrorEvent>),
    Loss(Box<LossEvent>),
    // specific events
    Start(Box<Event<()>>),
    Schedule(Box<ScheduleEvent>),
    Correlation(Box<CorrelationEvent>),
    Hash(Box<HashEvent>),
    Log(Box<LogEvent>),
    SysCoreResume(Box<SysCoreResumeEvent>),
}

impl From<HashEvent> for EbpfEvent {
    fn from(value: HashEvent) -> Self {
        Self::Hash(Box::new(value))
    }
}

impl From<LossEvent> for EbpfEvent {
    fn from(value: LossEvent) -> Self {
        Self::Loss(Box::new(value))
    }
}

impl EbpfEvent {
    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecoderError> {
        // event content must be at least the size of EventInfo
        if bytes.len() < core::mem::size_of::<EventInfo>() {
            return Err(DecoderError::NotEnoughBytes);
        }

        let info = unsafe {
            &(*(bytes[0..core::mem::size_of::<EventInfo>()].as_ptr() as *const EventInfo))
        };

        macro_rules! decode {
            ($src: ident) => {{
                if bytes.len() < $src::size_of() {
                    return Err(DecoderError::SizeDontMatch);
                }

                let mut buf = [0u8; $src::size_of()];
                buf.copy_from_slice(&bytes[0..$src::size_of()]);
                let e: $src = unsafe { core::mem::transmute::<[u8; $src::size_of()], $src>(buf) };
                e
            }};
        }

        // check that we didn't send uninitialized events
        debug_assert!(info.etype != Type::Unknown, "received unknown event");

        match info.etype {
            // here ExecveScript cannot exist
            Type::Execve | Type::ExecveScript => {
                let mut execve_event = decode!(ExecveEvent);
                if execve_event.data.interpreter != execve_event.data.executable {
                    execve_event.info.etype = Type::ExecveScript
                }
                Ok(Self::Execve(Box::new(execve_event)))
            }
            Type::Exit | Type::ExitGroup => Ok(Self::Exit(Box::new(decode!(ExitEvent)))),
            Type::Clone => Ok(Self::Clone(Box::new(decode!(CloneEvent)))),
            Type::Prctl => Ok(Self::Prctl(Box::new(decode!(PrctlEvent)))),
            Type::Kill => Ok(Self::Kill(Box::new(decode!(KillEvent)))),
            Type::Ptrace => Ok(Self::Ptrace(Box::new(decode!(PtraceEvent)))),
            Type::InitModule => Ok(Self::InitModule(Box::new(decode!(InitModuleEvent)))),
            Type::BpfProgLoad => Ok(Self::BpfProgLoad(Box::new(decode!(BpfProgLoadEvent)))),
            Type::BpfSocketFilter => Ok(Self::BpfSocketFilter(Box::new(decode!(
                BpfSocketFilterEvent
            )))),
            Type::MprotectExec => Ok(Self::Mprotect(Box::new(decode!(MprotectEvent)))),
            Type::MmapExec => Ok(Self::MmapExec(Box::new(decode!(MmapExecEvent)))),
            Type::Connect => Ok(Self::Connect(Box::new(decode!(ConnectEvent)))),
            Type::DnsQuery => Ok(Self::DnsQuery(Box::new(decode!(DnsQueryEvent)))),
            Type::SendData => Ok(Self::SendEntropy(Box::new(decode!(SendEntropyEvent)))),
            Type::Read
            | Type::ReadConfig
            | Type::Write
            | Type::WriteConfig
            | Type::WriteClose
            | Type::FileCreate => Ok(Self::File(Box::new(decode!(FileEvent)))),
            Type::FileRename => Ok(Self::FileRename(Box::new(decode!(FileRenameEvent)))),
            Type::FileUnlink => Ok(Self::Unlink(Box::new(decode!(UnlinkEvent)))),
            Type::IoUringSqe => Ok(Self::IoUringSqe(Box::new(decode!(IoUringSqeEvent)))),
            // not configurable events
            Type::TaskSched => Ok(Self::Schedule(Box::new(decode!(ScheduleEvent)))),
            Type::Correlation => Ok(Self::Correlation(Box::new(decode!(CorrelationEvent)))),
            Type::CacheHash => Ok(Self::Hash(Box::new(decode!(HashEvent)))),
            Type::Log => Ok(Self::Log(Box::new(decode!(LogEvent)))),
            Type::Loss => Ok(Self::Loss(Box::new(decode!(LossEvent)))),
            Type::Error => Ok(Self::Error(Box::new(decode!(ErrorEvent)))),
            Type::SyscoreResume => Ok(Self::SysCoreResume(Box::new(decode!(SysCoreResumeEvent)))),
            Type::EndConfigurable | Type::Max | Type::Start | Type::FileScan | Type::Unknown => {
                Err(DecoderError::Unsupported(info.etype))
            }
        }
    }

    #[inline(always)]
    pub fn ty(&self) -> Type {
        self.info().etype
    }

    #[inline(always)]
    pub fn info(&self) -> &EventInfo {
        match self {
            Self::Execve(e) => &e.info,
            Self::Exit(e) => &e.info,
            Self::Clone(e) => &e.info,
            Self::Prctl(e) => &e.info,
            Self::Kill(e) => &e.info,
            Self::Ptrace(e) => &e.info,
            Self::InitModule(e) => &e.info,
            Self::BpfProgLoad(e) => &e.info,
            Self::BpfSocketFilter(e) => &e.info,
            Self::Mprotect(e) => &e.info,
            Self::MmapExec(e) => &e.info,
            Self::Connect(e) => &e.info,
            Self::DnsQuery(e) => &e.info,
            Self::SendEntropy(e) => &e.info,
            Self::File(e) => &e.info,
            Self::FileRename(e) => &e.info,
            Self::Unlink(e) => &e.info,
            Self::IoUringSqe(e) => &e.info,
            Self::Error(e) => &e.info,
            Self::Loss(e) => &e.info,
            Self::Start(e) => &e.info,
            Self::Schedule(e) => &e.info,
            Self::Correlation(e) => &e.info,
            Self::Hash(e) => &e.info,
            Self::Log(e) => &e.info,
            Self::SysCoreResume(e) => &e.info,
        }
    }

    #[inline(always)]
    pub fn info_mut(&mut self) -> &mut EventInfo {
        match self {
            Self::Execve(e) => &mut e.info,
            Self::Exit(e) => &mut e.info,
            Self::Clone(e) => &mut e.info,
            Self::Prctl(e) => &mut e.info,
            Self::Kill(e) => &mut e.info,
            Self::Ptrace(e) => &mut e.info,
            Self::InitModule(e) => &mut e.info,
            Self::BpfProgLoad(e) => &mut e.info,
            Self::BpfSocketFilter(e) => &mut e.info,
            Self::Mprotect(e) => &mut e.info,
            Self::MmapExec(e) => &mut e.info,
            Self::Connect(e) => &mut e.info,
            Self::DnsQuery(e) => &mut e.info,
            Self::SendEntropy(e) => &mut e.info,
            Self::File(e) => &mut e.info,
            Self::FileRename(e) => &mut e.info,
            Self::Unlink(e) => &mut e.info,
            Self::IoUringSqe(e) => &mut e.info,
            Self::Error(e) => &mut e.info,
            Self::Loss(e) => &mut e.info,
            Self::Start(e) => &mut e.info,
            Self::Schedule(e) => &mut e.info,
            Self::Correlation(e) => &mut e.info,
            Self::Hash(e) => &mut e.info,
            Self::Log(e) => &mut e.info,
            Self::SysCoreResume(e) => &mut e.info,
        }
    }

    #[inline(always)]
    pub fn set_batch(&mut self, n: u64) {
        self.info_mut().batch = n
    }

    #[inline(always)]
    pub fn switch_type(&mut self, ty: Type) {
        self.info_mut().etype = ty
    }
}
