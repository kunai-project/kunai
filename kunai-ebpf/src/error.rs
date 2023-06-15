use crate::alloc;
use crate::maps;

use aya_log_ebpf::error;
use kunai_common::buffer;
use kunai_common::cgroup;
use kunai_common::events;
use kunai_common::net;
use kunai_common::path;
use kunai_common::string;

use kunai_common::syscalls;
use kunai_macros::BpfError;

pub const BPF_PROG_SUCCESS: u32 = 0;
pub const BPF_PROG_FAILURE: u32 = 1;

#[repr(C)]
#[derive(BpfError)]
pub enum MapError {
    #[error("failed to insert value into map")]
    InsertFailure,
    #[error("failed to get value from map")]
    GetFailure,
}

impl From<MapError> for ProbeError {
    fn from(value: MapError) -> Self {
        Self::BpfMapError(value)
    }
}

#[repr(C)]
pub struct LocError {
    pub line: u32,
    pub err: ProbeError,
}

macro_rules! log_loc_err {
    ($ctx:expr, $err:expr) => {
        aya_log_ebpf::error!($ctx, "{}:{}", $err.err.name(), $err.line);
    };
}

macro_rules! loc_error {
    ($e: expr) => {
        $crate::error::LocError::new(line!(), $e)
    };
}

impl LocError {
    pub fn new(line: u32, err: ProbeError) -> Self {
        LocError { line, err }
    }
}

#[repr(C)]
#[derive(BpfError)]
pub enum ProbeError {
    #[error("mandatory core field is missing")]
    CoReFieldMissing,
    #[error("failed to get kprobe arg")]
    KProbeArgFailure,
    #[error("failed to restore kprobe context")]
    KProbeCtxRestoreFailure,
    #[wrap]
    BpfMapError(MapError),
    #[wrap]
    PathError(path::Error),
    #[wrap]
    IpError(net::Error),
    #[wrap]
    StringError(string::Error),
    #[wrap]
    SyscallError(syscalls::Error),
    #[wrap]
    BufferError(buffer::Error),
    #[wrap]
    AllocError(alloc::Error),
    #[wrap]
    FdMapError(maps::Error),
    #[wrap]
    EventError(events::Error),
    #[wrap]
    CgroupError(cgroup::Error),
}

#[macro_export]
macro_rules! log_err {
    ($ctx:expr, $err:expr) => {
        //aya_log_ebpf::error!($ctx, "{}: {}", $err.name(), $err.description());
        aya_log_ebpf::error!($ctx, "{}", $err.name());
    };
}

pub(crate) use log_err;

impl From<syscalls::Error> for ProbeError {
    fn from(value: syscalls::Error) -> Self {
        Self::SyscallError(value)
    }
}

impl From<path::Error> for ProbeError {
    fn from(value: path::Error) -> Self {
        Self::PathError(value)
    }
}

impl From<string::Error> for ProbeError {
    fn from(value: string::Error) -> Self {
        Self::StringError(value)
    }
}

impl From<net::Error> for ProbeError {
    fn from(value: net::Error) -> Self {
        Self::IpError(value)
    }
}

impl From<buffer::Error> for ProbeError {
    fn from(value: buffer::Error) -> Self {
        Self::BufferError(value)
    }
}

impl From<alloc::Error> for ProbeError {
    fn from(value: alloc::Error) -> Self {
        Self::AllocError(value)
    }
}

impl From<events::Error> for ProbeError {
    fn from(value: events::Error) -> Self {
        Self::EventError(value)
    }
}

impl From<cgroup::Error> for ProbeError {
    fn from(value: cgroup::Error) -> Self {
        Self::CgroupError(value)
    }
}

pub type ProbeResult<T> = core::result::Result<T, ProbeError>;
