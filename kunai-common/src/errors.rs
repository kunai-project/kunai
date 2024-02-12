use crate::kprobe;
use crate::macros::bpf_target_code;

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

use crate::alloc;
use crate::bpf_events;
use crate::buffer;
use crate::cgroup;
use crate::net;
use crate::path;
use crate::string;
use crate::syscalls;

use kunai_macros::BpfError;

pub const BPF_PROG_SUCCESS: u32 = 0;
pub const BPF_PROG_FAILURE: u32 = 1;

#[repr(C)]
#[derive(BpfError, Clone, Copy)]
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

// this will generate an error if ProbeError enum becomes
// too big and does not fit into a BPF register. This would
// prevent unexpected behaviour when returning Result<T, ProbeError>
const _: bool = {
    if core::mem::size_of::<ProbeError>() > core::mem::size_of::<u64>() {
        panic!("ProbeError enum does not fit into a BPF register");
    }

    if core::mem::align_of::<ProbeError>() != core::mem::align_of::<u64>() {
        panic!("ProbeError must be 8 bytes aligned")
    }
    true
};

// it seems the verifier does not like when data carrying enum
// hold values with different size and alignments so we are forcing them
#[repr(C, align(8))]
#[derive(BpfError, Clone, Copy)]
pub enum ProbeError {
    #[error("failed to get configuration")]
    Config,
    #[error("mandatory core field is missing")]
    CoReFieldMissing,
    #[error("failed to get kprobe arg")]
    KProbeArgFailure,
    #[error("unexpected null pointer")]
    NullPointer,
    #[error("file not found")]
    FileNotFound,
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
    EventError(bpf_events::Error),
    #[wrap]
    CgroupError(cgroup::Error),
    #[wrap]
    KprobeCtxError(kprobe::Error),
}

pub type ProbeResult<T> = core::result::Result<T, ProbeError>;
