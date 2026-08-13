use kunai_macros::BpfError;

use crate::errors::ProbeError;

#[cfg(target_arch = "bpf")]
mod bpf;

#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("uid is missing")]
    Uid,
    #[error("gid is missing")]
    Gid,
    #[error("euid is missing")]
    EUid,
    #[error("egid is missing")]
    EGid,
    #[error("suid is missing")]
    SUid,
    #[error("sgid is missing")]
    SGid,
    #[error("fsuid is missing")]
    FSUid,
    #[error("fsgid is missing")]
    FSGid,
    #[error("cap_effective is missing")]
    CapEffective,
    #[error("cap_permitted is missing")]
    CapPermitted,
    #[error("cap_inheritable is missing")]
    CapInheritable,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::CredError(value)
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Creds {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
}
