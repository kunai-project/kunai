use crate::{errors::ProbeError, macros::bpf_target_code, macros::not_bpf_target_code};
use kunai_macros::BpfError;

not_bpf_target_code! {
    mod user;
    pub use user::*;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

const MAX_CGROUP_TYPE_NAMELEN: usize = 32;
const MAX_CFTYPE_NAME: usize = 64;

pub const CGROUP_FILE_NAME_MAX: usize = MAX_CGROUP_TYPE_NAMELEN + MAX_CFTYPE_NAME + 2;

const CGROUP_STRING_LEN: usize = CGROUP_FILE_NAME_MAX * 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Cgroup {
    path: crate::string::String<CGROUP_STRING_LEN>,
}

#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("failed to read cgroup.kn")]
    Kn,
    #[error("failed to read kn.name")]
    KnName,
    #[error("failed to read kn.parent")]
    KnParent,
    #[error("failed appending to path")]
    Append,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::CgroupError(value)
    }
}
