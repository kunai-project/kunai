use crate::{errors::ProbeError, macros::bpf_target_code, macros::not_bpf_target_code};
use kunai_macros::BpfError;

not_bpf_target_code! {
    mod user;

}

bpf_target_code! {
    mod bpf;
}

const CGROUP_PATH_MAX: usize = 128;

const CGROUP_STRING_LEN: usize = CGROUP_PATH_MAX * 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Cgroup {
    path: crate::string::String<CGROUP_STRING_LEN>,
    pub error: Option<Error>,
}

#[derive(BpfError, Debug, Clone, Copy)]
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
