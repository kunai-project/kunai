use crate::macros::bpf_target_code;

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

use kunai_macros::BpfError;

use super::errors::ProbeError;

#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("failed to get allocator")]
    FailedToGetAllocator,
    #[error("no more place to allocate")]
    NoMoreSpace,
    #[error("allocation is too big")]
    AllocTooBig,
    #[error("failed to insert new chunk")]
    ZeroChunkFailed,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        ProbeError::AllocError(value)
    }
}
