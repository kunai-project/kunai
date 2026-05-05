use kunai_macros::BpfError;

use crate::errors::ProbeError;

#[cfg(target_arch = "bpf")]
mod bpf;
#[cfg(target_arch = "bpf")]
pub use bpf::*;

#[repr(C)]
#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("failed to insert ctx")]
    CtxInsert,
    #[error("failed to get ctx")]
    CtxGet,
    #[error("failed to insert fn depth")]
    DepthInsert,
    #[error("failed to get fn depth")]
    DepthGet,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::KprobeCtxError(value)
    }
}
