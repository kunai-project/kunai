#[cfg(target_arch = "bpf")]
mod bpf;
#[cfg(target_arch = "bpf")]
pub use bpf::*;

use kunai_macros::BpfError;

use crate::errors::ProbeError;

#[repr(C)]
#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("failed to read enter args")]
    FailedToReadEnterArgs,
    #[error("failed to read exit args")]
    FailedToReadExitArgs,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::SyscallError(value)
    }
}
