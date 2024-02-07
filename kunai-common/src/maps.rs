use crate::macros::bpf_target_code;

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

use kunai_macros::BpfError;

use crate::errors::ProbeError;

#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("failed to insert last fd into map")]
    LastFdInsertion,
    #[error("failed to insert fd into map")]
    FdInsertion,
    #[error("failed to delete fd from map")]
    FdDeletion,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::FdMapError(value)
    }
}
