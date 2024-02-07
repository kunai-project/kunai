use kunai_macros::BpfError;

use crate::{errors::ProbeError, macros::bpf_target_code};

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

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
