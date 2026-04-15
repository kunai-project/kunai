#[cfg(target_arch = "bpf")]
mod bpf;
#[cfg(target_arch = "bpf")]
pub use bpf::*;
