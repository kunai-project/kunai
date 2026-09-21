// `aarch64` and `x86_64` are bindgen output generated from shim.c (see
// build.rs), one module per architecture. Only the one matching the
// current bpf_target_arch is regenerated and compiled.
#[cfg(bpf_target_arch = "aarch64")]
mod aarch64;
#[cfg(bpf_target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(bpf_target_arch = "x86_64")]
mod x86_64;
#[cfg(bpf_target_arch = "x86_64")]
pub use x86_64::*;
