#![deny(unused_imports)]
#![cfg_attr(target_arch = "bpf", no_std)]
#![cfg_attr(
    target_arch = "bpf",
    allow(static_mut_refs, clippy::missing_safety_doc)
)]

pub mod macros;

pub mod string;

pub mod utils;

pub mod alloc;
pub mod errors;
pub mod kprobe;
pub mod syscalls;

#[cfg(target_arch = "bpf")]
pub mod co_re;

pub mod bpf_events;
pub mod net;
pub mod path;

pub mod consts;

pub mod buffer;

pub mod uuid;

pub mod cgroup;
pub mod time;

pub mod config;

pub mod version;

pub mod io_uring;

pub mod option;
