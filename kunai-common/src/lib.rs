#![cfg_attr(target_arch = "bpf", no_std)]

pub mod macros;

pub mod string;

pub mod bpf_utils;
pub mod utils;

bpf_target_code! {
    pub mod syscalls;
    pub mod co_re;
    pub mod helpers {
        // this is a temporary fix to benefit from fixed helpers
        // while still using older Aya git for the rest
        pub use aya_helpers::helpers::*;
    }
}

pub mod bpf_events;
pub mod net;
pub mod path;

pub mod consts;

pub mod buffer;
//pub mod transfer;

pub mod uuid;

pub mod cgroup;
pub mod time;

pub mod config;
