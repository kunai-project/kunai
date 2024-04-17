use crate::{bpf_events, macros::bpf_target_code, macros::not_bpf_target_code};

not_bpf_target_code! {
    mod user;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

// analyzer does not see both target so we can allow dead code
// to prevent warnings to happen
#[allow(dead_code)]
const CONFIG_MAP_NAME: &str = "KUNAI_CONFIG_ARRAY";

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Loader {
    pub tgid: u32,
}

const FILTER_SIZE: usize = bpf_events::Type::Max as usize;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    enabled: [bool; FILTER_SIZE],
}

impl Filter {
    pub fn all_enabled() -> Self {
        Self {
            enabled: [true; FILTER_SIZE],
        }
    }

    pub fn all_disabled() -> Self {
        Self {
            enabled: [false; FILTER_SIZE],
        }
    }

    pub fn disable(&mut self, ty: bpf_events::Type) {
        self.enabled[ty as usize] = false;
    }

    pub fn enable(&mut self, ty: bpf_events::Type) {
        self.enabled[ty as usize] = true;
    }

    pub fn is_enabled(&self, ty: bpf_events::Type) -> bool {
        self.enabled[ty as usize]
    }
}

/// Structure holding configuration to use in eBPF programs
#[derive(Debug, Clone, Copy)]
pub struct BpfConfig {
    pub loader: Loader,
    pub filter: Filter,
}
