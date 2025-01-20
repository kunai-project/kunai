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

// FILTER_SIZE should not go beyond configurable event types
// otherwise we might prevent some wanted events (not configurable)
// from being processed
const FILTER_SIZE: usize = bpf_events::Type::EndConfigurable as usize;

/// A structure carrying on/off information about
/// Kunai events. Only events which are configurable
/// (with id below [bpf_events::Type::EndConfigurable])
/// can be configured.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    enabled: [bool; FILTER_SIZE],
}

impl Filter {
    /// Creates a [Filter] with all events enabled
    pub fn all_enabled() -> Self {
        Self {
            enabled: [true; FILTER_SIZE],
        }
    }

    /// Creates a [Filter] with all events disabled
    pub fn all_disabled() -> Self {
        Self {
            enabled: [false; FILTER_SIZE],
        }
    }

    #[inline(always)]
    fn set_value(&mut self, ty: bpf_events::Type, value: bool) {
        // we set the value only if it already exists
        if let Some(en) = self.enabled.get_mut(ty as usize) {
            *en = value;
        }
    }

    /// Disable any events of type [bpf_events::Type]
    #[inline(always)]
    pub fn disable(&mut self, ty: bpf_events::Type) {
        self.set_value(ty, false);
    }

    /// Enable any events of type [bpf_events::Type]
    #[inline(always)]
    pub fn enable(&mut self, ty: bpf_events::Type) {
        self.set_value(ty, true);
    }

    /// Returns `true` if event type [bpf_events::Type] is enabled
    #[inline(always)]
    pub fn is_enabled(&self, ty: bpf_events::Type) -> bool {
        // all the event types not configurable should always be enabled
        self.enabled.get(ty as usize).cloned().unwrap_or(true)
    }

    /// Returns `true` if event type [bpf_events::Type] is disabled
    #[inline(always)]
    pub fn is_disabled(&self, ty: bpf_events::Type) -> bool {
        !self.is_enabled(ty)
    }
}

/// Structure holding configuration to use in eBPF programs
#[derive(Debug, Clone, Copy)]
pub struct BpfConfig {
    pub loader: Loader,
    pub filter: Filter,
    pub glob_max_eps_fs: Option<u64>,
    pub task_max_eps_fs: Option<u64>,
    pub send_data_min_len: u64,
}
