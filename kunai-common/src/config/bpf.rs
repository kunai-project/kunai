use crate::bpf_events;
use crate::helpers::bpf_get_current_pid_tgid;
use aya_bpf::macros::map;
use aya_bpf::maps::Array;

use super::BpfConfig;

#[map]
static mut KUNAI_CONFIG_ARRAY: Array<BpfConfig> = Array::with_max_entries(1, 0);

/// Function to retrieve configuration into eBPF code
pub unsafe fn config() -> Option<&'static BpfConfig> {
    KUNAI_CONFIG_ARRAY.get(0)
}

impl BpfConfig {
    pub unsafe fn current_is_loader(&self) -> bool {
        bpf_get_current_pid_tgid() as u32 == self.loader.tgid
    }

    pub fn is_event_enabled(&self, ty: bpf_events::Type) -> bool {
        self.filter.is_enabled(ty)
    }
}
