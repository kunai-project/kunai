use crate::bpf_events;
use aya_ebpf::helpers::bpf_get_current_pid_tgid;
use aya_ebpf::macros::map;
use aya_ebpf::maps::Array;

use super::BpfConfig;

#[map]
static mut KUNAI_CONFIG_ARRAY: Array<BpfConfig> = Array::with_max_entries(1, 0);

/// Function to retrieve configuration into eBPF code
pub unsafe fn config() -> Option<&'static BpfConfig> {
    KUNAI_CONFIG_ARRAY.get(0)
}

impl BpfConfig {
    #[inline(always)]
    pub unsafe fn current_is_loader(&self) -> bool {
        bpf_get_current_pid_tgid() as u32 == self.loader.tgid
    }

    #[inline(always)]
    pub fn is_event_enabled(&self, ty: bpf_events::Type) -> bool {
        self.filter.is_enabled(ty)
    }

    #[inline(always)]
    pub fn is_event_disabled(&self, ty: bpf_events::Type) -> bool {
        !self.filter.is_enabled(ty)
    }
}
