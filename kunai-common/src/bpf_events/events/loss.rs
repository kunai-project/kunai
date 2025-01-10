use crate::bpf_events::Event;

/// Event that must be used only in userland
/// to encode events lost. It is used to bubble
/// up event loss into kunai logs
pub type LossEvent = Event<LossData>;

#[repr(C)]
pub struct LossData {
    /// total number of events read
    pub read: u64,
    /// total number of events lost
    pub lost: u64,
    /// total events per second
    pub eps: f64,
}
