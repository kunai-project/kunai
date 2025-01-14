use crate::bpf_events::Event;

/// Event that must be used only in userland
/// to encode status information
pub type StatusEvent = Event<()>;
