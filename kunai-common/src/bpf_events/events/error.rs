use kunai_macros::StrEnum;

use crate::bpf_events::Event;

pub type ErrorEvent = Event<ErrorData>;

/// Structure holding possible errors we want to forward
/// (as event) to userland. The error numbers is stable
/// and can be used to identify the error kind. On the other
/// hand Error text is subject to change.
#[repr(u64)]
#[derive(StrEnum, Clone, Copy)]
pub enum Error {
    /// when a task reaches it maximum allowed throughput
    /// it means some events of this task will be missing
    /// to prevent loss of other critical events
    #[str("throttle filesystem events, per task limit reached")]
    TaskThrottleFs = 1,
    /// this error may happen on any task randomly (based on
    /// current load).
    #[str("throttle filesystem events, global limit reached")]
    GlobalThrottleFs = 2,
}

#[repr(C)]
pub struct ErrorData {
    pub error: Error,
}
