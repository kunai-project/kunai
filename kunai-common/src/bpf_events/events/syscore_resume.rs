use crate::bpf_events::Event;

pub type SysCoreResumeEvent = Event<SysCoreResumeData>;

#[repr(C)]
pub struct SysCoreResumeData {}
