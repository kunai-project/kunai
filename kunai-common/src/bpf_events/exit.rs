use super::Event;

pub type ExitEvent = Event<ExitData>;

#[repr(C)]
pub struct ExitData {
    pub error_code: u64,
}
