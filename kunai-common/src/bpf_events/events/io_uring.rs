use crate::bpf_events::Event;

pub type IoUringSqeEvent = Event<IoUringSqeData>;

#[repr(C)]
pub struct IoUringSqeData {
    pub opcode: u8,
}
