use crate::bpf_events::Event;

pub type MprotectEvent = Event<MprotectData>;

#[repr(C)]
pub struct MprotectData {
    pub section: [u8; 16],
    pub start: u64,
    pub len: u64,
    pub prot: u64,
}
