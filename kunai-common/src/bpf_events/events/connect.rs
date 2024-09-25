use crate::{bpf_events::Event, net::SockAddr};

pub type ConnectEvent = Event<ConnectData>;

#[repr(C)]
pub struct ConnectData {
    pub family: u32,
    pub src: SockAddr,
    pub dst: SockAddr,
    pub connected: bool,
}
