use crate::{bpf_events::Event, net::SockAddr};

pub type ConnectEvent = Event<ConnectData>;

#[repr(C)]
pub struct ConnectData {
    pub family: u32,
    pub ip_port: SockAddr,
    pub connected: bool,
}
