use crate::{
    bpf_events::Event,
    net::{SockAddr, SocketInfo},
};

pub type ConnectEvent = Event<ConnectData>;

#[repr(C)]
pub struct ConnectData {
    pub socket: SocketInfo,
    pub src: SockAddr,
    pub dst: SockAddr,
    pub connected: bool,
}
