use super::Event;
use crate::net::IpPort;

pub type ConnectEvent = Event<ConnectData>;

#[repr(C)]
pub struct ConnectData {
    pub family: u32,
    pub ip_port: IpPort,
    pub connected: bool,
}
