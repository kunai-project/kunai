use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{IpType, SaFamily, SockAddr, SockType, SocketInfo};

impl From<SockAddr> for IpAddr {
    fn from(value: SockAddr) -> Self {
        match value.ty {
            IpType::V4 => IpAddr::V4(Ipv4Addr::from(value.data[0])),
            IpType::V6 => IpAddr::V6(Ipv6Addr::from(value.ip())),
        }
    }
}

impl SocketInfo {
    pub fn type_to_string(&self) -> String {
        if SockType::is_valid_type(self.ty) {
            let d: SockType = unsafe { core::mem::transmute(self.ty) };
            d.as_str().into()
        } else {
            format!("unknown({})", self.ty)
        }
    }

    pub fn domain_to_string(&self) -> String {
        if SaFamily::is_valid_sa_family(self.domain) {
            let t: SaFamily = unsafe { core::mem::transmute(self.domain) };
            t.as_str().into()
        } else {
            format!("unknown({})", self.domain)
        }
    }
}
