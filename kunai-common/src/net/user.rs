use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::{IpProto, IpType, SaFamily, SockAddr, SockType, SocketInfo};

impl From<SockAddr> for IpAddr {
    fn from(value: SockAddr) -> Self {
        match value.ty {
            IpType::V4 => IpAddr::V4(Ipv4Addr::from(value.data[0])),
            IpType::V6 => IpAddr::V6(Ipv6Addr::from(value.ip())),
        }
    }
}

impl SocketInfo {
    pub fn type_to_string(&self) -> Cow<'static, str> {
        SockType::try_from_uint(self.ty)
            .map(|t| t.as_str().into())
            .unwrap_or_else(|_| format!("unknown({})", self.ty).into())
    }

    pub fn domain_to_string(&self) -> Cow<'static, str> {
        SaFamily::try_from_uint(self.domain)
            .map(|sa| sa.as_str().into())
            .unwrap_or_else(|_| format!("unknown({})", self.domain).into())
    }

    pub fn proto_to_string(&self) -> Cow<'static, str> {
        IpProto::try_from_uint(self.proto)
            .map(|p| p.as_str().into())
            .unwrap_or_else(|_| format!("unknown({})", self.proto).into())
    }
}
