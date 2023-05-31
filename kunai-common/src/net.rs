use crate::{bpf_target_code, not_bpf_target_code};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub enum IpType {
    V4,
    V6,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IpPort {
    pub ty: IpType,
    data: [u32; 4],
    port: u16,
}

impl Default for IpPort {
    fn default() -> Self {
        Self {
            ty: IpType::V4,
            data: [0; 4],
            port: 0,
        }
    }
}

impl IpPort {
    pub fn new_v4_from_be(addr: u32, port: u16) -> Self {
        IpPort {
            ty: IpType::V4,
            data: [addr, 0, 0, 0],
            port,
        }
    }

    pub fn new_v6_from_be(addr: [u32; 4], port: u16) -> Self {
        IpPort {
            ty: IpType::V6,
            data: addr,
            port,
        }
    }

    pub fn ip(&self) -> u128 {
        match self.ty {
            IpType::V4 => self.data[0] as u128,
            IpType::V6 => u128::from_be_bytes(unsafe { core::mem::transmute(self.data) }),
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn is_v4(&self) -> bool {
        matches!(self.ty, IpType::V4)
    }

    pub fn is_v6(&self) -> bool {
        matches!(self.ty, IpType::V6)
    }

    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.data[0] == 0
            && self.data[1] == 0
            && self.data[2] == 0
            && self.data[3] == 0
            && self.port == 0
    }
}

not_bpf_target_code! {

    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    impl From<IpPort> for IpAddr {
        fn from(value: IpPort) -> Self {
            match value.ty {
                IpType::V4 => IpAddr::V4(Ipv4Addr::from(value.data[0])),
                IpType::V6 => IpAddr::V6(Ipv6Addr::from(value.ip())),
            }
        }
    }

}

bpf_target_code! {

    use crate::consts::*;
    use kunai_macros::BpfError;
    use crate::co_re::sock_common;

    #[repr(C)]
    #[derive(BpfError, Debug, Clone)]
    pub enum Error {
        #[error("unknown socket type")]
        UnknownSocketType,
        #[error("skc_family member not found")]
        SkcFamilyMissing,
        #[error("skc_addrpair member not found")]
        SkcAddrPairMissing,
        #[error("skc_portpair member not found")]
        SkcPortPairMissing,
        #[error("skc_v6_daddr member not found")]
        SkcV6daddrMissing,
    }



    impl IpPort {
        #[inline(always)]
        pub unsafe fn from_sock_common_foreign_ip(sk: &sock_common) -> Result<Self, Error> {
            let sa_family = sk.skc_family().ok_or(Error::SkcFamilyMissing)?;
            let dport = sk.skc_dport().ok_or(Error::SkcPortPairMissing)?.to_be();

            if sa_family == AF_INET as u16 {
                return Ok(IpPort::new_v4_from_be(
                    sk.skc_daddr().ok_or(Error::SkcAddrPairMissing)?.to_be(),
                    dport,
                ));
            } else if sa_family == AF_INET6 as u16 {
                return Ok(IpPort::new_v6_from_be(
                    sk.skc_v6_daddr().and_then(|in6| in6.addr32()).ok_or(Error::SkcV6daddrMissing)?,dport
                ));
            }

            return Err(Error::UnknownSocketType);
        }
    }
}
