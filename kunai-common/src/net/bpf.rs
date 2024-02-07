use crate::co_re::core_read_kernel;
use crate::co_re::sock_common;
use crate::consts::*;

use super::{Error, IpPort, SocketInfo};

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
                sk.skc_v6_daddr()
                    .and_then(|in6| in6.addr32())
                    .ok_or(Error::SkcV6daddrMissing)?,
                dport,
            ));
        }

        return Err(Error::UnknownSocketType);
    }
}

impl TryFrom<crate::co_re::sock> for SocketInfo {
    type Error = Error;

    #[inline(always)]
    fn try_from(s: crate::co_re::sock) -> Result<Self, Self::Error> {
        unsafe {
            let ty = core_read_kernel!(s, sk_type).ok_or(Error::SkTypeMissing)?;
            let domain =
                core_read_kernel!(s, sk_common, skc_family).ok_or(Error::SkcFamilyMissing)?;
            Ok(Self { domain, ty })
        }
    }
}
