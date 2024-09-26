use crate::co_re::core_read_kernel;
use crate::co_re::sock_common;
use crate::co_re::sockaddr;
use crate::co_re::sockaddr_in;
use crate::co_re::sockaddr_in6;
use crate::consts::*;

use super::{Error, SockAddr, SocketInfo};

impl SockAddr {
    #[inline(always)]
    pub unsafe fn from_sockaddr(sa: sockaddr) -> Result<Self, Error> {
        let sa_family = sa.sa_family().ok_or(Error::SaFamilyMissing)?;

        if sa_family == AF_INET {
            let sa_in = sockaddr_in::from(sa);

            let addr = sa_in.s_addr().ok_or(Error::SaInAddrMissing)?.to_be();
            let port = sa_in.sin_port().ok_or(Error::SaInPortMissing)?.to_be();

            return Ok(SockAddr::new_v4_from_be(addr, port));
        } else if sa_family == AF_INET6 {
            let sa_in6 = sockaddr_in6::from(sa);

            let addr = sa_in6
                .sin6_addr()
                .and_then(|in6| in6.addr32())
                .ok_or(Error::SaIn6AddrMissing)?;
            let port = sa_in6.sin6_port().ok_or(Error::SaIn6PortMissing)?.to_be();

            return Ok(SockAddr::new_v6_from_be(addr, port));
        }

        return Err(Error::UnsupportedSaFamily);
    }

    #[inline(always)]
    pub unsafe fn dst_from_sock_common(sk: sock_common) -> Result<Self, Error> {
        let sa_family = sk.skc_family().ok_or(Error::SkcFamilyMissing)?;
        let dport = sk.skc_dport().ok_or(Error::SkcPortPairMissing)?.to_be();

        if sa_family == AF_INET as u16 {
            return Ok(SockAddr::new_v4_from_be(
                sk.skc_daddr().ok_or(Error::SkcAddrPairMissing)?.to_be(),
                dport,
            ));
        } else if sa_family == AF_INET6 as u16 {
            return Ok(SockAddr::new_v6_from_be(
                sk.skc_v6_daddr()
                    .and_then(|in6| in6.addr32())
                    .ok_or(Error::SkcV6daddrMissing)?,
                dport,
            ));
        }

        return Err(Error::UnsupportedSaFamily);
    }

    #[inline(always)]
    pub unsafe fn src_from_sock_common(sk: sock_common) -> Result<Self, Error> {
        let sa_family = sk.skc_family().ok_or(Error::SkcFamilyMissing)?;
        let sport = sk
            .skc_num()
            .map(u16::to_be)
            .ok_or(Error::SkcPortPairMissing)?;

        if sa_family == AF_INET as u16 {
            return Ok(SockAddr::new_v4_from_be(
                sk.skc_rcv_saddr()
                    .map(u32::to_be)
                    .ok_or(Error::SkcAddrPairMissing)?,
                sport,
            ));
        } else if sa_family == AF_INET6 as u16 {
            return Ok(SockAddr::new_v6_from_be(
                sk.skc_v6_rcv_saddr()
                    .and_then(|in6| in6.addr32())
                    .ok_or(Error::SkcV6daddrMissing)?,
                sport,
            ));
        }

        return Err(Error::UnsupportedSaFamily);
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
            let proto = core_read_kernel!(s, sk_protocol).ok_or(Error::SkProtocolMissing)?;
            Ok(Self { domain, ty, proto })
        }
    }
}
