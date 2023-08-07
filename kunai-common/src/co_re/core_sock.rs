use aya_bpf::cty::c_void;
use aya_bpf::helpers::{bpf_probe_read_kernel_buf, bpf_probe_read_user_buf};

use super::gen::{self, *};
use super::{iov_iter, iovec, rust_shim_kernel_impl, rust_shim_user_impl, CoRe};

#[allow(non_camel_case_types)]
pub type in6_addr = CoRe<gen::in6_addr>;

impl in6_addr {
    rust_shim_kernel_impl!(pub(self), in6_addr, u6_addr8, *mut u8);
    rust_shim_user_impl!(pub(self), in6_addr, u6_addr8, *mut u8);

    pub unsafe fn addr8(&self) -> Option<[u8; 16]> {
        let mut addr = [0u8; 16];
        bpf_probe_read_kernel_buf(self.u6_addr8()?, addr.as_mut_slice()).ok()?;
        Some(addr)
    }

    pub unsafe fn addr16(&self) -> Option<[u16; 8]> {
        let addr = self.addr8()?;
        Some(core::mem::transmute(addr))
    }

    pub unsafe fn addr32(&self) -> Option<[u32; 4]> {
        let addr = self.addr8()?;
        Some(core::mem::transmute(addr))
    }

    pub unsafe fn addr8_user(&self) -> Option<[u8; 16]> {
        let mut addr = [0u8; 16];
        bpf_probe_read_user_buf(self.u6_addr8_user()?, addr.as_mut_slice()).ok()?;
        Some(addr)
    }

    pub unsafe fn addr16_user(&self) -> Option<[u16; 8]> {
        let addr = self.addr8_user()?;
        Some(core::mem::transmute(addr))
    }

    pub unsafe fn addr32_user(&self) -> Option<[u32; 4]> {
        let addr = self.addr8_user()?;
        Some(core::mem::transmute(addr))
    }
}

#[allow(non_camel_case_types)]
pub type socket = CoRe<gen::socket>;

impl socket {
    rust_shim_kernel_impl!(pub, socket, sk, sock);
}

#[allow(non_camel_case_types)]
pub type sock = CoRe<gen::sock>;

impl sock {
    rust_shim_kernel_impl!(pub, sk_common, sock, __sk_common, sock_common);
    rust_shim_kernel_impl!(pub, sock, sk_type, u16);
    rust_shim_kernel_impl!(pub, sock, sk_receive_queue, sk_buff_head);
}

#[allow(non_camel_case_types)]
pub type sock_common = CoRe<gen::sock_common>;

#[repr(C)]
struct skc_addrpair {
    skc_daddr: u32,
    skc_rcv_saddr: u32,
}

#[repr(C)]
struct skc_portpair {
    skc_dport: u16,
    skc_num: u16,
}

impl sock_common {
    rust_shim_kernel_impl!(pub, sock_common, skc_family, u16);
    rust_shim_kernel_impl!(pub, sock_common, skc_addrpair, u64);

    pub unsafe fn skc_daddr(&self) -> Option<u32> {
        let addrpair: skc_addrpair = core::mem::transmute(self.skc_addrpair()?);
        Some(addrpair.skc_daddr)
    }

    pub unsafe fn skc_rcv_saddr(&self) -> Option<u32> {
        let addrpair: skc_addrpair = core::mem::transmute(self.skc_addrpair()?);
        Some(addrpair.skc_rcv_saddr)
    }

    rust_shim_kernel_impl!(pub, sock_common, skc_portpair, u32);

    pub unsafe fn skc_dport(&self) -> Option<u16> {
        let portpair: skc_portpair = core::mem::transmute(self.skc_portpair()?);
        Some(portpair.skc_dport)
    }

    pub unsafe fn skc_num(&self) -> Option<u16> {
        let portpair: skc_portpair = core::mem::transmute(self.skc_portpair()?);
        Some(portpair.skc_num)
    }

    rust_shim_kernel_impl!(pub, sock_common, skc_v6_daddr, in6_addr);
    rust_shim_kernel_impl!(pub, sock_common, skc_v6_rcv_saddr, in6_addr);
}

#[allow(non_camel_case_types)]
pub type msghdr = CoRe<gen::msghdr>;

impl msghdr {
    rust_shim_kernel_impl!(pub, msghdr, msg_iter, iov_iter);
}

#[allow(non_camel_case_types)]
pub type sk_buff = CoRe<gen::sk_buff>;

impl sk_buff {
    rust_shim_kernel_impl!(pub, sk_buff, len, u32);
    rust_shim_kernel_impl!(pub, sk_buff, data, *mut u8);
}

#[allow(non_camel_case_types)]
pub type sk_buff_list = CoRe<gen::sk_buff_list>;

impl sk_buff_list {
    rust_shim_kernel_impl!(pub, sk_buff_list, next, sk_buff);
    rust_shim_kernel_impl!(pub, sk_buff_list, prev, sk_buff);
}

#[allow(non_camel_case_types)]
pub type sk_buff_head = CoRe<gen::sk_buff_head>;

impl sk_buff_head {
    rust_shim_kernel_impl!(pub(self), _next, sk_buff_head, next, sk_buff);
    rust_shim_kernel_impl!(pub(self), _prev, sk_buff_head, prev, sk_buff);
    rust_shim_kernel_impl!(pub(self), _list, sk_buff_head, list, sk_buff_list);

    // depending on the kernel version next might be wrapped inside a list struct
    // we handle that case here.
    pub unsafe fn next(&self) -> Option<sk_buff> {
        if let Some(next) = self._next() {
            return Some(next);
        }
        if let Some(list) = self._list() {
            return list.next();
        }
        return None;
    }
}

#[allow(non_camel_case_types)]
pub type user_msghdr = CoRe<gen::user_msghdr>;

impl user_msghdr {
    rust_shim_user_impl!(pub, user_msghdr, msg_name, *mut c_void);
    rust_shim_user_impl!(pub, user_msghdr, msg_iov, iovec);
    rust_shim_user_impl!(pub, user_msghdr, msg_iovlen, u64);
}

#[allow(non_camel_case_types)]
pub type sockaddr = CoRe<gen::sockaddr>;

impl sockaddr {
    rust_shim_kernel_impl!(pub, sockaddr, sa_family, u32);
    rust_shim_user_impl!(pub, sockaddr, sa_family, u32);
}

#[allow(non_camel_case_types)]
pub type sockaddr_in = CoRe<gen::sockaddr_in>;

impl From<sockaddr> for sockaddr_in {
    fn from(value: sockaddr) -> Self {
        Self::from_ptr(value.as_ptr() as *const _)
    }
}

impl sockaddr_in {
    rust_shim_kernel_impl!(pub, sockaddr_in, sin_family, u32);
    rust_shim_user_impl!(pub, sockaddr_in, sin_family, u32);

    rust_shim_kernel_impl!(pub, sockaddr_in, sin_port, u16);
    rust_shim_user_impl!(pub, sockaddr_in, sin_port, u16);

    rust_shim_kernel_impl!(pub, sockaddr_in, s_addr, u32);
    rust_shim_user_impl!(pub, sockaddr_in, s_addr, u32);
}

#[allow(non_camel_case_types)]
pub type sockaddr_in6 = CoRe<gen::sockaddr_in6>;

impl From<sockaddr> for sockaddr_in6 {
    fn from(value: sockaddr) -> Self {
        Self::from_ptr(value.as_ptr() as *const _)
    }
}

impl sockaddr_in6 {
    rust_shim_kernel_impl!(pub, sockaddr_in6, sin6_family, u32);
    rust_shim_user_impl!(pub, sockaddr_in6, sin6_family, u32);

    rust_shim_kernel_impl!(pub, sockaddr_in6, sin6_port, u16);
    rust_shim_user_impl!(pub, sockaddr_in6, sin6_port, u16);

    rust_shim_kernel_impl!(pub, sockaddr_in6, sin6_addr, in6_addr);
    rust_shim_user_impl!(pub, sockaddr_in6, sin6_addr, in6_addr);
}
