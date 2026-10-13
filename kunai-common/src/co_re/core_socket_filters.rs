use super::bindings::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type sock_fprog = CoRe<bindings::sock_fprog>;

impl sock_fprog {
    rust_shim_kernel_impl!(pub, sock_fprog, len, u16);
    rust_shim_kernel_impl!(pub, sock_fprog, filter, sock_filter);

    #[inline(always)]
    pub unsafe fn size(&self) -> Option<usize> {
        unsafe { Some(self.len()? as usize * core::mem::size_of::<bindings::sock_filter>()) }
    }
}

#[allow(non_camel_case_types)]
pub type sock_fprog_kern = CoRe<bindings::sock_fprog_kern>;

impl sock_fprog_kern {
    rust_shim_kernel_impl!(pub, sock_fprog_kern, len, u16);
    rust_shim_kernel_impl!(pub, sock_fprog_kern, filter, sock_filter);

    #[inline(always)]
    pub unsafe fn byte_size_from_len(len: u16) -> usize {
        len as usize * core::mem::size_of::<bindings::sock_filter>()
    }

    #[inline(always)]
    pub unsafe fn byte_size(&self) -> Option<usize> {
        unsafe { Some(Self::byte_size_from_len(self.len()?)) }
    }
}

#[allow(non_camel_case_types)]
pub type sock_filter = CoRe<bindings::sock_filter>;

impl sock_filter {
    rust_shim_kernel_impl!(pub, sock_filter, code, u16);
    rust_shim_kernel_impl!(pub, sock_filter, jt, u8);
    rust_shim_kernel_impl!(pub, sock_filter, jf, u8);
    rust_shim_kernel_impl!(pub, sock_filter, k, u32);
}
