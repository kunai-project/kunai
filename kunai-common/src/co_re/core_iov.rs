use aya_bpf::cty::c_void;

use super::gen::{self, *};
use super::{rust_shim_kernel_impl, rust_shim_user_impl, CoRe};

#[allow(non_camel_case_types)]
pub type iovec = CoRe<gen::iovec>;

impl iovec {
    rust_shim_kernel_impl!(pub, iovec, iov_base, *mut c_void);
    rust_shim_user_impl!(pub, iovec, iov_base, *mut c_void);
    rust_shim_kernel_impl!(pub, iovec, iov_len, u64);
    rust_shim_user_impl!(pub, iovec, iov_len, u64);

    #[inline(always)]
    pub unsafe fn get(&self, i: usize) -> Self {
        self.as_ptr().add(i).into()
    }
}

#[allow(non_camel_case_types)]
pub type iov_iter = CoRe<gen::iov_iter>;

impl iov_iter {
    rust_shim_kernel_impl!(pub, iov_iter, count, u64);
    rust_shim_kernel_impl!(pub, iov_iter, nr_segs, u64);
    rust_shim_kernel_impl!(pub(self), _iov, iov_iter, iov, iovec);
    rust_shim_kernel_impl!(pub(self), ___iov, iov_iter, __iov, iovec);

    pub unsafe fn iov(&self) -> Option<iovec> {
        self._iov().or(self.___iov())
    }
}
