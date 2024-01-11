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

#[repr(u8)]
#[allow(non_camel_case_types)]
// iter_type enum defined: https://elixir.bootlin.com/linux/v6.6/C/ident/iter_type
enum IterType {
    /* iter types */
    ITER_IOVEC,
    ITER_KVEC,
    ITER_BVEC,
    ITER_XARRAY,
    ITER_DISCARD,
    ITER_UBUF,
}

#[allow(non_camel_case_types)]
pub type iov_iter = CoRe<gen::iov_iter>;

impl iov_iter {
    rust_shim_kernel_impl!(pub, iov_iter, iter_type, u8);
    rust_shim_kernel_impl!(pub, iov_iter, count, u64);
    rust_shim_kernel_impl!(pub, iov_iter, nr_segs, u64);
    rust_shim_kernel_impl!(pub, iov_iter, ubuf, *mut c_void);
    rust_shim_kernel_impl!(pub(self), _iov, iov_iter, iov, iovec);
    rust_shim_kernel_impl!(pub(self), ___iov, iov_iter, __iov, iovec);

    fn is_iter_type(&self, ty: IterType) -> bool {
        if let Some(t) = unsafe { self.iter_type() } {
            return t == ty as u8;
        }
        false
    }

    #[inline(always)]
    pub fn is_iter_iovec(&self) -> bool {
        self.is_iter_type(IterType::ITER_IOVEC)
    }

    #[inline(always)]
    pub fn is_iter_kvec(&self) -> bool {
        self.is_iter_type(IterType::ITER_KVEC)
    }

    #[inline(always)]
    pub fn is_iter_bvec(&self) -> bool {
        self.is_iter_type(IterType::ITER_BVEC)
    }

    #[inline(always)]
    pub fn is_iter_xarray(&self) -> bool {
        self.is_iter_type(IterType::ITER_XARRAY)
    }

    #[inline(always)]
    pub fn is_iter_discard(&self) -> bool {
        self.is_iter_type(IterType::ITER_DISCARD)
    }

    #[inline(always)]
    pub fn is_iter_ubuf(&self) -> bool {
        self.is_iter_type(IterType::ITER_UBUF)
    }

    #[inline(always)]
    pub unsafe fn iov(&self) -> Option<iovec> {
        self._iov().or(self.___iov())
    }
}
