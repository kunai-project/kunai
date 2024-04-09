use aya_bpf::cty::c_void;

use crate::kernel;
use crate::version::kernel_version;

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

#[repr(C)]
#[derive(PartialEq)]
#[allow(non_camel_case_types)]
/// IterType encodes the iter type. We cannot use the enum defined
/// in the Linux Kernel as it is not stable accross versions.
pub enum IterType {
    ITER_IOVEC,
    ITER_KVEC,
    ITER_BVEC,
    ITER_XARRAY,
    ITER_PIPE,
    ITER_DISCARD,
    ITER_UBUF,
}

impl IterType {
    fn from_u8(iter_type: u8) -> Option<Self> {
        let kernel = kernel_version();
        let t = {
            if kernel < kernel!(5, 14, 0) {
                (iter_type & 0b11111100) as u32
            } else {
                iter_type as u32
            }
        };

        unsafe {
            match t {
                x if shim_iter_type_ITER_IOVEC_exists() && x == shim_iter_type_ITER_IOVEC() => {
                    Some(IterType::ITER_IOVEC)
                }
                x if shim_iter_type_ITER_KVEC_exists() && x == shim_iter_type_ITER_KVEC() => {
                    Some(IterType::ITER_KVEC)
                }
                x if shim_iter_type_ITER_BVEC_exists() && x == shim_iter_type_ITER_BVEC() => {
                    Some(IterType::ITER_BVEC)
                }
                /*x if shim_iter_type_ITER_XARRAY_exists() && x == shim_iter_type_ITER_XARRAY() => {
                    Some(IterType::ITER_XARRAY)
                }*/
                /*x if shim_iter_type_ITER_PIPE_exists() && x == shim_iter_type_ITER_PIPE() => {
                    Some(IterType::ITER_PIPE)
                }*/
                /*x if shim_iter_type_ITER_DISCARD_exists() && x == shim_iter_type_ITER_DISCARD() => {
                    Some(IterType::ITER_DISCARD)
                }*/
                /*x if shim_iter_type_ITER_UBUF_exists() && x == shim_iter_type_ITER_UBUF() => {
                    Some(IterType::ITER_UBUF)
                }*/
                _ => None,
            }
        }
    }
}

#[allow(non_camel_case_types)]
pub type iov_iter = CoRe<gen::iov_iter>;

impl iov_iter {
    rust_shim_kernel_impl!(pub(self), _iter_type, iov_iter, iter_type, u8);
    rust_shim_kernel_impl!(pub(self), _type, iov_iter, type, u32);

    #[inline(always)]
    pub unsafe fn iter_type(&self) -> Option<IterType> {
        let t = self._iter_type().or(self._type().map(|t| t as u8))?;

        IterType::from_u8(t)
    }

    rust_shim_kernel_impl!(pub, iov_iter, count, u64);
    rust_shim_kernel_impl!(pub, iov_iter, nr_segs, u64);
    rust_shim_kernel_impl!(pub, iov_iter, ubuf, *mut c_void);
    rust_shim_kernel_impl!(pub(self), _iov, iov_iter, iov, iovec);
    rust_shim_kernel_impl!(pub(self), ___iov, iov_iter, __iov, iovec);

    fn is_iter_type(&self, ty: IterType) -> bool {
        if let Some(t) = unsafe { self.iter_type() } {
            return t == ty;
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
