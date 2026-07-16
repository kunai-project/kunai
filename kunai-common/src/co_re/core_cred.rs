use super::gen::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type cred = CoRe<gen::cred>;

impl cred {
    rust_shim_kernel_impl!(cred, uid, u32);
    rust_shim_kernel_impl!(cred, gid, u32);
    rust_shim_kernel_impl!(cred, euid, u32);
    rust_shim_kernel_impl!(cred, egid, u32);
    rust_shim_kernel_impl!(cred, suid, u32);
    rust_shim_kernel_impl!(cred, sgid, u32);
    rust_shim_kernel_impl!(cred, fsuid, u32);
    rust_shim_kernel_impl!(cred, fsgid, u32);

    rust_shim_kernel_impl!(pub(self), _cap_effective_val, cred, cap_effective_val, u64);
    rust_shim_kernel_impl!(pub(self), _cap_effective_cap_lo, cred, cap_effective_cap_lo, u32);
    rust_shim_kernel_impl!(pub(self), _cap_effective_cap_hi, cred, cap_effective_cap_hi, u32);

    rust_shim_kernel_impl!(pub(self), _cap_permitted_val, cred, cap_permitted_val, u64);
    rust_shim_kernel_impl!(pub(self), _cap_permitted_cap_lo, cred, cap_permitted_cap_lo, u32);
    rust_shim_kernel_impl!(pub(self), _cap_permitted_cap_hi, cred, cap_permitted_cap_hi, u32);

    rust_shim_kernel_impl!(pub(self), _cap_inheritable_val, cred, cap_inheritable_val, u64);
    rust_shim_kernel_impl!(pub(self), _cap_inheritable_cap_lo, cred, cap_inheritable_cap_lo, u32);
    rust_shim_kernel_impl!(pub(self), _cap_inheritable_cap_hi, cred, cap_inheritable_cap_hi, u32);

    #[inline(always)]
    pub unsafe fn cap_effective(&self) -> Option<u64> {
        self._cap_effective_val().or_else(|| {
            let lo = self._cap_effective_cap_lo()?;
            let hi = self._cap_effective_cap_hi()?;
            Some(((hi as u64) << 32) | (lo as u64))
        })
    }

    /// Permitted capability set packed into a u64.
    #[inline(always)]
    pub unsafe fn cap_permitted(&self) -> Option<u64> {
        self._cap_permitted_val().or_else(|| {
            let lo = self._cap_permitted_cap_lo()?;
            let hi = self._cap_permitted_cap_hi()?;
            Some(((hi as u64) << 32) | (lo as u64))
        })
    }

    #[inline(always)]
    pub unsafe fn cap_inheritable(&self) -> Option<u64> {
        self._cap_inheritable_val().or_else(|| {
            let lo = self._cap_inheritable_cap_lo()?;
            let hi = self._cap_inheritable_cap_hi()?;
            Some(((hi as u64) << 32) | (lo as u64))
        })
    }
}
