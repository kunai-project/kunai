use super::gen::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type cred = CoRe<gen::cred>;

impl cred {
    #[inline(always)]
    pub unsafe fn uid(&self) -> u32 {
        shim_cred_uid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn gid(&self) -> u32 {
        shim_cred_gid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn euid(&self) -> u32 {
        shim_cred_euid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn egid(&self) -> u32 {
        shim_cred_egid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn suid(&self) -> u32 {
        shim_cred_suid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn sgid(&self) -> u32 {
        shim_cred_sgid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn fsuid(&self) -> u32 {
        shim_cred_fsuid(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn fsgid(&self) -> u32 {
        shim_cred_fsgid(self.as_ptr_mut())
    }

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
    pub unsafe fn cap_effective(&self) -> u64 {
        if let Some(v) = self._cap_effective_val() {
            return v;
        }
        let lo = self._cap_effective_cap_lo().unwrap_or(0);
        let hi = self._cap_effective_cap_hi().unwrap_or(0);
        ((hi as u64) << 32) | (lo as u64)
    }

    /// Permitted capability set packed into a u64.
    #[inline(always)]
    pub unsafe fn cap_permitted(&self) -> u64 {
        if let Some(v) = self._cap_permitted_val() {
            return v;
        }
        let lo = self._cap_permitted_cap_lo().unwrap_or(0);
        let hi = self._cap_permitted_cap_hi().unwrap_or(0);
        ((hi as u64) << 32) | (lo as u64)
    }

    #[inline(always)]
    pub unsafe fn cap_inheritable(&self) -> u64 {
        if let Some(v) = self._cap_inheritable_val() {
            return v;
        }
        let lo = self._cap_inheritable_cap_lo().unwrap_or(0);
        let hi = self._cap_inheritable_cap_hi().unwrap_or(0);
        ((hi as u64) << 32) | (lo as u64)
    }
}
