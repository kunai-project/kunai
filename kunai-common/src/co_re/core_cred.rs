use super::gen::{self, *};
use super::{CoRe};

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

    #[inline(always)]
    pub unsafe fn cap_effective(&self) -> u64 {
        shim_cred_cap_effective(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn cap_permitted(&self) -> u64 {
        shim_cred_cap_permitted(self.as_ptr_mut())
    }

    #[inline(always)]
    pub unsafe fn cap_inheritable(&self) -> u64 {
        shim_cred_cap_inheritable(self.as_ptr_mut())
    }
}
