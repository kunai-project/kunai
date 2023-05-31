use super::gen::{self, *};
use super::{rust_shim_impl, CoRe};

#[allow(non_camel_case_types)]
pub type cred = CoRe<gen::cred>;

impl cred {
    pub unsafe fn uid(&self) -> u32 {
        shim_cred_uid(self.as_ptr_mut())
    }

    pub unsafe fn gid(&self) -> u32 {
        shim_cred_gid(self.as_ptr_mut())
    }
}
