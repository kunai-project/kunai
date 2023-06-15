use super::gen::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type kernfs_node = CoRe<gen::kernfs_node>;

impl kernfs_node {
    rust_shim_kernel_impl!(pub(self),_name, kernfs_node, name, *const i8);

    pub unsafe fn name(&self) -> Option<*const u8> {
        Some(self._name()? as *const u8)
    }

    rust_shim_kernel_impl!(kernfs_node, parent, kernfs_node);
}
