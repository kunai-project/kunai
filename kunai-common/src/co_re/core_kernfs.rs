use core::ffi::c_char;

use super::bindings::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type kernfs_node = CoRe<bindings::kernfs_node>;

impl kernfs_node {
    rust_shim_kernel_impl!(kernfs_node, name, *const c_char);
    rust_shim_kernel_impl!(kernfs_node, parent, kernfs_node);
}
