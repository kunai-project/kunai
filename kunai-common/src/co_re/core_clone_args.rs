use super::bindings::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type kernel_clone_args = CoRe<bindings::kernel_clone_args>;

impl kernel_clone_args {
    rust_shim_kernel_impl!(kernel_clone_args, flags, u64);
}
