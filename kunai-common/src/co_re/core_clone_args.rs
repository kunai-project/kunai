use super::gen::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type kernel_clone_args = CoRe<gen::kernel_clone_args>;

impl kernel_clone_args {
    rust_shim_kernel_impl!(kernel_clone_args, flags, u64);
}
