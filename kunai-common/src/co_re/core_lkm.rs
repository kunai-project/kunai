use super::bindings::{self, *};
use super::{CoRe, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type load_info = CoRe<bindings::load_info>;

impl load_info {
    rust_shim_kernel_impl!(pub, load_info, name, *const u8);
}
