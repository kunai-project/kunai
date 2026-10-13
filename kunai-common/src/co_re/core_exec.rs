use super::bindings::{self, *};
use super::{CoRe, file, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type linux_binprm = CoRe<bindings::linux_binprm>;

impl linux_binprm {
    rust_shim_kernel_impl!(pub, linux_binprm, file, file);
}
