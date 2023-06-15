use super::gen::{self, *};
use super::{file, rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type linux_binprm = CoRe<gen::linux_binprm>;

impl linux_binprm {
    rust_shim_kernel_impl!(pub, linux_binprm, file, file);
}
