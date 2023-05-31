use super::gen::{self, *};
use super::{file, rust_shim_impl, CoRe};

#[allow(non_camel_case_types)]
pub type mm_struct = CoRe<gen::mm_struct>;

impl mm_struct {
    rust_shim_impl!(mm_struct, arg_start, u64);

    pub unsafe fn arg_len(&self) -> Option<u64> {
        Some(self.arg_end()? - self.arg_start()?)
    }

    rust_shim_impl!(mm_struct, arg_end, u64);
    rust_shim_impl!(mm_struct, exe_file, file);
}
