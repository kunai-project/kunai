use super::gen::{self, *};
use super::{file, rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type mm_struct = CoRe<gen::mm_struct>;

impl mm_struct {
    rust_shim_kernel_impl!(mm_struct, arg_start, u64);

    #[inline(always)]
    // inspired from: https://elixir.bootlin.com/linux/v6.6.13/source/fs/proc/base.c#L256
    pub unsafe fn arg_len(&self) -> Option<u64> {
        let start = self.arg_start()?;
        let end = self.arg_end()?;
        Some({
            if end == 0 || start >= end {
                0
            } else {
                end - start
            }
        })
    }

    rust_shim_kernel_impl!(mm_struct, arg_end, u64);
    rust_shim_kernel_impl!(mm_struct, exe_file, file);
}
