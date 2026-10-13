use aya_ebpf::helpers::bpf_probe_read_kernel;

use super::bindings::{self, *};
use super::{CoRe, core_read_kernel, file, rust_shim_kernel_impl};

#[allow(non_camel_case_types)]
pub type fdtable = CoRe<bindings::fdtable>;

impl fdtable {
    rust_shim_kernel_impl!(fdtable, max_fds, u32);
    rust_shim_kernel_impl!(fdtable, fd, *mut *mut bindings::file);
}

#[allow(non_camel_case_types)]
pub type files_struct = CoRe<bindings::files_struct>;

impl files_struct {
    rust_shim_kernel_impl!(files_struct, fdt, fdtable);
    rust_shim_kernel_impl!(files_struct, fd_array, *mut *mut bindings::file);

    /// gets a file corresponding to a file descriptor. We lookup in fdtable
    /// as it always points to the good array containing fds.
    /// NB: fd_array is not reliable because it can be remapped.
    #[inline(always)]
    pub unsafe fn get_file(&self, fd: usize) -> Option<file> {
        unsafe {
            if fd <= core_read_kernel!(self, fdt, max_fds)? as usize {
                let ptr = bpf_probe_read_kernel(core_read_kernel!(self, fdt, fd)?.add(fd)).ok()?;
                return Some(ptr.into());
            }
            None
        }
    }
}
