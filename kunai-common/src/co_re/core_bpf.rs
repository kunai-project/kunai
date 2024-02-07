use crate::helpers::bpf_probe_read_kernel_buf;

use super::gen::{self, *};
use super::{rust_shim_kernel_impl, sock_fprog_kern, CoRe};

#[allow(non_camel_case_types)]
pub type bpf_ksym = CoRe<gen::bpf_ksym>;

impl bpf_ksym {
    rust_shim_kernel_impl!(pub, bpf_ksym, name, *mut u8);
}

#[allow(non_camel_case_types)]
pub type bpf_prog = CoRe<gen::bpf_prog>;

impl bpf_prog {
    rust_shim_kernel_impl!(pub, bpf_prog, len, u32);
    // type and expected_attach_type are enums
    rust_shim_kernel_impl!(pub, ty, bpf_prog, r#type, u32);
    rust_shim_kernel_impl!(pub, bpf_prog, expected_attach_type, u32);
    rust_shim_kernel_impl!(pub, bpf_prog, aux, bpf_prog_aux);
    rust_shim_kernel_impl!(pub, bpf_prog, orig_prog, sock_fprog_kern);
    rust_shim_kernel_impl!(pub, bpf_prog, tag, *mut u8);

    #[inline(always)]
    pub unsafe fn tag_array(&self) -> Option<[u8; 8]> {
        let mut out = [0; 8];
        if let Some(tag) = self.tag() {
            if !tag.is_null() {
                bpf_probe_read_kernel_buf(tag, out.as_mut_slice()).ok()?;
            }
        }
        Some(out)
    }
}

#[allow(non_camel_case_types)]
pub type bpf_prog_aux = CoRe<gen::bpf_prog_aux>;

impl bpf_prog_aux {
    rust_shim_kernel_impl!(pub, bpf_prog_aux, id, u32);
    rust_shim_kernel_impl!(pub, bpf_prog_aux, name, *mut u8);
    rust_shim_kernel_impl!(pub, bpf_prog_aux, attach_func_name, *const u8);
    rust_shim_kernel_impl!(pub, bpf_prog_aux, verified_insns, u32);
    rust_shim_kernel_impl!(pub, bpf_prog_aux, ksym, bpf_ksym);
}
