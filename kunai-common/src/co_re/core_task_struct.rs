use aya_bpf::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_task_btf,
    bpf_probe_read_kernel_buf,
};

use super::gen::{self, *};
use super::{cred, mm_struct, nsproxy, rust_shim_impl, CoRe};

#[allow(non_camel_case_types)]
pub type task_struct = CoRe<gen::task_struct>;

impl task_struct {
    pub unsafe fn current() -> Self {
        Self::from_ptr(bpf_get_current_task() as *const _)
    }

    pub unsafe fn current_btf() -> Self {
        Self::from_ptr(bpf_get_current_task_btf() as *const _)
    }

    pub unsafe fn uuid(&self) -> u128 {
        unsafe { core::mem::transmute([bpf_get_current_pid_tgid(), self.as_ptr() as u64]) }
    }

    rust_shim_impl!(pub, task_struct, start_time, u64);

    rust_shim_impl!(pub(self), _start_boot_time, task_struct, start_boottime, u64);
    rust_shim_impl!(pub(self),_real_start_time, task_struct, real_start_time, u64);

    pub unsafe fn start_boottime(&self) -> Option<u64> {
        if let Some(sbt) = self._start_boot_time() {
            return Some(sbt);
        }

        if let Some(rst) = self._real_start_time() {
            return Some(rst);
        }

        None
    }

    pub unsafe fn real_start_time(&self) -> Option<u64> {
        self.start_boottime()
    }

    pub unsafe fn comm(&self) -> [u8; 16] {
        let mut comm = [0u8; 16];
        bpf_probe_read_kernel_buf(shim_task_struct_comm(self.as_ptr_mut()), &mut comm[..]);

        comm
    }

    rust_shim_impl!(pub, task_struct, tgid, pid_t);
    rust_shim_impl!(pub, task_struct, pid, pid_t);
    rust_shim_impl!(pub, task_struct, cred, cred);
    rust_shim_impl!(pub, task_struct, mm, mm_struct);

    rust_shim_impl!(pub, task_struct, group_leader, Self);
    rust_shim_impl!(pub, task_struct, real_parent, Self);

    rust_shim_impl!(pub, task_struct, nsproxy, nsproxy);
}
