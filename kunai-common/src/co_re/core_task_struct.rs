use crate::helpers::{
    bpf_get_current_pid_tgid, bpf_get_current_task, bpf_get_current_task_btf,
    bpf_probe_read_kernel_buf,
};

use crate::string::String;

use super::gen::{self, *};
use super::{
    core_read_kernel, cred, file, files_struct, mm_struct, nsproxy, rust_shim_kernel_impl,
    task_group, CoRe,
};

#[allow(non_camel_case_types)]
pub type task_struct = CoRe<gen::task_struct>;

impl task_struct {
    #[inline(always)]
    pub unsafe fn current() -> Self {
        Self::from_ptr(bpf_get_current_task() as *const _)
    }

    #[inline(always)]
    pub unsafe fn current_btf() -> Self {
        Self::from_ptr(bpf_get_current_task_btf() as *const _)
    }

    #[inline(always)]
    pub unsafe fn uuid(&self) -> u128 {
        unsafe { core::mem::transmute([bpf_get_current_pid_tgid(), self.as_ptr() as u64]) }
    }

    rust_shim_kernel_impl!(pub, task_struct, flags, u32);
    rust_shim_kernel_impl!(pub, task_struct, start_time, u64);

    rust_shim_kernel_impl!(pub(self), _start_boot_time, task_struct, start_boottime, u64);
    rust_shim_kernel_impl!(pub(self),_real_start_time, task_struct, real_start_time, u64);

    #[inline(always)]
    pub unsafe fn start_boottime(&self) -> Option<u64> {
        if let Some(sbt) = self._start_boot_time() {
            return Some(sbt);
        }

        if let Some(rst) = self._real_start_time() {
            return Some(rst);
        }

        None
    }

    #[inline(always)]
    pub unsafe fn real_start_time(&self) -> Option<u64> {
        self.start_boottime()
    }

    rust_shim_kernel_impl!(pub, task_struct, comm, *mut u8);

    #[inline(always)]
    pub unsafe fn comm_array(&self) -> Option<[u8; 16]> {
        let mut comm = [0u8; 16];
        bpf_probe_read_kernel_buf(self.comm()?, comm.as_mut_slice()).ok()?;
        Some(comm)
    }

    #[inline(always)]
    pub unsafe fn comm_str(&self) -> Option<String<16>> {
        let mut comm = String::<16>::new();
        comm.read_kernel_str_bytes(self.comm()?).ok()?;
        Some(comm)
    }

    rust_shim_kernel_impl!(pub, task_struct, tgid, pid_t);
    rust_shim_kernel_impl!(pub, task_struct, pid, pid_t);
    rust_shim_kernel_impl!(pub, task_struct, cred, cred);
    rust_shim_kernel_impl!(pub, task_struct, mm, mm_struct);

    rust_shim_kernel_impl!(pub, task_struct, group_leader, Self);
    rust_shim_kernel_impl!(pub, task_struct, real_parent, Self);

    rust_shim_kernel_impl!(task_struct, files, files_struct);
    rust_shim_kernel_impl!(pub, task_struct, nsproxy, nsproxy);

    rust_shim_kernel_impl!(task_struct, sched_task_group, task_group);

    #[inline(always)]
    /// this is a shortcut function to easily get a file from its fd
    /// looking up the task_struct fdtable.
    pub unsafe fn get_fd(&self, fd: usize) -> Option<file> {
        core_read_kernel!(self, files)?.get_file(fd)
    }
}
