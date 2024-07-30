#![deny(warnings)]
use compat::Programs;
use kunai_common::{kernel, version::KernelVersion};

pub mod cache;
pub mod compat;
pub mod config;
pub mod containers;
pub mod events;
pub mod info;
pub mod ioc;
pub mod util;

/// function that responsible of probe priorities and compatibily across kernels
/// panic: if a given probe name is not found
#[allow(unused_variables)]
pub fn configure_probes(programs: &mut Programs, target: KernelVersion) {
    programs.expect_mut("execve_security_bprm_check").prio = 0;

    programs.expect_mut("execve_exit_bprm_execve").prio = 20;
    programs.expect_mut("syscalls_sys_exit_execve").prio = 20;

    // bprm_execve does not exists before 5.9
    programs
        .expect_mut("execve_exit_bprm_execve")
        .min_kernel(kernel!(5, 9));

    programs
        .expect_mut("syscalls_sys_exit_execve")
        .max_kernel(kernel!(5, 9));

    programs
        .expect_mut("syscalls_sys_exit_execveat")
        .max_kernel(kernel!(5, 9));

    // bpf probes
    programs.expect_mut("entry_security_bpf_prog").prio = 90;
    programs.expect_mut("exit_bpf_prog_load").prio = 100;

    // mmap probe
    programs.expect_mut("syscalls_sys_enter_mmap").prio = 90;
}
