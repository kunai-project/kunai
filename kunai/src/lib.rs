#![deny(unused_imports)]
use compat::Programs;
use config::Config;
use kunai_common::{kernel, version::KernelVersion};

pub mod cache;
pub mod compat;
pub mod config;
pub mod containers;
pub mod events;
pub mod info;
pub mod ioc;
pub mod util;
pub mod yara;

/// function that responsible of probe priorities and compatibily across kernels
/// panic: if a given probe name is not found
#[allow(unused_variables)]
pub fn configure_probes(conf: &Config, programs: &mut Programs, target: KernelVersion) {
    // LSM probes are available only since 5.7
    // We disable them if we're not running in harden mode
    programs
        .expect_mut("lsm_task_kill")
        .min_kernel(kernel!(5, 7))
        .prio(0)
        .disable_if(!conf.harden);

    programs
        .expect_mut("lsm_ptrace_access_check")
        .min_kernel(kernel!(5, 7))
        .prio(0)
        .disable_if(!conf.harden);

    // Other probes
    programs.expect_mut("execve_security_bprm_check").prio(1);

    programs.expect_mut("execve_exit_bprm_execve").prio(20);
    programs.expect_mut("syscalls_sys_exit_execve").prio(20);

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
    programs.expect_mut("entry_security_bpf_prog").prio(90);
    programs.expect_mut("exit_bpf_prog_load").prio(100);

    // mmap probe
    programs.expect_mut("syscalls_sys_enter_mmap").prio(90);
}
