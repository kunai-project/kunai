use compat::{KernelVersion, Programs};

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
pub fn configure_probes(programs: &mut Programs, target: KernelVersion) {
    programs.expect_mut("execve.security_bprm_check").prio = 0;

    programs.expect_mut("execve.exit.bprm_execve").prio = 20;
    programs.expect_mut("syscalls.sys_exit_execve").prio = 20;

    // bprm_execve does not exists before 5.9
    programs
        .expect_mut("execve.exit.bprm_execve")
        .min_kernel(kernel!(5, 9));

    programs
        .expect_mut("syscalls.sys_exit_execve")
        .max_kernel(kernel!(5, 9));

    programs
        .expect_mut("syscalls.sys_exit_execveat")
        .max_kernel(kernel!(5, 9));

    // bpf probes
    programs.expect_mut("entry.security_bpf_prog").prio = 90;
    programs.expect_mut("exit.bpf_prog_load").prio = 100;

    // path_mount -> do_mount
    programs
        .expect_mut("fs.exit.path_mount")
        .rename_if(target < kernel!(5, 9), "fs.exit.do_mount");

    // mmap probe
    programs.expect_mut("syscalls.sys_enter_mmap").prio = 90;
}
