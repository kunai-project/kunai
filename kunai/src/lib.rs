#![deny(unused_imports)]

use std::collections::HashSet;

use aya::util::kernel_symbols;
use compat::Programs;
use config::Config;
use kunai_common::{kernel, version::KernelVersion};
use log::warn;

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
    // we need to be able to parse available symbols to check if some function exist
    let sym = kernel_symbols()
        .unwrap_or_default()
        .into_values()
        .collect::<HashSet<String>>();

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

    // syscore_resume may be missing if kernel is compiled without CONFIG_PM_SLEEP
    // see: https://github.com/kunai-project/kunai/issues/105
    if !sym.contains("syscore_resume") {
        programs.expect_mut("enter_syscore_resume").disable();
        // the risk is we disable a probe that changed name (not desired)
        // we know that until v6.12 the function is there so print warning
        // only if kernel is more recent.
        if target > kernel!(6, 12) {
            warn!("syscore_resume probe has been disabled: make sure your kernel has been built without CONFIG_PM_SLEEP")
        }
    }
}
