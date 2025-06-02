#![deny(unused_imports)]

use std::collections::HashSet;

use aya::{
    include_bytes_aligned, programs::ProgramError, util::kernel_symbols, Btf, Ebpf, EbpfLoader,
    VerifierLogLevel,
};
use compat::Programs;
use config::Config;
use kunai_common::{config::BpfConfig, kernel, version::KernelVersion};
use log::{info, warn};
use util::{page_shift, page_size};

pub mod cache;
pub mod compat;
pub mod config;
pub mod containers;
pub mod events;
pub mod info;
pub mod ioc;
pub mod util;
pub mod yara;

/// Holds the binary data of all the eBPF programs
const BPF_ELF: &[u8] = {
    #[cfg(debug_assertions)]
    let d = include_bytes_aligned!("../../target/bpfel-unknown-none/debug/kunai-ebpf");
    #[cfg(not(debug_assertions))]
    let d = include_bytes_aligned!("../../target/bpfel-unknown-none/release/kunai-ebpf");
    d
};

/// Function managing probe priorities and compatibilities with kernels
///
/// # Panic
///
/// If a given probe name is not found
#[allow(unused_variables)]
fn configure_probes(conf: &Config, programs: &mut Programs, target: KernelVersion) {
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

    // io_uring probes
    programs
        .expect_mut("enter_io_submit_sqe")
        .min_kernel(kernel!(5, 1))
        .max_kernel(kernel!(5, 4));

    programs
        .expect_mut("enter_io_issue_sqe")
        .min_kernel(kernel!(5, 5))
        // we need to hook another function to have all SQEs since v6.15: https://elixir.bootlin.com/linux/v6.15/source/io_uring/io_uring.c#L1717
        .change_attach_point_if(target > kernel!(6, 14), "__io_issue_sqe");

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

/// This function is responsible from loading eBPF code from a buffer
/// into the appropriate Aya structure. It does not load the eBPF code
/// into the kernel.
pub fn prepare_bpf(
    kernel: KernelVersion,
    conf: &Config,
    vll: VerifierLogLevel,
) -> anyhow::Result<Ebpf> {
    let page_size = page_size()? as u64;
    let page_shift = page_shift()? as u64;

    let mut bpf = EbpfLoader::new()
        .verifier_log_level(vll)
        .set_global("PAGE_SHIFT", &page_shift, true)
        .set_global("PAGE_SIZE", &page_size, true)
        .set_global("LINUX_KERNEL_VERSION", &kernel, true)
        .load(BPF_ELF)?;

    BpfConfig::init_config_in_bpf(&mut bpf, conf.clone().try_into()?)
        .expect("failed to initialize bpf configuration");

    Ok(bpf)
}

/// Loads eBPF programs in the kernel and attach each program
/// to its attach point. This function acts as a generic eBPF
/// program loader.
pub fn load_and_attach_bpf<'a>(
    conf: &'a Config,
    kernel: KernelVersion,
    bpf: &'a mut Ebpf,
) -> anyhow::Result<()> {
    // make possible probe selection in debug
    #[allow(unused_mut)]
    let mut en_probes: Vec<String> = vec![];
    #[cfg(debug_assertions)]
    if let Ok(enable) = std::env::var("PROBES") {
        enable.split(',').for_each(|s| en_probes.push(s.into()));
    }

    // We need to parse eBPF ELF to extract section names
    let mut programs = Programs::with_bpf(bpf).with_elf_info(BPF_ELF)?;
    let btf = Btf::from_sys_fs()?;

    configure_probes(conf, &mut programs, kernel);

    // generic program loader
    for (_, p) in programs.sorted_by_prio() {
        // filtering probes to enable (only available in debug)
        if !en_probes.is_empty() && en_probes.iter().filter(|e| p.name.contains(*e)).count() == 0 {
            continue;
        }

        // we force enabling of selected probes
        // debug probes are disabled by default
        if !en_probes.is_empty() {
            p.enable();
        }

        if !p.enable {
            warn!("{} probe has been disabled", p.name);
            continue;
        }

        if !p.is_compatible(&kernel) {
            warn!(
                "{} probe is not compatible with current kernel: min={} max={} current={}",
                p.name,
                p.compat.min(),
                p.compat.max(),
                kernel
            );
            continue;
        }

        info!(
            "loading: {} {:?} with priority={}",
            p.name,
            p.prog_type(),
            p.prio
        );

        p.load(&btf)?;

        // this handles the very specific case where /proc/kallsyms
        // is not available to check if syscore_resume is present
        // In such case attach will fail with a SyscallError and
        // a warning must be shown
        let r = p.attach();
        if p.has_attach_point("syscore_resume")
            && matches!(
                r,
                Err(crate::compat::Error::Program(ProgramError::SyscallError(_)))
            )
        {
            warn!("syscore_resume probe has failed to load, make sure your kernel is compiled without CONFIG_PM_SLEEP")
        }
    }

    Ok(())
}
