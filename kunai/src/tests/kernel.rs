use anyhow::anyhow;
use aya::{include_bytes_aligned, BpfLoader, Btf, VerifierLogLevel};
use env_logger::Builder;
use kunai::compat::{KernelVersion, Programs};
use kunai::configure_probes;
use libc::{rlimit, LINUX_REBOOT_CMD_POWER_OFF, RLIMIT_MEMLOCK, RLIM_INFINITY};
use log::{error, info, warn};
use std::{ffi::CString, panic};

fn mount(src: &str, target: &str, filesystem_type: &str) -> anyhow::Result<()> {
    // Paths and options
    let source = CString::new(src).expect("CString creation failed");
    let target = CString::new(target).expect("CString creation failed");
    let filesystem_type = CString::new(filesystem_type).expect("CString creation failed");
    //let flags = MS_NOSUID | MS_RDONLY;
    let flags = 0;

    // Mount sysfs
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            filesystem_type.as_ptr(),
            flags,
            std::ptr::null(),
        )
    };

    if result != 0 {
        return Err(anyhow!("failed to mount sysfs"));
    }

    Ok(())
}

fn integration() -> anyhow::Result<()> {
    let verifier_level = VerifierLogLevel::STATS;

    let current_kernel = KernelVersion::from_sys()?;
    info!("linux kernel: {current_kernel}");

    info!("mounting sysfs");
    // creating /sys mountpoint
    std::fs::create_dir_all("/sys")?;
    mount("none", "/sys", "sysfs")?;
    info!("mounting tracefs");
    mount("none", "/sys/kernel/tracing", "tracefs")?;

    info!("loading ebpf bytes");
    #[cfg(debug_assertions)]
    let mut bpf =
        BpfLoader::new()
            .verifier_log_level(verifier_level)
            .load(include_bytes_aligned!(
                "../../../target/bpfel-unknown-none/debug/kunai-ebpf"
            ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf =
        BpfLoader::new()
            .verifier_log_level(verifier_level)
            .load(include_bytes_aligned!(
                "../../../target/bpfel-unknown-none/release/kunai-ebpf"
            ))?;

    let mut programs = Programs::from_bpf(&mut bpf);

    configure_probes(&mut programs, current_kernel);

    info!("getting BTF");
    let btf = Btf::from_sys_fs()?;

    // generic program loader
    for (_, mut p) in programs.into_vec_sorted_by_prio() {
        info!(
            "loading: {} {:?} with priority={}",
            p.name,
            p.prog_type(),
            p.prio
        );

        if !p.enable {
            warn!("{} probe has been disabled", p.name);
            continue;
        }

        if !p.is_compatible(&current_kernel) {
            warn!(
                "{} probe is not compatible with current kernel: min={} max={} current={}",
                p.name,
                p.compat.min(),
                p.compat.max(),
                current_kernel
            );
            continue;
        }

        p.attach(&btf)?;
    }

    Ok(())
}

fn getrlimit() -> anyhow::Result<rlimit> {
    let mut rlim: rlimit = rlimit {
        rlim_cur: 0, // Set the soft limit to 0 initially
        rlim_max: 0, // Set the hard limit to 0 initially
    };

    // Get the current limit
    if unsafe { libc::getrlimit(RLIMIT_MEMLOCK, &mut rlim) } != 0 {
        return Err(anyhow!("failed to get rlimit"));
    }

    Ok(rlim)
}

fn setrlimit(rlimit: &rlimit) -> anyhow::Result<()> {
    // Set the new limit
    if unsafe { libc::setrlimit(RLIMIT_MEMLOCK, rlimit) } != 0 {
        return Err(anyhow!("failed to get rlimit"));
    }
    Ok(())
}

fn custom_panic_handler(info: &panic::PanicInfo) {
    // Your custom panic handling code goes here
    println!("\x1b[1;31m{info}\x1b[0m");
    // we power-off the system
    unsafe { libc::reboot(LINUX_REBOOT_CMD_POWER_OFF) };
}

fn main() -> ! {
    panic::set_hook(Box::new(custom_panic_handler));

    println!("initializing logger");
    // building the logger
    Builder::new().filter_level(log::LevelFilter::Info).init();

    let mut rlimit = getrlimit().expect("failed to get rlimit");
    info!("cur:{} max:{}", rlimit.rlim_cur, rlimit.rlim_max);
    rlimit.rlim_cur = RLIM_INFINITY;
    rlimit.rlim_max = RLIM_INFINITY;

    setrlimit(&rlimit).expect("failed to set rlimit");
    getrlimit().expect("failed to get rlimit after update");

    let res = integration();
    if res.is_err() {
        error!("FAILURE: {}", res.err().unwrap());
    } else {
        info!("SUCCESS");
    }

    unsafe { libc::reboot(LINUX_REBOOT_CMD_POWER_OFF) };

    core::unreachable!()
}
