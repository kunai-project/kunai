#![deny(unused_imports)]
use anyhow::anyhow;
use aya::VerifierLogLevel;
use env_logger::Builder;
use kunai::{
    config::Config,
    util::{is_bpf_lsm_enabled, uname::Utsname},
};
use kunai_common::kernel;
use libc::{
    makedev, mknod, rlimit, LINUX_REBOOT_CMD_POWER_OFF, RLIMIT_MEMLOCK, RLIM_INFINITY, S_IFCHR,
    S_IRUSR, S_IWUSR,
};
use log::{error, info, warn};
use std::{ffi::CString, panic, path::Path};

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

    let current_kernel = Utsname::kernel_version()?;
    info!("linux kernel: {current_kernel}");

    info!("mounting sysfs");
    // creating /sys mountpoint
    std::fs::create_dir_all("/sys")?;
    mount("none", "/sys", "sysfs")?;
    info!("mounting tracefs");
    mount("none", "/sys/kernel/tracing", "tracefs")?;
    info!("mounting securityfs");
    mount("none", "/sys/kernel/security", "securityfs")?;

    let conf = Config::default_hardened();

    if conf.harden {
        if current_kernel < kernel!(5, 7, 0) {
            warn!("hardened mode does not work below kernel 5.7.0")
        }

        if current_kernel >= kernel!(5, 7, 0) && !is_bpf_lsm_enabled()? {
            return Err(anyhow!(
                "trying to run in hardened mode but BPF LSM is not enabled"
            ));
        }
    }

    info!("loading ebpf bytes");
    let mut bpf = kunai::prepare_bpf(current_kernel, &conf, verifier_level)?;
    kunai::load_and_attach_bpf(&conf, current_kernel, &mut bpf)?;

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

fn custom_panic_handler(info: &panic::PanicHookInfo) {
    // Your custom panic handling code goes here
    println!("\x1b[1;31m{info}\x1b[0m");
    // we power-off the system
    unsafe { libc::reboot(LINUX_REBOOT_CMD_POWER_OFF) };
}

fn mknode_urandom() -> anyhow::Result<()> {
    let path = CString::new("/dev/urandom").unwrap();
    let mode = S_IFCHR | S_IRUSR | S_IWUSR; // Character device with read/write permissions
    let dev = makedev(1, 9); // Major 1, Minor 9 for /dev/urandom

    let result = unsafe { mknod(path.as_ptr(), mode, dev as _) };

    if result != 0 {
        Err(std::io::Error::last_os_error().into())
    } else {
        Ok(())
    }
}

fn main() -> ! {
    panic::set_hook(Box::new(custom_panic_handler));

    if !Path::new("/dev/urandom").exists() {
        println!("/dev/urandom does not exists, trying to create it");
        mknode_urandom().unwrap();
    }

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
