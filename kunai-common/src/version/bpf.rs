use super::KernelVersion;
use core::ptr;

#[no_mangle]
static LINUX_KERNEL_VERSION: KernelVersion = KernelVersion::MIN_VERSION;

#[inline(always)]
pub fn kernel_version() -> KernelVersion {
    unsafe { ptr::read_volatile(&LINUX_KERNEL_VERSION) }
}
