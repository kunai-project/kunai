#![deny(unused_imports)]
#![allow(static_mut_refs)]
#![no_std]
#![no_main]

// bringing probes into main
mod probes;

#[cfg(target_arch = "bpf")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
