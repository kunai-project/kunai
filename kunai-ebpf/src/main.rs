#![deny(unused_imports, clippy::all)]
#![no_std]
#![no_main]

// bringing probes into main
mod probes;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
