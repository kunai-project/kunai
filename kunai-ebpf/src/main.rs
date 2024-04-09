#![no_std]
#![no_main]

// bringing probes into main
#[allow(non_snake_case)]
mod probes;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
