#![no_std]
#![no_main]

mod alloc;
mod error;
mod maps;
mod util;

// bringing probes into main
mod probes;

// we make sure we define AYA_BTF_INFO Hashmap
//#[allow(unused_imports)]
//use kunai_common::btf_info::*;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
