use aya_ebpf::cty::c_void;

use super::{gen, CoRe};
use core::ptr;

#[no_mangle]
static PAGE_SIZE: u64 = 0;

#[no_mangle]
static PAGE_SHIFT: u64 = 0;

#[inline(always)]
pub fn page_shift() -> u64 {
    unsafe { ptr::read_volatile(&PAGE_SHIFT) }
}

#[inline(always)]
pub fn page_size() -> u64 {
    unsafe { ptr::read_volatile(&PAGE_SIZE) }
}

#[allow(non_camel_case_types)]
pub type page = CoRe<gen::page>;

impl page {
    pub fn to_va(&self) -> *const c_void {
        ((self.as_ptr() as u64 / page_size()) << page_shift()) as *const _
    }
}
