#![allow(unexpected_cfgs)]

use aya_ebpf::cty::c_void;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
use aya_ebpf::helpers::bpf_probe_read_kernel;

use super::{
    gen::{self, shim_size_of_page},
    CoRe,
};
use core::ptr;

#[no_mangle]
static PAGE_SIZE: u64 = 0;

#[no_mangle]
static PAGE_SHIFT: u64 = 0;

#[cfg(bpf_target_arch = "x86_64")]
#[no_mangle]
static VMEMMAP_BASE_PTR: u64 = 0;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
static mut VMEMMAP_BASE: u64 = 0;

#[cfg(bpf_target_arch = "x86_64")]
#[no_mangle]
static PAGE_OFFSET_BASE_PTR: u64 = 0;
#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
static mut PAGE_OFFSET_BASE: u64 = 0;

/// Returns the kernel page shift (i.e., `log2(page_size)`).
#[inline(always)]
pub fn page_shift() -> u64 {
    unsafe { ptr::read_volatile(&PAGE_SHIFT) }
}

/// Returns the kernel page size in bytes.
#[inline(always)]
pub fn page_size() -> u64 {
    unsafe { ptr::read_volatile(&PAGE_SIZE) }
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn vmemmap_base() -> u64 {
    unsafe {
        if VMEMMAP_BASE == 0 {
            let addr = ptr::read_volatile(&VMEMMAP_BASE_PTR) as *const u64;
            VMEMMAP_BASE = bpf_probe_read_kernel(addr).unwrap_or(0);
        }
        VMEMMAP_BASE
    }
}

#[cfg(bpf_target_arch = "x86_64")]
#[inline(always)]
fn page_offset_base() -> u64 {
    unsafe {
        if PAGE_OFFSET_BASE == 0 {
            let addr = ptr::read_volatile(&PAGE_OFFSET_BASE_PTR) as *const u64;
            PAGE_OFFSET_BASE = bpf_probe_read_kernel(addr).unwrap_or(0);
        }
        PAGE_OFFSET_BASE
    }
}

#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn mem_layout_aarch64(page_ptr: u64) -> (u64, u64) {
    unsafe {
        if PAGE_OFFSET_BASE == 0 || PAGE_OFFSET_BASE == 0 {
            (VMEMMAP_BASE, PAGE_OFFSET_BASE) =
                find_mem_layout_aarch64(page_ptr).unwrap_or_default();
        }
        (VMEMMAP_BASE, PAGE_OFFSET_BASE)
    }
}

#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn is_kernel_memory_readable<T>(addr: u64) -> bool {
    unsafe { bpf_probe_read_kernel(addr as *const T).is_ok() }
}

#[cfg(bpf_target_arch = "aarch64")]
const ARM64_LAYOUT_CANDIDATES: &[(u64, u64)] = &[
    // (VMEMMAP_START, PAGE_OFFSET)

    // 4K pages, 48-bit VA
    (0xfffffc0000000000, 0xffff000000000000),
    // 64K pages, 52-bit VA
    (0xfffffc0000000000, 0xfff0000000000000),
];

#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn is_page_readable(virt: u64) -> bool {
    let page_sz = 1u64 << page_shift();

    is_kernel_memory_readable::<u64>(virt)
        && is_kernel_memory_readable::<u64>(virt.wrapping_add(page_sz >> 1))
        && is_kernel_memory_readable::<u64>(
            virt.wrapping_add(page_sz - core::mem::size_of::<u64>() as u64),
        )
}

/// Infers `(VMEMMAP_START, PAGE_OFFSET)` from a known `struct page` pointer.
///
/// Iterates over known aarch64 layout candidates and returns the first pair
/// whose derived virtual address is readable via `bpf_probe_read_kernel`.
/// Returns `None` if no candidate matches.
#[cfg(bpf_target_arch = "aarch64")]
#[inline(always)]
fn find_mem_layout_aarch64(page_ptr: u64) -> Option<(u64, u64)> {
    let struct_page_size = page::size_of();
    let shift = page_shift();

    for &(vmemmap_start, page_offset) in ARM64_LAYOUT_CANDIDATES {
        if page_ptr >= vmemmap_start {
            let idx = page_ptr.wrapping_sub(vmemmap_start) / struct_page_size;
            let virt = page_offset.wrapping_add(idx << shift);

            if is_page_readable(virt) {
                return Some((vmemmap_start, page_offset));
            }
        }
    }

    None
}

/// BPF CO-RE wrapper for the kernel `struct page`.
#[allow(non_camel_case_types)]
pub type page = CoRe<gen::page>;

impl page {
    /// Returns the size of `struct page` as reported by the kernel via CO-RE.
    #[inline(always)]
    pub fn size_of() -> u64 {
        unsafe { shim_size_of_page() }
    }

    /// Converts this `struct page` pointer to its virtual address.
    ///
    /// Returns a null pointer on unsupported architectures.
    pub fn page_to_virt(&self) -> Option<*const c_void> {
        cfg_select! {
           bpf_target_arch = "x86_64" => Some(self.page_to_virt_x86_64()),
           bpf_target_arch = "aarch64" => Some(self.page_to_virt_aarch64()),
           _ => None
        }
    }

    #[cfg(bpf_target_arch = "x86_64")]
    #[inline(always)]
    fn page_to_virt_x86_64(&self) -> *const c_void {
        let vmemmap = vmemmap_base();
        let page_offset = page_offset_base();

        self._page_to_virt(vmemmap, page_offset)
    }

    #[cfg(bpf_target_arch = "aarch64")]
    #[inline(always)]
    fn page_to_virt_aarch64(&self) -> *const c_void {
        let (vmemmap, page_offset) = mem_layout_aarch64(self.as_ptr() as u64);

        self._page_to_virt(vmemmap, page_offset)
    }

    #[inline(always)]
    fn _page_to_virt(&self, vmemmap: u64, page_offset: u64) -> *const c_void {
        let pfn = (self.as_ptr() as u64).wrapping_sub(vmemmap) / page::size_of();
        let phys = pfn << page_shift();
        phys.wrapping_add(page_offset) as *const c_void
    }
}
