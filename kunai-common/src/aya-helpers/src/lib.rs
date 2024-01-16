#![cfg_attr(target_arch = "bpf", feature(asm_experimental_arch))]
#![no_std]
// this file is a simplified version of https://github.com/aya-rs/aya/blob/main/bpf/aya-bpf/src/lib.rs

/// Check if a value is within a range, using conditional forms compatible with
/// the verifier.
#[inline(always)]
pub fn check_bounds_signed(value: i64, lower: i64, upper: i64) -> bool {
    #[cfg(target_arch = "bpf")]
    unsafe {
        let mut in_bounds = 0u64;
        core::arch::asm!(
            "if {value} s< {lower} goto +2",
            "if {value} s> {upper} goto +1",
            "{i} = 1",
            i = inout(reg) in_bounds,
            lower = in(reg) lower,
            upper = in(reg) upper,
            value = in(reg) value,
        );
        in_bounds == 1
    }
    // We only need this for doc tests which are compiled for the host target
    #[cfg(not(target_arch = "bpf"))]
    {
        let _ = value;
        let _ = lower;
        let _ = upper;
        unimplemented!()
    }
}

pub mod helpers;
