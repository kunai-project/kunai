use aya_ebpf::helpers::bpf_get_current_pid_tgid;

#[inline(always)]
pub fn bpf_task_tracking_id() -> u64 {
    bpf_get_current_pid_tgid()
}

/// Clamp `value` to `[lower, upper]` in a form the BPF verifier can follow.
///
/// The standard Rust `.clamp()` may be optimised away entirely by the compiler
/// when it can prove the value is already in range. Using inline assembly prevents
/// the compiler from eliminating the branches, so the verifier always observes them.
///
/// **`lower` and `upper` must be compile-time constants.**
#[inline(always)]
pub fn verifier_clamp(mut value: i64, lower: i64, upper: i64) -> i64 {
    unsafe {
        core::arch::asm!(
            "if {value} s> {lower} goto +1", // if value > lower, skip the floor clamp
            "{value} = {lower}",
            "if {value} s< {upper} goto +1", // if value < upper, skip the ceiling clamp
            "{value} = {upper}",
            value = inout(reg) value,
            lower = in(reg) lower,
            upper = in(reg) upper,
        );
        value
    }
}
