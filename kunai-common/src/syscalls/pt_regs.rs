#![allow(unexpected_cfgs)]

use core::mem::offset_of;

use aya_ebpf::{bindings::pt_regs, helpers::bpf_probe_read_kernel, Argument};

/// Reads `pt_regs` argument and return-value registers via `bpf_probe_read_kernel`.
///
/// Use this when only a `*const pt_regs` obtained from a raw tracepoint context
/// is available (the pointer lives in kernel memory and must be read with
/// `bpf_probe_read_kernel`).
///
/// Field offsets are computed at compile time with [`core::mem::offset_of!`].
pub trait PtRegsKernelRead {
    /// Reads the nth function argument register.
    ///
    /// Returns `None` if `index` exceeds the number of argument registers for
    /// the target architecture or if the kernel read fails.
    ///
    /// # Safety
    ///
    /// `self` must be a valid pointer to a `pt_regs` struct in kernel memory.
    unsafe fn arg_at(&self, index: usize) -> Option<u64>;

    /// Reads the return-value register.
    ///
    /// Returns `None` if the kernel read fails.
    ///
    /// # Safety
    ///
    /// `self` must be a valid pointer to a `pt_regs` struct in kernel memory.
    unsafe fn rc(&self) -> Option<u64>;

    /// Reads the syscall number.
    ///
    /// Returns `None` if the kernel read fails.
    ///
    /// # Safety
    ///
    /// `self` must be a valid pointer to a `pt_regs` struct in kernel memory.
    unsafe fn sys_nr(&self) -> Option<i64>;
}

#[cfg(bpf_target_arch = "x86_64")]
impl PtRegsKernelRead for *const pt_regs {
    unsafe fn arg_at(&self, index: usize) -> Option<u64> {
        // System V AMD64: rdi, rsi, rdx, rcx, r8, r9
        // https://github.com/torvalds/linux/blob/v6.17/arch/x86/include/asm/ptrace.h#L103-L155
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L134-L152
        let offset = match index {
            0 => offset_of!(pt_regs, rdi),
            1 => offset_of!(pt_regs, rsi),
            2 => offset_of!(pt_regs, rdx),
            3 => offset_of!(pt_regs, rcx),
            4 => offset_of!(pt_regs, r8),
            5 => offset_of!(pt_regs, r9),
            _ => return None,
        };
        bpf_probe_read_kernel(self.byte_offset(offset as isize) as *const u64).ok()
    }

    unsafe fn rc(&self) -> Option<u64> {
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L148-L152
        bpf_probe_read_kernel(self.byte_offset(offset_of!(pt_regs, rax) as isize) as *const u64)
            .ok()
    }

    unsafe fn sys_nr(&self) -> Option<i64> {
        // x86_64 syscall number is in orig_ax
        // https://github.com/torvalds/linux/blob/v6.17/arch/x86/include/asm/ptrace.h#L120
        bpf_probe_read_kernel(
            self.byte_offset(offset_of!(pt_regs, orig_rax) as isize) as *const i64,
        )
        .ok()
    }
}

#[cfg(bpf_target_arch = "aarch64")]
impl PtRegsKernelRead for *const pt_regs {
    unsafe fn arg_at(&self, index: usize) -> Option<u64> {
        // AArch64: x0–x7 map to args 0–7 (regs[0..7])
        // https://github.com/torvalds/linux/blob/v6.17/arch/arm64/include/uapi/asm/ptrace.h#L88-L93
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L229-L244
        if index > 7 {
            return None;
        }
        let offset = offset_of!(pt_regs, regs) + index * core::mem::size_of::<u64>();
        bpf_probe_read_kernel(self.byte_offset(offset as isize) as *const u64).ok()
    }

    unsafe fn rc(&self) -> Option<u64> {
        // x0/regs[0]
        // https://github.com/torvalds/linux/blob/v6.17/tools/lib/bpf/bpf_tracing.h#L248-L251
        bpf_probe_read_kernel(self.byte_offset(offset_of!(pt_regs, regs) as isize) as *const u64)
            .ok()
    }

    unsafe fn sys_nr(&self) -> Option<i64> {
        // aya's pt_regs on aarch64 is user_pt_regs, which ends at `pstate`.
        // The full kernel pt_regs appends: orig_x0 (u64), syscallno (s32).
        // https://github.com/torvalds/linux/blob/v6.17/arch/arm64/include/asm/ptrace.h
        let offset = offset_of!(pt_regs, pstate)
            + core::mem::size_of::<u64>() // pstate
            + core::mem::size_of::<u64>(); // orig_x0
        let v: i32 = bpf_probe_read_kernel(self.byte_offset(offset as isize) as *const i32).ok()?;
        Some(v as i64)
    }
}

/// Coerces a `T` from the `n`th argument of a `pt_regs` context where `n` starts
/// at 0 and increases by 1 for each successive argument.
pub(crate) unsafe fn arg<T: Argument>(ctx: *const pt_regs, n: usize) -> Option<T> {
    let reg = ctx.arg_at(n)?;
    #[expect(clippy::allow_attributes, reason = "architecture-specific")]
    #[allow(
        clippy::cast_sign_loss,
        clippy::unnecessary_cast,
        trivial_numeric_casts,
        reason = "architecture-specific"
    )]
    Some(T::from_register(reg))
}

/// Coerces a `T` from the return value of a `pt_regs` context.
#[allow(dead_code)]
pub(crate) unsafe fn ret<T: Argument>(ctx: *const pt_regs) -> Option<T> {
    let reg = ctx.rc()?;
    #[expect(clippy::allow_attributes, reason = "architecture-specific")]
    #[allow(
        clippy::cast_sign_loss,
        clippy::unnecessary_cast,
        trivial_numeric_casts,
        reason = "architecture-specific"
    )]
    Some(T::from_register(reg))
}
