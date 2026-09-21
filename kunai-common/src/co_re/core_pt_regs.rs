use aya_ebpf::Argument;

use super::gen::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

/// CO-RE-relocated access to the kernel's `pt_regs`.
#[allow(non_camel_case_types)]
pub type pt_regs = CoRe<gen::pt_regs>;

#[cfg(bpf_target_arch = "x86_64")]
impl pt_regs {
    rust_shim_kernel_impl!(pt_regs, di, u64);
    rust_shim_kernel_impl!(pt_regs, si, u64);
    rust_shim_kernel_impl!(pt_regs, dx, u64);
    rust_shim_kernel_impl!(pt_regs, r10, u64);
    rust_shim_kernel_impl!(pt_regs, r8, u64);
    rust_shim_kernel_impl!(pt_regs, r9, u64);
    rust_shim_kernel_impl!(pt_regs, ax, u64);
    rust_shim_kernel_impl!(pt_regs, orig_ax, u64);

    unsafe fn syscall_arg_at(&self, index: usize) -> Option<u64> {
        match index {
            0 => self.di(),
            1 => self.si(),
            2 => self.dx(),
            3 => self.r10(), // syscall ABI substitutes r10 for the usual cx slot
            4 => self.r8(),
            5 => self.r9(),
            _ => None,
        }
    }

    pub(crate) unsafe fn sys_nr(&self) -> Option<i64> {
        self.orig_ax().map(|v| v as i64)
    }
}

#[cfg(bpf_target_arch = "aarch64")]
impl pt_regs {
    rust_shim_kernel_impl!(pt_regs, reg0, u64);
    rust_shim_kernel_impl!(pt_regs, reg1, u64);
    rust_shim_kernel_impl!(pt_regs, reg2, u64);
    rust_shim_kernel_impl!(pt_regs, reg3, u64);
    rust_shim_kernel_impl!(pt_regs, reg4, u64);
    rust_shim_kernel_impl!(pt_regs, reg5, u64);
    rust_shim_kernel_impl!(pt_regs, reg6, u64);
    rust_shim_kernel_impl!(pt_regs, reg7, u64);
    rust_shim_kernel_impl!(pt_regs, syscallno, i32);

    unsafe fn syscall_arg_at(&self, index: usize) -> Option<u64> {
        match index {
            0 => self.reg0(),
            1 => self.reg1(),
            2 => self.reg2(),
            3 => self.reg3(),
            4 => self.reg4(),
            5 => self.reg5(),
            6 => self.reg6(),
            7 => self.reg7(),
            _ => None,
        }
    }

    pub(crate) unsafe fn sys_nr(&self) -> Option<i64> {
        self.syscallno().map(|v| v as i64)
    }
}

#[cfg(any(bpf_target_arch = "x86_64", bpf_target_arch = "aarch64"))]
impl pt_regs {
    /// Coerces a `T` from the `n`th argument of a `pt_regs` context where `n` starts
    /// at 0 and increases by 1 for each successive argument.
    ///
    /// # Note
    /// This function must only be used to access syscall arguments, due to register clobbering.
    pub(crate) unsafe fn syscall_arg<T: Argument>(&self, n: usize) -> Option<T> {
        let reg = self.syscall_arg_at(n)?;
        #[expect(clippy::allow_attributes, reason = "architecture-specific")]
        #[allow(
            clippy::cast_sign_loss,
            clippy::unnecessary_cast,
            trivial_numeric_casts,
            reason = "architecture-specific"
        )]
        Some(T::from_register(reg))
    }
}
