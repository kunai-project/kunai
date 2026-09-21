use crate::co_re::pt_regs;

use aya_ebpf::{cty::c_long, programs::RawTracePointContext, Argument, EbpfContext};

/// A raw_tracepoint attached to "sys_enter" receives its arguments as
/// declared in the kernel's `TP_PROTO(struct pt_regs *regs, long id)` for
/// that tracepoint: `args[0]` is `regs`, `args[1]` is `id` (the syscall
/// number). This is what tells us `ctx.arg(0)` is the `pt_regs` pointer
/// and `ctx.arg(1)` is the syscall number below.
///
/// https://elixir.bootlin.com/linux/v7.2/source/include/trace/events/syscalls.h#L18
#[repr(C)]
pub struct RawSysEnterContext {
    ctx: RawTracePointContext,
    pt_regs: pt_regs,
    sys_nr: c_long,
}

impl From<RawTracePointContext> for RawSysEnterContext {
    fn from(ctx: RawTracePointContext) -> Self {
        let pt_regs = pt_regs::from_ptr(ctx.arg(0));
        let sys_nr: i64 = ctx.arg(1);
        Self {
            ctx,
            pt_regs,
            sys_nr,
        }
    }
}

impl EbpfContext for RawSysEnterContext {
    #[inline(always)]
    fn as_ptr(&self) -> *mut aya_ebpf::cty::c_void {
        self.ctx.as_ptr()
    }
}

impl RawSysEnterContext {
    #[inline(always)]
    pub unsafe fn arg<T: Argument>(&self, n: usize) -> Option<T> {
        self.pt_regs.syscall_arg(n)
    }

    #[inline(always)]
    pub fn sys_nr(&self) -> i64 {
        self.sys_nr
    }
}

/// A raw_tracepoint attached to "sys_exit" receives its arguments as
/// declared in the kernel's `TP_PROTO(struct pt_regs *regs, long ret)` for
/// that tracepoint: `args[0]` is `regs`, `args[1]` is `ret` (the syscall
/// return value). Note there is no syscall number argument here (unlike
/// sys_enter), which is why `sys_nr()` below has to read it back out of
/// `regs` instead of taking it straight from an arg.
///
/// https://elixir.bootlin.com/linux/v7.2/source/include/trace/events/syscalls.h#L46
#[repr(C)]
pub struct RawSysExitContext {
    ctx: RawTracePointContext,
    pt_regs: pt_regs,
    ret: c_long,
}

impl From<RawTracePointContext> for RawSysExitContext {
    fn from(ctx: RawTracePointContext) -> Self {
        let pt_regs = pt_regs::from_ptr(ctx.arg(0));
        let ret: i64 = ctx.arg(1);
        Self { ctx, pt_regs, ret }
    }
}

impl EbpfContext for RawSysExitContext {
    #[inline(always)]
    fn as_ptr(&self) -> *mut aya_ebpf::cty::c_void {
        self.ctx.as_ptr()
    }
}

impl RawSysExitContext {
    #[inline(always)]
    pub fn ret(&self) -> c_long {
        self.ret
    }

    #[inline(always)]
    pub unsafe fn sys_nr(&self) -> Option<i64> {
        self.pt_regs.sys_nr()
    }
}
