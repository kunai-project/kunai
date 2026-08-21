use super::pt_regs::{arg, PtRegsKernelRead};

use aya_ebpf::{
    bindings::pt_regs, cty::c_long, programs::RawTracePointContext, Argument, EbpfContext,
};

#[repr(C)]
pub struct RawSysEnterContext {
    ctx: RawTracePointContext,
    pt_regs: *const pt_regs,
    sys_nr: c_long,
}

impl From<RawTracePointContext> for RawSysEnterContext {
    fn from(ctx: RawTracePointContext) -> Self {
        let pt_regs = ctx.arg::<*const pt_regs>(0);
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
        arg(self.pt_regs, n)
    }

    #[inline(always)]
    pub fn sys_nr(&self) -> i64 {
        self.sys_nr
    }
}

#[repr(C)]
pub struct RawSysExitContext {
    ctx: RawTracePointContext,
    pt_regs: *const pt_regs,
    ret: c_long,
}

impl From<RawTracePointContext> for RawSysExitContext {
    fn from(ctx: RawTracePointContext) -> Self {
        let pt_regs = ctx.arg::<*const pt_regs>(0);
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
