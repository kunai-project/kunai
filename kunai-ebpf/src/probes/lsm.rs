use core::ffi::c_void;

use aya_ebpf::{cty::c_int, programs::LsmContext};

use super::*;

enum LsmStatus {
    Continue(i32),
    Block,
}

impl From<LsmStatus> for i32 {
    #[inline(always)]
    fn from(value: LsmStatus) -> Self {
        match value {
            LsmStatus::Block => -1,
            LsmStatus::Continue(ret) => ret,
        }
    }
}

#[lsm(hook = "task_kill")]
pub fn lsm_task_kill(ctx: LsmContext) -> i32 {
    match unsafe { try_lsm_security_task_kill(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
unsafe fn try_lsm_security_task_kill(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let target = co_re::task_struct::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    let sig: c_int = ctx.arg(2);
    // previous hook return code
    let ret: c_int = ctx.arg(4);

    // signal can be 0 but no signal is actually sent to the target
    // it is used only to check if the task can be killed
    if sig == 0 {
        return Ok(LsmStatus::Continue(ret));
    }

    let target_tgid = core_read_kernel!(target, tgid)?;

    // if the target is not kunai we let it go
    if target_tgid as u32 != get_cfg!()?.loader.tgid {
        return Ok(LsmStatus::Continue(ret));
    }

    // we block any attempt to send a signal to kunai
    Ok(LsmStatus::Block)
}

#[lsm(hook = "ptrace_access_check")]
pub fn lsm_ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
unsafe fn try_ptrace_access_check(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let target = co_re::task_struct::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    // previous hook return code
    let ret: c_int = ctx.arg(2);

    let target_tgid = core_read_kernel!(target, tgid)?;

    // if the target is not kunai we let it go
    if target_tgid as u32 != get_cfg!()?.loader.tgid {
        return Ok(LsmStatus::Continue(ret));
    }

    // we block any attempt to ptrace kunai
    Ok(LsmStatus::Block)
}
