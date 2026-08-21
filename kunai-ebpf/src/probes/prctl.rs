use super::*;

use aya_ebpf::{maps::LruHashMap, programs::RawTracePointContext};
use kunai_common::syscalls::{RawSysEnterContext, RawSysExitContext};

#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_PRCTL: i64 = 157;
#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_PRCTL: i64 = 167;

#[map]
static mut PRCTL_ARGS: LruHashMap<u64, PrctlData> = LruHashMap::with_max_entries(1024, 0);

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscalls_sys_enter_prctl(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysEnterContext::from(ctx);
    if ctx.sys_nr() != SYS_PRCTL {
        return errors::BPF_PROG_SUCCESS;
    }

    match unsafe { try_enter_prctl(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_enter_prctl(ctx: &RawSysEnterContext) -> ProbeResult<()> {
    // early return if event is disabled
    if_disabled_return!(Type::Prctl, ());

    // we need it for kernel 5.4 to prove entire memory is written
    let mut args = core::mem::zeroed::<PrctlData>();
    args.option = ctx.arg(0).unwrap_or_default();
    args.arg2 = ctx.arg(1).unwrap_or_default();
    args.arg3 = ctx.arg(2).unwrap_or_default();
    args.arg4 = ctx.arg(3).unwrap_or_default();
    args.arg5 = ctx.arg(4).unwrap_or_default();
    args.success = false;

    // we ignore result as we can check something went wrong when we try to insert argument
    ignore_result!(PRCTL_ARGS.insert(&bpf_task_tracking_id(), &args, 0));

    Ok(())
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn syscalls_sys_exit_prctl(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysExitContext::from(ctx);

    unsafe {
        if ctx.sys_nr() != Some(SYS_PRCTL) {
            return errors::BPF_PROG_SUCCESS;
        }
    }

    match unsafe { try_exit_prctl(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_exit_prctl(ctx: &RawSysExitContext) -> ProbeResult<()> {
    // early return if event is disabled
    if_disabled_return!(Type::Prctl, ());

    let key = bpf_task_tracking_id();

    let entry_args = *(PRCTL_ARGS.get(&key).ok_or(errors::MapError::GetFailure)?);

    alloc::init()?;
    let event = alloc::alloc_zero::<PrctlEvent>()?;

    event.init_from_current_task(Type::Prctl)?;

    event.data = entry_args;
    // on error returns -1
    event.data.success = ctx.ret() != -1;

    pipe_event(ctx, event);

    // cleanup prctl arguments no need to handle failure
    ignore_result!(PRCTL_ARGS.remove(&key));

    Ok(())
}
