use super::*;

use aya_bpf::{maps::LruHashMap, programs::TracePointContext};
use kunai_common::syscalls::{SysEnterArgs, SysExitArgs};

#[map]
static mut PRCTL_ARGS: LruHashMap<u64, SysEnterArgs<PrctlArgs>> =
    LruHashMap::with_max_entries(1024, 0);

#[repr(C)]
struct PrctlArgs {
    option: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
}

#[tracepoint(name = "syscalls.sys_enter_prctl")]
pub fn sys_enter_prctl(ctx: TracePointContext) -> u32 {
    match unsafe { try_enter_prctl(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_enter_prctl(ctx: &TracePointContext) -> ProbeResult<()> {
    let args = SysEnterArgs::<PrctlArgs>::from_context(ctx)?;

    // we ignore result as we can check something went wrong when we try to insert argument
    ignore_result!(PRCTL_ARGS.insert(&bpf_task_tracking_id(), &args, 0));

    return Ok(());
}

#[tracepoint(name = "syscalls.sys_exit_prctl")]
pub fn sys_exit_prctl(ctx: TracePointContext) -> u32 {
    match unsafe { try_exit_prctl(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_exit_prctl(ctx: &TracePointContext) -> ProbeResult<()> {
    let exit_args = SysExitArgs::from_context(ctx)?;
    let key = bpf_task_tracking_id();

    let entry_args = PRCTL_ARGS.get(&key).ok_or(errors::MapError::GetFailure)?;

    alloc::init()?;
    let event = alloc::alloc_zero::<PrctlEvent>()?;

    event.init_from_current_task(Type::Prctl)?;

    event.data.option = entry_args.args.option;
    event.data.arg2 = entry_args.args.arg2;
    event.data.arg3 = entry_args.args.arg3;
    event.data.arg4 = entry_args.args.arg4;
    event.data.arg5 = entry_args.args.arg5;
    // on error returns -1
    event.data.success = exit_args.ret != -1;

    pipe_event(ctx, event);

    // cleanup prctl arguments no need to handle failure
    ignore_result!(PRCTL_ARGS.remove(&key));

    return Ok(());
}
