use super::*;
use aya_bpf::programs::TracePointContext;
use kunai_common::syscalls::{SysEnterArgs, Syscall};

#[tracepoint(name = "syscalls_0x2e_sys_enter_exit")]
pub fn sys_enter_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_exit(&ctx, Type::Exit) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[tracepoint(name = "syscalls_0x2e_sys_enter_exit_group")]
pub fn sys_enter_exit_group(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_exit(&ctx, Type::ExitGroup) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[repr(C)]
struct SysEnterExitArgs {
    syscall: Syscall,
    error_code: u64,
}

#[inline(always)]
unsafe fn try_sys_enter_exit(ctx: &TracePointContext, t: Type) -> ProbeResult<()> {
    alloc::init()?;
    // map_err here (while in theory unecessary) prevents the verifier from failing !
    let args = SysEnterArgs::<SysEnterExitArgs>::from_context(ctx)?.args;
    let event = alloc::alloc_zero::<ExitEvent>()?;

    event.init_from_current_task(t)?;

    // set event data
    event.data.error_code = args.error_code;
    pipe_event(ctx, event);

    Ok(())
}
