use super::*;
use aya_bpf::programs::TracePointContext;

#[tracepoint(name = "syscalls.sys_enter_exit")]
pub fn sys_enter_exit(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_exit(&ctx, Type::Exit) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[tracepoint(name = "syscalls.sys_enter_exit_group")]
pub fn sys_enter_exit_group(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_exit(&ctx, Type::ExitGroup) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
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

    event.init_from_btf_task(t);

    // set event data
    event.data.error_code = args.error_code;
    pipe_event(ctx, event);

    Ok(())
}
