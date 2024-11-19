use super::*;
use aya_ebpf::programs::TracePointContext;
use kunai_common::syscalls::{SysEnterArgs, Syscall};

// this is important not to filter out exit event as those
// are used to clean up some structure in userland
#[tracepoint(name = "sys_enter_exit", category = "syscalls")]
pub fn syscalls_sys_enter_exit(ctx: TracePointContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_sys_enter_exit(&ctx, Type::Exit) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

// this is important not to filter out exit_group event as those
// are used to clean up some structure in userland
#[tracepoint(name = "sys_enter_exit_group", category = "syscalls")]
pub fn syscalls_sys_enter_exit_group(ctx: TracePointContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

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
