use super::*;
use aya_ebpf::programs::RawTracePointContext;
use kunai_common::syscalls::RawSysEnterContext;

#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_EXIT: i64 = 60;
#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_EXIT_GROUP: i64 = 231;

#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_EXIT: i64 = 93;
#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_EXIT_GROUP: i64 = 94;

// this is important not to filter out exit event as those
// are used to clean up some structure in userland
#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscalls_sys_enter_exit(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysEnterContext::from(ctx);

    let ty = match ctx.sys_nr() {
        SYS_EXIT => Type::Exit,
        SYS_EXIT_GROUP => Type::ExitGroup,
        _ => return errors::BPF_PROG_SUCCESS,
    };

    match unsafe { try_sys_enter_exit(&ctx, ty) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_sys_enter_exit(ctx: &RawSysEnterContext, t: Type) -> ProbeResult<()> {
    alloc::init()?;
    let event = alloc::alloc_zero::<ExitEvent>()?;

    event.init_from_current_task(t)?;

    // set event data
    event.data.error_code = ctx.arg(0).unwrap_or(1337);
    pipe_event(ctx, event);

    Ok(())
}
