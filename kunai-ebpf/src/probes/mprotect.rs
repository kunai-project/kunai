use super::*;
use aya_ebpf::programs::RawTracePointContext;
use kunai_common::syscalls::RawSysEnterContext;

#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_MPROTECT: i64 = 10;
#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_MPROTECT: i64 = 226;

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscalls_sys_enter_mprotect(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysEnterContext::from(ctx);
    if ctx.sys_nr() != SYS_MPROTECT {
        return errors::BPF_PROG_SUCCESS;
    }

    match unsafe { try_sys_enter_mprotect(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_mprotect(ctx: &RawSysEnterContext) -> ProbeResult<()> {
    // early return if event is disabled
    if_disabled_return!(Type::MprotectExec, ());

    let start: u64 = ctx.arg(0).unwrap_or_default();
    let len: u64 = ctx.arg(1).unwrap_or_default();
    let prot: u64 = ctx.arg(2).unwrap_or_default();

    if prot & PROT_EXEC as u64 == PROT_EXEC as u64 {
        alloc::init()?;
        let event = alloc::alloc_zero::<MprotectEvent>()?;

        event.init_from_current_task(Type::MprotectExec)?;

        // setting event data
        event.data.start = start;
        event.data.prot = prot;
        event.data.len = len;

        pipe_event(ctx, event);
    }

    Ok(())
}
