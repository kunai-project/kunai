use super::*;
use aya_ebpf::programs::RawTracePointContext;
use kunai_common::{co_re::task_struct, syscalls::RawSysEnterContext};

#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_MMAP: i64 = 9;
#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_MMAP: i64 = 222;

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn syscalls_sys_enter_mmap(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysEnterContext::from(ctx);
    if ctx.sys_nr() != SYS_MMAP {
        return errors::BPF_PROG_SUCCESS;
    }

    match unsafe { try_sys_enter_mmap(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_mmap(ctx: &RawSysEnterContext) -> ProbeResult<()> {
    // early return if event is disabled
    if_disabled_return!(Type::MmapExec, ());

    let prot: u64 = ctx.arg(2).unwrap_or_default();
    let fd: i32 = ctx.arg(4).unwrap_or_default();

    if fd >= 0 && prot & PROT_EXEC as u64 == PROT_EXEC as u64 {
        let current = task_struct::current();

        let file = current
            .get_fd(fd as usize)
            .ok_or(ProbeError::FileNotFound)?;

        if file.is_null() {
            return Err(ProbeError::FileNotFound);
        }

        alloc::init()?;
        let event = alloc::alloc_zero::<MmapExecEvent>()?;

        event.init_from_current_task(Type::MmapExec)?;

        event
            .data
            .filename
            .core_resolve_file(&file, MAX_PATH_DEPTH)?;

        pipe_event(ctx, event);
    }

    Ok(())
}
