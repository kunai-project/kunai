use aya_ebpf::{cty::c_uint, programs::ProbeContext};

use super::*;

#[kprobe(function = "security_ptrace_access_check")]
pub fn kprobe_ptrace_access_check(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_ptrace_access_check(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_ptrace_access_check(ctx: &ProbeContext) -> Result<(), ProbeError> {
    let target = co_re::task_struct::from_ptr(kprobe_arg!(ctx, 0)?);
    let mode: c_uint = kprobe_arg!(ctx, 1)?;

    // only catch PTRACE_MODE_ATTACH
    if mode & 0x2 != 0x2 {
        return Ok(());
    }

    // initialize allocator
    alloc::init()?;
    // alloc a new event
    let event = alloc::alloc_zero::<PtraceEvent>()?;
    // initialize eventc
    event.init_from_current_task(Type::Ptrace)?;
    // ptrace mode
    event.data.mode = mode;
    // initialize target task
    event.data.target.from_task(target)?;

    pipe_event(ctx, event);

    Ok(())
}
