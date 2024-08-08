use aya_ebpf::{cty::c_int, programs::ProbeContext};

use super::*;

#[kprobe(function = "security_task_kill")]
pub fn enter_security_task_kill(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_security_task_kill(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_enter_security_task_kill(ctx: &ProbeContext) -> ProbeResult<()> {
    let target = co_re::task_struct::from_ptr(kprobe_arg!(ctx, 0)?);
    let sig: c_int = kprobe_arg!(ctx, 2)?;

    // signal can be 0 but no signal is actually sent to the target
    // it is used only to check if the task can be killed
    if sig == 0 {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<KillEvent>()?;

    event.init_from_current_task(Type::Kill)?;

    event.data.signal = sig as u8;
    event.data.target.from_task(target)?;

    pipe_event(ctx, event);

    Ok(())
}
