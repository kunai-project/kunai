use aya_ebpf::programs::ProbeContext;

use super::*;

/// this probe is hit when the system is resumed, it is a way to
/// create a trigger for program reload as a bug has been identified
/// for some kretprobes not surviving to a suspend/resume cycle
/// https://bugzilla.kernel.org/show_bug.cgi?id=218775
///
/// match-proto:v5.0:drivers/base/syscore.c:void syscore_resume(void)
/// match-proto:latest:drivers/base/syscore.c:void syscore_resume(void)
#[kprobe(function = "syscore_resume")]
pub fn enter_syscore_resume(ctx: ProbeContext) -> u32 {
    match unsafe { try_syscore_resume(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_syscore_resume(ctx: &ProbeContext) -> ProbeResult<()> {
    let evt = alloc::alloc_zero::<SysCoreResumeEvent>()?;

    evt.init_from_current_task(Type::SyscoreResume)?;

    pipe_event(ctx, evt);
    Ok(())
}
