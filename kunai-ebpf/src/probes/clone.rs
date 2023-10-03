use aya_bpf::programs::ProbeContext;
use kunai_common::co_re::{kernel_clone_args, task_struct};

use super::*;

#[kprobe(name = "enter.wake_up_new_task")]
pub fn enter_wake_up_new_task(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_wake_up_new_task(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_enter_wake_up_new_task(ctx: &ProbeContext) -> ProbeResult<()> {
    // makes sure we are inside kernel_clone
    if let Ok(entry_ctx) = restore_entry_ctx(ProbeFn::kernel_clone)
        .ok_or(ProbeError::KProbeCtxRestoreFailure)
        .and_then(|c| Ok(c.probe_context()))
    {
        let clone_args = kernel_clone_args::from_ptr(kprobe_arg!(&entry_ctx, 0)?);
        let new_task = task_struct::from_ptr(kprobe_arg!(ctx, 0)?);
        alloc::init()?;

        let event = alloc::alloc_zero::<CloneEvent>()?;

        // initializing task
        event.init_from_task(Type::Clone, new_task)?;

        // setting clone flags
        event.data.flags = core_read_kernel!(clone_args, flags)?;

        let mm = core_read_kernel!(new_task, mm)?;

        if mm.is_null() {
            return Ok(());
        }

        let arg_start = core_read_kernel!(mm, arg_start)?;
        let arg_len = core_read_kernel!(mm, arg_len)?;

        // parsing executable
        let exe_file = core_read_kernel!(mm, exe_file)?;
        inspect_err!(
            event
                .data
                .executable
                .core_resolve_file(&exe_file, MAX_PATH_DEPTH),
            |e: path::Error| error!(ctx, "failed to resolve exe: {}", e.description())
        );

        // we check that arg_start is not a null pointer
        if arg_start != 0 && arg_len != 0 {
            inspect_err!(
                event
                    .data
                    .argv
                    .read_user_at(arg_start as *const u8, arg_len as u32),
                |_| error!(ctx, "failed to read argv")
            );
        }

        // cgroup parsing
        let cgroup = core_read_kernel!(new_task, sched_task_group, css, cgroup)?;
        if let Err(e) = event.data.cgroup.resolve(cgroup) {
            error!(ctx, "failed to resolve cgroup: {}", e.description());
        }

        pipe_event(ctx, event)
    }

    Ok(())
}
