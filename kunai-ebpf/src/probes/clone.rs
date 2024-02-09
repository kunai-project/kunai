use aya_bpf::programs::ProbeContext;
use kunai_common::co_re::task_struct;

use super::*;

#[kprobe(name = "clone.enter.security_task_alloc")]
pub fn security_task_alloc(ctx: ProbeContext) -> u32 {
    let rc = match unsafe { try_enter_wake_up_new_task(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    rc
}

unsafe fn try_enter_wake_up_new_task(ctx: &ProbeContext) -> ProbeResult<()> {
    let new_task = task_struct::from_ptr(kprobe_arg!(ctx, 0)?);
    let clone_flags = kprobe_arg!(&ctx, 1)?;

    alloc::init()?;

    let event = alloc::alloc_zero::<CloneEvent>()?;

    // initializing task
    event.init_from_task(Type::Clone, new_task)?;

    // setting clone flags
    event.data.flags = clone_flags;

    let mm = core_read_kernel!(new_task, mm)?;

    if mm.is_null() {
        return Ok(());
    }

    let arg_start = core_read_kernel!(mm, arg_start)?;
    let arg_len = core_read_kernel!(mm, arg_len)?;

    // parsing executable
    let exe_file = core_read_kernel!(mm, exe_file)?;
    ignore_result!(inspect_err!(
        event
            .data
            .executable
            .core_resolve_file(&exe_file, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve exe", (*e).into())
    ));

    // we check that arg_start is not a null pointer
    if arg_start != 0 && arg_len != 0 {
        ignore_result!(inspect_err!(
            event
                .data
                .argv
                .read_user_at(arg_start as *const u8, arg_len as u32),
            |_| warn_msg!(ctx, "failed to read argv")
        ));
    }

    // cgroup parsing
    let cgroup = core_read_kernel!(new_task, sched_task_group, css, cgroup)?;
    ignore_result!(event.data.cgroup.resolve(cgroup));

    pipe_event(ctx, event);

    Ok(())
}
