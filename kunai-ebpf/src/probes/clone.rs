use aya_ebpf::programs::ProbeContext;
use kunai_common::{buffer, co_re::task_struct, kprobe::ProbeFn};

use super::*;

/// match-proto:v5.0:security/security.c:int security_task_alloc(struct task_struct *task, unsigned long clone_flags)
/// match-proto:v6.17:security/security.c:int security_task_alloc(struct task_struct *task, unsigned long clone_flags)
/// match-proto:latest:security/security.c:int security_task_alloc(struct task_struct *task, u64 clone_flags)
#[kprobe(function = "security_task_alloc")]
pub fn clone_enter_security_task_alloc(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    // we just save kprobe context
    unsafe { ignore_result!(ProbeFn::security_task_alloc.save_ctx(&ctx)) }
    errors::BPF_PROG_SUCCESS
}

/// match-proto:v5.0:kernel/sched/core.c:void wake_up_new_task(struct task_struct *p)
/// match-proto:latest:kernel/sched/core.c:void wake_up_new_task(struct task_struct *p)
#[kprobe(function = "wake_up_new_task")]
pub fn clone_enter_wake_up_new_task(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    let rc = match unsafe { try_enter_wake_up_new_task(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    ignore_result!(unsafe { ProbeFn::security_task_alloc.clean_ctx() });
    rc
}

unsafe fn try_enter_wake_up_new_task(ctx: &ProbeContext) -> ProbeResult<()> {
    // we make sure we've been through security_task_alloc
    if let Ok(entry_ctx) = ProbeFn::security_task_alloc
        .restore_ctx()
        .map_err(ProbeError::from)
        .map(|c| c.probe_context())
    {
        // second argument of security_task_alloc
        let clone_flags = kprobe_arg!(entry_ctx, 1)?;

        // first argument of wake_up_new_task function
        let new_task = task_struct::from_ptr(kprobe_arg!(ctx, 0)?);

        alloc::init()?;

        let event = alloc::alloc_zero::<CloneEvent>()?;

        let nsproxy = core_read_kernel!(new_task, nsproxy)?;

        // this may happen, see: https://github.com/kunai-project/kunai/issues/34
        if !nsproxy.is_null() {
            ignore_result!(inspect_err!(
                event.data.nodename.read_kernel_at(
                    core_read_kernel!(new_task, nsproxy, uts_ns, name, nodename)?,
                    event.data.nodename.cap() as u32
                ),
                |e: &buffer::Error| warn!(ctx, "failed to read nodename", (*e).into())
            ));
        }

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
            // on aarch64 this call sometimes fails for uknown reason
            // causing warning to be displayed in the kunai logs.
            // As this is not a critical error warning has been disabled.
            ignore_result!(event
                .data
                .argv
                .read_user_at(arg_start as *const u8, arg_len as u32));
        }

        // cgroup parsing
        let cgroup = core_read_kernel!(new_task, sched_task_group, css, cgroup)?;
        ignore_result!(event.data.cgroup.resolve(cgroup));

        pipe_event(ctx, event);
    }

    Ok(())
}
