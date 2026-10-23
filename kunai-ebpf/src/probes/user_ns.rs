use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use kunai_common::kprobe::ProbeFn;

use super::*;

// map_write() is static and may be inlined, so we hook its callers. We need a
// kretprobe as maps are only set once the write succeeded.

/// match-proto:v5.0:kernel/user_namespace.c:ssize_t proc_uid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
/// match-proto:latest:kernel/user_namespace.c:ssize_t proc_uid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
#[kprobe(function = "proc_uid_map_write")]
pub fn user_ns_enter_proc_uid_map_write(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    unsafe { ignore_result!(ProbeFn::user_ns_proc_uid_map_write.save_ctx(&ctx)) }
    0
}

/// match-proto:v5.0:kernel/user_namespace.c:ssize_t proc_uid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
/// match-proto:latest:kernel/user_namespace.c:ssize_t proc_uid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
#[kretprobe(function = "proc_uid_map_write")]
pub fn user_ns_exit_proc_uid_map_write(exit_ctx: RetProbeContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    exit_map_write(&exit_ctx, ProbeFn::user_ns_proc_uid_map_write)
}

/// match-proto:v5.0:kernel/user_namespace.c:ssize_t proc_gid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
/// match-proto:latest:kernel/user_namespace.c:ssize_t proc_gid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
#[kprobe(function = "proc_gid_map_write")]
pub fn user_ns_enter_proc_gid_map_write(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    unsafe { ignore_result!(ProbeFn::user_ns_proc_gid_map_write.save_ctx(&ctx)) }
    0
}

/// match-proto:v5.0:kernel/user_namespace.c:ssize_t proc_gid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
/// match-proto:latest:kernel/user_namespace.c:ssize_t proc_gid_map_write(struct file *file, const char __user *buf, size_t size, loff_t *ppos)
#[kretprobe(function = "proc_gid_map_write")]
pub fn user_ns_exit_proc_gid_map_write(exit_ctx: RetProbeContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    exit_map_write(&exit_ctx, ProbeFn::user_ns_proc_gid_map_write)
}

#[inline(always)]
fn exit_map_write(exit_ctx: &RetProbeContext, f: ProbeFn) -> u32 {
    let rc = match unsafe {
        f.restore_ctx()
            .map_err(ProbeError::from)
            .and_then(|entry_ctx| {
                let entry_ctx = &entry_ctx.probe_context();
                let file = co_re::file::from_ptr(kprobe_arg!(entry_ctx, 0)?);
                handle_map_write(exit_ctx, file)
            })
    } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(exit_ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    // we cleanup entry context
    ignore_result!(unsafe { f.clean_ctx() });
    rc
}

#[inline(always)]
unsafe fn handle_map_write(exit_ctx: &RetProbeContext, file: co_re::file) -> ProbeResult<()> {
    unsafe {
        let rc: isize = exit_ctx.ret();
        if rc <= 0 {
            return Ok(());
        }

        // the ns whose map got written, not necessarily the writer's one
        let seq = co_re::seq_file::from_ptr(core_read_kernel!(file, private_data)? as *mut _);
        let ns = co_re::user_namespace::from_ptr(core_read_kernel!(seq, private)? as *mut _);
        if ns.is_null() {
            return Ok(());
        }

        alloc::init()?;
        let event = alloc::alloc_zero::<UserNsMapEvent>()?;
        event.init_from_current_task(Type::UserNsMap)?;
        event.data.user_ns.from_user_namespace(ns);

        pipe_event(exit_ctx, event);
        Ok(())
    }
}
