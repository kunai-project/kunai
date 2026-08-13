use aya_ebpf::programs::ProbeContext;

use super::*;

/// commit_creds() is the single choke point every credential change goes through, 
/// and it runs after all the LSM fixups (cap_emulate_setxuid() and friends), so `new` 
/// holds exactly what the kernel installs on the task.
///
/// match-proto:v5.4:kernel/cred.c:int commit_creds(struct cred *new)
/// match-proto:latest:kernel/cred.c:int commit_creds(struct cred *new)
#[kprobe(function = "commit_creds")]
pub fn creds_commit_creds(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_commit_creds(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_commit_creds(ctx: &ProbeContext) -> Result<(), ProbeError> {
    if_disabled_return!(Type::CommitCreds, ());

    let new = co_re::cred::from_ptr(kprobe_arg!(ctx, 0)?);

    if new.is_null() {
        return Ok(());
    }

    // creds are not committed yet so the task still carries the old ones
    let task = co_re::task_struct::current();
    let old = core_read_kernel!(task, cred)?;

    if old.is_null() {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<CommitCredsEvent>()?;
    event.init_from_current_task(Type::CommitCreds)?;
    event.data.old.from_cred(old)?;
    event.data.new.from_cred(new)?;

    pipe_event(ctx, event);

    Ok(())
}
