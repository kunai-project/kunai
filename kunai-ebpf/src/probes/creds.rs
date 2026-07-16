use aya_ebpf::{programs::ProbeContext, EbpfContext};

use kunai_common::bpf_events::{CredSnapshot, CredsChangeKind, CredsEvent};

use super::*;

#[inline(always)]
unsafe fn snapshot_cred(c: &co_re::cred) -> Result<CredSnapshot, ProbeError> {
    Ok(CredSnapshot {
        uid: core_read_kernel!(c, uid)?,
        gid: core_read_kernel!(c, gid)?,
        euid: core_read_kernel!(c, euid)?,
        egid: core_read_kernel!(c, egid)?,
        suid: core_read_kernel!(c, suid)?,
        sgid: core_read_kernel!(c, sgid)?,
        fsuid: core_read_kernel!(c, fsuid)?,
        fsgid: core_read_kernel!(c, fsgid)?,
        cap_effective: core_read_kernel!(c, cap_effective)?,
        cap_permitted: core_read_kernel!(c, cap_permitted)?,
        cap_inheritable: core_read_kernel!(c, cap_inheritable)?,
    })
}

#[inline(always)]
unsafe fn emit_creds_event<C: EbpfContext>(
    ctx: &C,
    new: &co_re::cred,
    old: &co_re::cred,
    kind: CredsChangeKind,
    flags: LsmSetIdFlags,
) -> Result<(), ProbeError> {
    if new.is_null() || old.is_null() {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<CredsEvent>()?;
    event.init_from_current_task(Type::SetCreds)?;
    event.data.kind = kind;
    event.data.flags = flags;
    event.data.old = snapshot_cred(old)?;
    event.data.new = snapshot_cred(new)?;

    pipe_event(ctx, event);
    Ok(())
}

#[kprobe(function = "security_task_fix_setuid")]
pub fn creds_security_task_fix_setuid(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_task_fix_setuid(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_security_task_fix_setuid(ctx: &ProbeContext) -> Result<(), ProbeError> {
    if_disabled_return!(Type::SetCreds, ());

    let new = co_re::cred::from_ptr(kprobe_arg!(ctx, 0)?);
    let old = co_re::cred::from_ptr(kprobe_arg!(ctx, 1)?);
    let flags: i32 = kprobe_arg!(ctx, 2)?;

    emit_creds_event(
        ctx,
        &new,
        &old,
        CredsChangeKind::SetUid,
        LsmSetIdFlags::from_bits(flags),
    )
}

#[kprobe(function = "security_task_fix_setgid")]
pub fn creds_security_task_fix_setgid(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_task_fix_setgid(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_security_task_fix_setgid(ctx: &ProbeContext) -> Result<(), ProbeError> {
    if_disabled_return!(Type::SetCreds, ());

    let new = co_re::cred::from_ptr(kprobe_arg!(ctx, 0)?);
    let old = co_re::cred::from_ptr(kprobe_arg!(ctx, 1)?);
    let flags: i32 = kprobe_arg!(ctx, 2)?;

    emit_creds_event(
        ctx,
        &new,
        &old,
        CredsChangeKind::SetGid,
        LsmSetIdFlags::from_bits(flags),
    )
}

#[kprobe(function = "security_capset")]
pub fn creds_security_capset(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_capset(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_security_capset(ctx: &ProbeContext) -> Result<(), ProbeError> {
    if_disabled_return!(Type::SetCreds, ());

    let new = co_re::cred::from_ptr(kprobe_arg!(ctx, 0)?);
    let old = co_re::cred::from_ptr(kprobe_arg!(ctx, 1)?);

    emit_creds_event(
        ctx,
        &new,
        &old,
        CredsChangeKind::Capset,
        LsmSetIdFlags::empty(),
    )
}
