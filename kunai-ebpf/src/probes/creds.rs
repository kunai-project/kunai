use core::ffi::c_void;

use aya_ebpf::{cty::c_int, programs::ProbeContext, EbpfContext};

use kunai_common::bpf_events::{CredSnapshot, CredsChangeKind, CredsEvent};

use super::*;

#[inline(always)]
unsafe fn snapshot_cred(c: &co_re::cred) -> CredSnapshot {
    CredSnapshot {
        uid: c.uid(),
        gid: c.gid(),
        euid: c.euid(),
        egid: c.egid(),
        suid: c.suid(),
        sgid: c.sgid(),
        fsuid: c.fsuid(),
        fsgid: c.fsgid(),
        cap_effective: c.cap_effective(),
        cap_permitted: c.cap_permitted(),
        cap_inheritable: c.cap_inheritable(),
    }
}

#[inline(always)]
unsafe fn emit_creds_event<C: EbpfContext>(
    ctx: &C,
    new: &co_re::cred,
    old: &co_re::cred,
    kind: CredsChangeKind,
    flags: u32,
) -> Result<(), ProbeError> {
    if new.is_null() || old.is_null() {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<CredsEvent>()?;
    event.init_from_current_task(Type::SetCreds)?;
    event.data.kind = kind;
    event.data.flags = flags;
    event.data.old = snapshot_cred(old);
    event.data.new = snapshot_cred(new);

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

    let new = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(0).unwrap_or(core::ptr::null()) as *const _,
    );
    let old = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(1).unwrap_or(core::ptr::null()) as *const _,
    );
    let flags: c_int = ctx.arg(2).unwrap_or(0);

    emit_creds_event(ctx, &new, &old, CredsChangeKind::SetUid, flags as u32)
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

    let new = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(0).unwrap_or(core::ptr::null()) as *const _,
    );
    let old = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(1).unwrap_or(core::ptr::null()) as *const _,
    );
    let flags: c_int = ctx.arg(2).unwrap_or(0);

    emit_creds_event(ctx, &new, &old, CredsChangeKind::SetGid, flags as u32)
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

    let new = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(0).unwrap_or(core::ptr::null()) as *const _,
    );
    let old = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(1).unwrap_or(core::ptr::null()) as *const _,
    );

    emit_creds_event(ctx, &new, &old, CredsChangeKind::Capset, 0)
}
