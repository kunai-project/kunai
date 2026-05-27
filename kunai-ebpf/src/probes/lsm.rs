use core::ffi::c_void;

use aya_ebpf::{
    cty::c_int,
    maps::LruHashMap,
    programs::{LsmContext, ProbeContext},
    EbpfContext,
};

use kunai_common::bpf_events::{CredSnapshot, CredsChangeKind, CredsEvent, CredsTamperedEvent};

use super::*;

#[map]
pub(crate) static mut TASK_CREDS: LruHashMap<u128, u32> =
    LruHashMap::with_max_entries(10240, 0);

#[inline(always)]
pub(crate) unsafe fn check_creds_tampering<C: EbpfContext>(ctx: &C) -> Result<(), ProbeError> {
    if_disabled_return!(Type::CredsTampered, ());

    let task = co_re::task_struct::current();
    
    let task_uuid = task.uuid();

    let cred = match task.cred() {
        Some(c) => c,
        None => return Ok(()),
    };

    let actual_uid = cred.uid();

    match TASK_CREDS.get(&task_uuid) {
        None => {
            // First time we see this task — set baseline, no alert.
            let _ = TASK_CREDS.insert(&task_uuid, &actual_uid, 0);
        }
        Some(&expected_uid) => {
            if expected_uid != actual_uid {
                alloc::init()?;
                let event = alloc::alloc_zero::<CredsTamperedEvent>()?;
                event.init_from_current_task(Type::CredsTampered)?;
                event.data.expected_uid = expected_uid;
                event.data.actual_uid = actual_uid;
                pipe_event(ctx, event);
                // Update baseline so we don't flood with repeated alerts.
                let _ = TASK_CREDS.insert(&task_uuid, &actual_uid, 0);
            }
        }
    }

    Ok(())
}

enum LsmStatus {
    Continue(i32),
    Block,
}

impl From<LsmStatus> for i32 {
    #[inline(always)]
    fn from(value: LsmStatus) -> Self {
        match value {
            LsmStatus::Block => -1,
            LsmStatus::Continue(ret) => ret,
        }
    }
}

#[lsm(hook = "task_kill")]
pub fn lsm_task_kill(ctx: LsmContext) -> i32 {
    match unsafe { try_lsm_security_task_kill(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
unsafe fn try_lsm_security_task_kill(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let target = co_re::task_struct::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    let sig: c_int = ctx.arg(2);
    // previous hook return code
    let ret: c_int = ctx.arg(4);

    // signal can be 0 but no signal is actually sent to the target
    // it is used only to check if the task can be killed
    if sig == 0 {
        return Ok(LsmStatus::Continue(ret));
    }

    let target_tgid = core_read_kernel!(target, tgid)?;

    // if the target is not kunai we let it go
    if target_tgid as u32 != get_cfg!()?.loader.tgid {
        return Ok(LsmStatus::Continue(ret));
    }

    // we block any attempt to send a signal to kunai
    Ok(LsmStatus::Block)
}

#[lsm(hook = "ptrace_access_check")]
pub fn lsm_ptrace_access_check(ctx: LsmContext) -> i32 {
    match unsafe { try_ptrace_access_check(&ctx) } {
        Ok(s) => s.into(),
        Err(s) => {
            error!(&ctx, s);
            // we don't block on error to prevent DOS
            0
        }
    }
}

#[inline(always)]
unsafe fn try_ptrace_access_check(ctx: &LsmContext) -> Result<LsmStatus, ProbeError> {
    let target = co_re::task_struct::from_ptr(ctx.arg::<*const c_void>(0) as *const _);
    // previous hook return code
    let ret: c_int = ctx.arg(2);

    let target_tgid = core_read_kernel!(target, tgid)?;

    // if the target is not kunai we let it go
    if target_tgid as u32 != get_cfg!()?.loader.tgid {
        return Ok(LsmStatus::Continue(ret));
    }

    // we block any attempt to ptrace kunai
    Ok(LsmStatus::Block)
}

#[inline(always)]
unsafe fn update_creds_map(new: &co_re::cred) {
    if new.is_null() {
        return;
    }
    let task = co_re::task_struct::current();
    let task_uuid = task.uuid();
    let new_uid = new.uid();
    let _ = TASK_CREDS.insert(&task_uuid, &new_uid, 0);
}

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

/// kprobe: security_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
/// Fires on setuid/setresuid/setreuid/setfsuid family syscalls.
/// Equivalent coverage to the LSM task_fix_setuid hook; compatible from kernel 5.4.
///
/// match-proto:v5.4:security/security.c:int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
/// match-proto:latest:security/security.c:int security_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
#[kprobe(function = "security_task_fix_setuid")]
pub fn lsm_security_task_fix_setuid(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_lsm_security_task_fix_setuid(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_lsm_security_task_fix_setuid(ctx: &ProbeContext) -> Result<(), ProbeError> {
    let new = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(0).unwrap_or(core::ptr::null()) as *const _,
    );
    let old = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(1).unwrap_or(core::ptr::null()) as *const _,
    );
    let flags: c_int = ctx.arg(2).unwrap_or(0);

    update_creds_map(&new);

    if_disabled_return!(Type::SetCreds, ());

    emit_creds_event(ctx, &new, &old, CredsChangeKind::SetUid, flags as u32)
}

#[kprobe(function = "security_task_fix_setgid")]
pub fn lsm_security_task_fix_setgid(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_lsm_security_task_fix_setgid(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_lsm_security_task_fix_setgid(ctx: &ProbeContext) -> Result<(), ProbeError> {
    let new = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(0).unwrap_or(core::ptr::null()) as *const _,
    );
    let old = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(1).unwrap_or(core::ptr::null()) as *const _,
    );
    let flags: c_int = ctx.arg(2).unwrap_or(0);

    update_creds_map(&new);

    if_disabled_return!(Type::SetCreds, ());

    emit_creds_event(ctx, &new, &old, CredsChangeKind::SetGid, flags as u32)
}


#[kprobe(function = "security_capset")]
pub fn lsm_security_capset(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_lsm_security_capset(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_lsm_security_capset(ctx: &ProbeContext) -> Result<(), ProbeError> {
    let new = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(0).unwrap_or(core::ptr::null()) as *const _,
    );
    let old = co_re::cred::from_ptr(
        ctx.arg::<*const c_void>(1).unwrap_or(core::ptr::null()) as *const _,
    );

    update_creds_map(&new);

    if_disabled_return!(Type::SetCreds, ());

    emit_creds_event(ctx, &new, &old, CredsChangeKind::Capset, 0)
}
