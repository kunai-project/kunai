use super::*;

use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{ProbeContext, TracePointContext};
use aya_ebpf::EbpfContext;
use co_re::task_struct;
use kunai_common::syscalls::SysExitArgs;

#[map]
static mut EXECVE_TRACKING: LruHashMap<u128, ExecveEvent> = LruHashMap::with_max_entries(4096, 0);

// this guy gives us the real executable path (i.e. a script for instance)
// we need to hook at another point in order to get the interpreter. For
// instance at exit of bprm_execve.

#[kprobe(function = "security_bprm_check")]
pub fn execve_security_bprm_check(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_bprm_check(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_bprm_check(ctx: &ProbeContext) -> ProbeResult<()> {
    let linux_binprm = co_re::linux_binprm::from_ptr(ctx.arg(0).unwrap_or(core::ptr::null()));
    let ts = co_re::task_struct::current();
    let task_uuid = ts.uuid();

    if EXECVE_TRACKING.get_ptr_mut(&task_uuid).is_some() {
        // security_bprm_check is running in a loop
        // we aleady processed the higher call giving executable
        return Ok(());
    }

    // we keep track of linux_binprm
    if !linux_binprm.is_null() {
        ignore_result!(BPRM_EXECVE_ARGS.insert(&bpf_task_tracking_id(), &linux_binprm, 0))
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ExecveEvent>()?;

    if let Some(file) = linux_binprm.file() {
        event
            .data
            .executable
            .core_resolve_file(&file, MAX_PATH_DEPTH)?;
    }

    EXECVE_TRACKING
        .insert(&task_uuid, event, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

#[map]
static mut BPRM_EXECVE_ARGS: LruHashMap<u64, co_re::linux_binprm> =
    LruHashMap::with_max_entries(1024, 0);

// for kernel < 5.9 bprm_execve does not exists, we must replace the hook
// by __do_execve_file (done in program loader)

#[kretprobe(function = "bprm_execve")]
pub fn execve_exit_bprm_execve(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_bprm_execve(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn execve_event<C: EbpfContext>(ctx: &C, rc: i32) -> ProbeResult<()> {
    let linux_binprm = BPRM_EXECVE_ARGS
        .get(&bpf_task_tracking_id())
        .ok_or(MapError::GetFailure)?;

    let ts = task_struct::current();

    let task_uuid = ts.uuid();

    let event = EXECVE_TRACKING
        .get_ptr_mut(&task_uuid)
        .ok_or(MapError::GetFailure)?;

    let event = &mut (*event);

    let current = task_struct::current();

    // getting nodename first as we need the current task struct
    event.data.nodename.read_kernel_at(
        core_read_kernel!(current, nsproxy, uts_ns, name, nodename)?,
        event.data.nodename.cap() as u32,
    )?;

    // initializing event
    event.init_from_task(Type::Execve, current)?;

    // file should not be null here
    // we are getting interpreter which is set to the file attribute by exec_binprm kernel function
    if let Some(file) = linux_binprm.file() {
        event
            .data
            .interpreter
            .core_resolve_file(&file, MAX_PATH_DEPTH)?;
    }

    event.data.rc = rc;

    let arg_start = core_read_kernel!(ts, mm, arg_start)?;
    let arg_len = core_read_kernel!(ts, mm, arg_len)?;

    // parsing argv
    if event
        .data
        .argv
        .read_user_at(arg_start as *const u8, arg_len as u32)
        .is_err()
    {
        warn_msg!(ctx, "failed to read argv")
    }

    // cgroup parsing
    let cgroup = core_read_kernel!(ts, sched_task_group, css, cgroup)?;
    // we do not raise any error on cgroup parsing, we let a chance to userland to solve it
    ignore_result!(event.data.cgroup.resolve(cgroup));

    pipe_event(ctx, event);

    // we use a LruHashMap so we can safely ignore result
    ignore_result!(EXECVE_TRACKING.remove(&task_uuid));

    Ok(())
}

unsafe fn try_bprm_execve(ctx: &ProbeContext) -> ProbeResult<()> {
    let rc = ctx.ret().unwrap_or(-1);

    // execve failed
    if rc < 0 {
        return Ok(());
    }

    execve_event(ctx, rc)
}

#[tracepoint(name = "sys_exit_execve", category = "syscalls")]
pub fn syscalls_sys_exit_execve(ctx: TracePointContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_sys_exit_execve(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[tracepoint(name = "sys_exit_execveat", category = "syscalls")]
pub fn syscalls_sys_exit_execveat(ctx: TracePointContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_sys_exit_execve(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
pub unsafe fn try_sys_exit_execve(ctx: &TracePointContext) -> Result<(), ProbeError> {
    let args = SysExitArgs::from_context(ctx)?;
    let rc = args.ret as i32;

    if rc < 0 {
        return Ok(());
    }

    execve_event(ctx, rc)
}
