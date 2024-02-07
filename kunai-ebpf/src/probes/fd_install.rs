use super::*;
use aya_bpf::{
    cty::{c_uint, c_ulong},
    maps::LruHashMap,
    programs::ProbeContext,
};
use kunai_common::maps::FdMap;

#[kprobe(name = "fd.entry.__fdget")]
pub fn entry_fd_get(ctx: ProbeContext) -> u32 {
    match unsafe { try_entry_fd_get(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[map]
static mut FD_GET_ARGS: LruHashMap<u64, c_uint> = LruHashMap::with_max_entries(1024, 0);

unsafe fn try_entry_fd_get(ctx: &ProbeContext) -> ProbeResult<()> {
    let fd: c_uint = ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?;
    FD_GET_ARGS
        .insert(&bpf_task_tracking_id(), &fd, 0)
        .map_err(|_| MapError::InsertFailure)?;
    Ok(())
}

#[kretprobe(name = "fd.exit.__fdget")]
pub fn exit_fd_get(ctx: ProbeContext) -> u32 {
    match unsafe { try_exit_fd_get(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_exit_fd_get(ctx: &ProbeContext) -> ProbeResult<()> {
    // ok_or patterns trips up the verifier
    let fd = *FD_GET_ARGS
        .get(&bpf_task_tracking_id())
        .ok_or(MapError::GetFailure)?;

    let v: c_ulong = ctx.ret().unwrap_or_default();
    let file = co_re::file::from_ptr((v & !3) as *const _);

    let mut fds = FdMap::attach();
    fds.insert(fd as i64, &file)?;

    Ok(())
}

#[kprobe(name = "fd.fd_install")]
pub fn fd_install(ctx: ProbeContext) -> u32 {
    match unsafe { try_track_fd(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

/*
fd_install is used by the kernel to set fd into task_struct fd_array.
We use it to track fds used by tasks as it has been observed that
accessing fd_array from task_struct in BPF is not reliable -> in some
cases the file pointer is null while it should not.
 */
unsafe fn try_track_fd(ctx: &ProbeContext) -> ProbeResult<()> {
    alloc::init()?;

    let fd: i64 = ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?;
    let file = co_re::file::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);

    let mut fds = FdMap::attach();
    fds.insert(fd, &file)?;

    Ok(())
}
