use super::*;
use crate::maps::FdMap;
use aya_bpf::{
    cty::{c_uint, c_ulong},
    maps::LruHashMap,
    programs::ProbeContext,
};

#[kprobe(name = "fd.entry.__fdget")]
pub fn entry_fd_get(ctx: ProbeContext) -> u32 {
    match unsafe { try_entry_fd_get(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
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
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            //let b = s.name().as_bytes().iter().copied();

            log_err!(&ctx, s);
            /*{
                ::aya_log_ebpf::macro_support::check_impl_default(s.name());
                if let Some(buf_ptr) = unsafe { ::aya_log_ebpf::AYA_LOG_BUF.get_ptr_mut(0) } {
                    let buf = unsafe { &mut *buf_ptr };
                    if let Ok(header_len) = ::aya_log_ebpf::write_record_header(
                        &mut buf.buf,
                        "module::path",
                        ::aya_log_ebpf::macro_support::Level::Error,
                        "module::path",
                        "",
                        0 as u32,
                        2usize,
                    ) {
                        let record_len = header_len;
                        if let Ok(record_len) = {
                            Ok::<_, ()>(record_len)
                                .and_then(|record_len| {
                                    if record_len >= buf.buf.len() {
                                        return Err(());
                                    }
                                    aya_log_ebpf::WriteToBuf::write(
                                        { ::aya_log_ebpf::macro_support::DisplayHint::Default },
                                        &mut buf.buf[record_len..],
                                    )
                                    .map(|len| record_len + len)
                                })
                                .and_then(|record_len| {
                                    if record_len >= buf.buf.len() {
                                        return Err(());
                                    }
                                    aya_log_ebpf::WriteToBuf::write(
                                        { s.name().as_bytes() },
                                        &mut buf.buf[record_len..],
                                    )
                                    .map(|len| record_len + len)
                                })
                        } {
                            unsafe {
                                ::aya_log_ebpf::AYA_LOGS.output((&ctx), &buf.buf[..record_len], 0)
                            }
                        }
                    }
                }
            };*/
            error::BPF_PROG_FAILURE
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
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
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
