#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use aya_bpf::programs::ProbeContext;

#[kretprobe(name = "debug.exit.schedule")]
pub fn debug_exit_schedule(ctx: ProbeContext) -> u32 {
    match unsafe { try_debug_schedule(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_debug_schedule(ctx: &ProbeContext) -> ProbeResult<()> {
    let config = get_cfg!()?;

    if config.current_is_loader() {
        let ts = co_re::task_struct::current();
        let comm = core_read_kernel!(ts, comm_str)?;
        let tgid = core_read_kernel!(ts, tgid)?;
        info!(
            ctx,
            "current task is loader: {} (tgid={})",
            comm.as_str(),
            tgid
        );
    }

    Ok(())
}
