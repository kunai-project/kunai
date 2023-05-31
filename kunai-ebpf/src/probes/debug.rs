use aya_bpf::{programs::ProbeContext};

#[allow(unused_imports)]
use super::*;

// place where to put test probes

#[kprobe(name = "debug.schedule")]
pub fn debug_schedule(ctx: ProbeContext) -> u32 {
    match unsafe { try_debug_schedule(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_debug_schedule(ctx: &ProbeContext) -> ProbeResult<()> {
    let ts = co_re::task_struct::current();
    let root = core_read_kernel!(ts, nsproxy, mnt_ns, root)?;

    info!(ctx, "root={}", root.as_ptr() as usize);
    Ok(())
}
