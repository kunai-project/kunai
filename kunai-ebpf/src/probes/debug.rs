use core::ptr;

use aya_bpf::cty::c_int;
use aya_bpf::helpers::gen::bpf_probe_read;
use aya_bpf::programs::{FExitContext, ProbeContext};
use aya_bpf::{helpers, BpfContext};
use kunai_common::string::String;

#[allow(unused_imports)]
use super::*;

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

unsafe fn try_debug_schedule(ctx: &ProbeContext) -> ProbeResult<()> {
    let ts = co_re::task_struct::current();

    let pid = core_read_kernel!(ts, pid)?;
    let mnt_ns = core_read_kernel!(ts, nsproxy, mnt_ns, ns, inum)?;

    info!(ctx, "pid={} mnt_namespace={}", pid, mnt_ns);

    Ok(())
}
