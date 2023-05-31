use super::*;
use aya_bpf::{helpers::bpf_ktime_get_ns, programs::ProbeContext};

#[kprobe(name = "kprobe.enter.vfs_read")]
pub fn enter_vfs_read(ctx: ProbeContext) -> u32 {
    unsafe { ignore_result!(save_context(ProbeFn::vfs_read, bpf_ktime_get_ns(), &ctx)) };
    0
}

#[kprobe(name = "kprobe.enter.__sys_recvfrom")]
pub fn enter_recv(ctx: ProbeContext) -> u32 {
    unsafe {
        ignore_result!(save_context(
            ProbeFn::__sys_recvfrom,
            bpf_ktime_get_ns(),
            &ctx
        ))
    }
    0
}

#[kprobe(name = "kprobe.enter.__sys_recvmsg")]
pub fn enter_sys_recvmsg(ctx: ProbeContext) -> u32 {
    unsafe {
        ignore_result!(save_context(
            ProbeFn::__sys_recvmsg,
            bpf_ktime_get_ns(),
            &ctx
        ))
    }
    0
}
