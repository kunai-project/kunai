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

#[kprobe(name = "kprobe.enter.security_sb_mount")]
pub fn enter_path_mount(ctx: ProbeContext) -> u32 {
    unsafe {
        ignore_result!(save_context(
            ProbeFn::security_sb_mount,
            bpf_ktime_get_ns(),
            &ctx
        ));
    }
    0
}

#[kprobe(name = "kprobe.enter.__sk_attach_prog")]
pub fn enter_sk_attach_prog(ctx: ProbeContext) -> u32 {
    unsafe {
        ignore_result!(save_context(
            ProbeFn::__sk_attach_prog,
            bpf_ktime_get_ns(),
            &ctx
        ))
    }
    0
}

#[kprobe(name = "kprobe.enter.reuseport_attach_prog")]
pub fn enter_reuseport_attach_prog(ctx: ProbeContext) -> u32 {
    unsafe {
        ignore_result!(save_context(
            ProbeFn::reuseport_attach_prog,
            bpf_ktime_get_ns(),
            &ctx
        ))
    }
    0
}

#[kprobe(name = "kprobe.enter.kernel_clone")]
pub fn enter_kernel_clone(ctx: ProbeContext) -> u32 {
    unsafe {
        ignore_result!(save_context(
            ProbeFn::kernel_clone,
            bpf_ktime_get_ns(),
            &ctx
        ));
    }
    0
}

// ToDo: move all save probes so that they use this macro
/// def_save_probe helper to create kprobes to save entry context
#[allow(unused_macros)]
macro_rules! def_save_probe {
    ($hook:ident) => {
        paste::item! {
            #[allow(non_snake_case)]
            #[kprobe]
            pub fn [<$hook>](ctx: ProbeContext) -> u32 {
                unsafe {
                    ignore_result!(save_context(
                        ProbeFn::$hook,
                        bpf_ktime_get_ns(),
                        &ctx
                    ));
                }
                0
            }
        }
    };
}
