use aya_bpf::{
    bindings::pt_regs, helpers::gen::bpf_probe_read_kernel, macros::*, maps::LruHashMap,
    programs::ProbeContext,
};
use core::mem::MaybeUninit;
use kunai_common::bpf_utils::bpf_task_tracking_id;

#[map]
static mut SAVED_CTX: LruHashMap<u128, KProbeEntryContext> = LruHashMap::with_max_entries(4096, 0);

pub unsafe fn save_context(pfn: ProbeFn, ts: u64, ctx: &ProbeContext) -> Result<(), i64> {
    SAVED_CTX.insert(&pfn.uuid(), &KProbeEntryContext::new(pfn, ts, ctx.regs), 0)
}

#[allow(dead_code)]
/// this function can be used to save context when using kprobe to hook into syscalls
pub unsafe fn save_syscall_context(pfn: ProbeFn, ts: u64, ctx: &ProbeContext) -> Result<(), i64> {
    let p_regs: *mut pt_regs = ctx.arg(0).ok_or(-1)?;

    let mut reg: MaybeUninit<pt_regs> = MaybeUninit::uninit();

    let ret = bpf_probe_read_kernel(
        reg.as_mut_ptr() as *mut _,
        core::mem::size_of::<pt_regs>() as u32,
        p_regs as *const _,
    );

    if ret == 0 {
        return SAVED_CTX.insert(
            &pfn.uuid(),
            &KProbeEntryContext::new(pfn, ts, reg.as_mut_ptr()),
            0,
        );
    }

    Err(-1)
}

pub unsafe fn restore_entry_ctx(pfn: ProbeFn) -> Option<&'static mut KProbeEntryContext> {
    let ctx = SAVED_CTX.get_ptr_mut(&pfn.uuid())?;
    Some(&mut (*ctx))
}

// in order to save ctx in the same map for several kinds of probes
// we need to have a fix id between kprobe and kretprobes. The
// only way (I found) to do that is to set a enum that must be used
// in the two kinds of probes
#[repr(u64)]
#[derive(Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum ProbeFn {
    vfs_read,
    __sys_recvfrom,
    __sys_recvmsg,
    __sys_connect,
    security_sb_mount,
    __sk_attach_prog,
    reuseport_attach_prog,
    kernel_clone,
}

impl ProbeFn {
    pub unsafe fn uuid(&self) -> u128 {
        core::mem::transmute([bpf_task_tracking_id(), *self as u64])
    }
}

#[repr(C)]
pub struct KProbeEntryContext {
    pub ty: ProbeFn,
    pub regs: pt_regs,
    pub timestamp: u64,
}

impl KProbeEntryContext {
    #[inline(always)]
    pub unsafe fn new(ty: ProbeFn, timestamp: u64, regs: *mut pt_regs) -> Self {
        Self {
            ty,
            regs: *regs,
            timestamp,
        }
    }

    #[inline(always)]
    pub unsafe fn uuid(&self) -> u128 {
        self.ty.uuid()
    }

    #[inline(always)]
    pub unsafe fn probe_context(&mut self) -> ProbeContext {
        ProbeContext::new((&mut self.regs as *mut pt_regs) as *mut _)
    }
}
