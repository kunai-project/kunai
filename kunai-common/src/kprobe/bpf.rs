use aya_ebpf::{bindings::pt_regs, macros::*, maps::LruHashMap, programs::ProbeContext};

use crate::utils::bpf_task_tracking_id;

use crate::kprobe::Error;
use kunai_macros::StrEnum;

#[map]
static mut SAVED_CTX: LruHashMap<CtxKey, KProbeEntryContext> =
    LruHashMap::with_max_entries(4096, 0);

#[map]
// u8 limits the maximum depth, we decide to support (here 255) after that we will reuse old entries
// it should not be a big deal as anyway old saved ctx will be reused because SAVED_CTX is a LruHashMap
static mut FN_DEPTH: LruHashMap<u128, u8> = LruHashMap::with_max_entries(0x1ffff, 0);

// in order to save ctx in the same map for several kinds of probes
// we need to have a fix id between kprobe and kretprobes. The
// only way (I found) to do that is to set an enum that must be used
// in the two kinds of probes
#[repr(u32)]
#[derive(Clone, Copy, StrEnum)]
#[allow(non_camel_case_types)]
pub enum ProbeFn {
    dns_vfs_read,
    dns_sys_recv_from,
    net_dns_sys_recvmsg,
    net_sys_connect,
    fs_security_sb_mount,
    sk_sk_attach_prog,
    sk_reuseport_attach_prog,
    security_path_unlink,
}

#[repr(C)]
struct CtxKey {
    func: ProbeFn,
    depth: u32,
    task_tracking_id: u64,
}

impl ProbeFn {
    #[inline(always)]
    unsafe fn ctx_key(&self, depth: u8) -> CtxKey {
        CtxKey {
            func: *self,
            task_tracking_id: bpf_task_tracking_id(),
            depth: depth as u32,
        }
    }

    #[inline(always)]
    unsafe fn get_depth(&self) -> Option<u8> {
        if let Some(d) = FN_DEPTH.get(&self.depth_key()) {
            return Some(*d);
        }
        None
    }

    #[inline(always)]
    pub unsafe fn save_ctx(&self, ctx: &ProbeContext) -> Result<(), Error> {
        let depth = self.get_depth().unwrap_or(0).wrapping_add(1);

        let k = self.ctx_key(depth);
        SAVED_CTX
            .insert(&k, &KProbeEntryContext::new(*self, ctx.regs), 0)
            .map_err(|_| Error::CtxInsert)?;

        self.update_depth(depth)
    }

    #[inline(always)]
    pub unsafe fn restore_ctx(&self) -> Result<&'static mut KProbeEntryContext, Error> {
        let depth = self.get_depth().ok_or(Error::DepthGet)?;
        let k = self.ctx_key(depth);
        let ctx = SAVED_CTX.get_ptr_mut(&k).ok_or(Error::CtxGet)?;
        Ok(&mut (*ctx))
    }

    #[inline(always)]
    pub unsafe fn clean_ctx(&self) -> Result<(), Error> {
        let depth = self.get_depth().ok_or(Error::DepthGet)?;
        // this is not a big deal if we fail at removing the context
        // as it probably means it's already been replaced by a newer entry
        let _ = SAVED_CTX.remove(&self.ctx_key(depth));
        // we decrement depth and update map
        self.update_depth(depth.wrapping_sub(1))
    }

    #[inline(always)]
    unsafe fn update_depth(&self, depth: u8) -> Result<(), Error> {
        FN_DEPTH
            .insert(&self.depth_key(), &depth, 0)
            .map_err(|_| Error::DepthInsert)
    }

    #[inline(always)]
    pub unsafe fn depth_key(&self) -> u128 {
        core::mem::transmute([bpf_task_tracking_id(), *self as u64])
    }
}

#[repr(C)]
pub struct KProbeEntryContext {
    pub ty: ProbeFn,
    pub regs: pt_regs,
}

impl KProbeEntryContext {
    #[inline(always)]
    pub unsafe fn new(ty: ProbeFn, regs: *mut pt_regs) -> Self {
        Self { ty, regs: *regs }
    }

    #[inline(always)]
    pub unsafe fn uuid(&self) -> u128 {
        self.ty.depth_key()
    }

    #[inline(always)]
    pub unsafe fn probe_context(&mut self) -> ProbeContext {
        ProbeContext::new((&mut self.regs as *mut pt_regs) as *mut _)
    }
}
