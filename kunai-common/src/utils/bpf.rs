use aya_ebpf::helpers::{self, bpf_get_current_pid_tgid, bpf_probe_read};
use aya_ebpf::{programs::FExitContext, EbpfContext};

#[inline(always)]
pub fn bpf_task_tracking_id() -> u64 {
    bpf_get_current_pid_tgid()
}

#[repr(C)]
pub enum Error {
    NotSupported,
}

#[inline(always)]
// this function is available since some minor commit of 5.15 kernel so for kernels
// between 5.5 (since when fexit is possible) and that 5.15 kernel version, it is not
// possible to use this function. Use bpf_get_fexit_rc instead.
pub fn bpf_get_func_ret<C: EbpfContext>(ctx: &C) -> Result<u64, Error> {
    let mut rc = 0u64;
    if unsafe { helpers::bpf_get_func_ret(ctx.as_ptr(), core::ptr::addr_of_mut!(rc)) } == 0 {
        return Ok(rc);
    }
    Err(Error::NotSupported)
}

#[inline(always)]
// function replicating the behaviour of bpf_get_func_ret (inlined by the verifier)
// for tracing programs ctx is [num args][CTX][arg1][arg2][retval]
pub unsafe fn bpf_get_fexit_rc(ctx: &FExitContext) -> Result<u64, ()> {
    let pctx = ctx.as_ptr();
    // we get num_args
    if let Ok(v) = bpf_probe_read(pctx.wrapping_sub(8) as *const u64) {
        // we multiply num_args by 8 (pointer size)
        let v = (v << 3) as u8;
        // we get the value at retval index, which is return code
        if let Ok(rc) = bpf_probe_read(pctx.wrapping_add(v as usize) as *const u64) {
            return Ok(rc);
        }
    }
    Err(())
}
