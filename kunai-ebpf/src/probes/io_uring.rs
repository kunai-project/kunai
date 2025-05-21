use super::*;
use aya_ebpf::programs::ProbeContext;
use kunai_common::co_re::{io_kiocb, sqe_submit};

// In order to find the appropriate attach point for this
// probe search for the call to `audit_uring_entry` in kernel
// souce code and attach to the caller.

// For kernels in [ 5.5; 6.14 ]
#[kprobe(function = "io_issue_sqe")]
pub fn enter_io_issue_sqe(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_io_issue_sqe(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_io_issue_sqe(ctx: &ProbeContext) -> ProbeResult<()> {
    let req = io_kiocb::from_ptr(kprobe_arg!(ctx, 0)?);

    let event = alloc::alloc_zero::<IoUringSqeEvent>()?;

    event.init_from_current_task(Type::IoUringSqe)?;

    // set event data
    event.data.opcode = core_read_kernel!(req, opcode)?;

    pipe_event(ctx, event);
    Ok(())
}

// For kernels in [5.1; 5.4]
#[kprobe(function = "__io_submit_sqe")]
pub fn enter_io_submit_sqe(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_io_submit_sqe(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_io_submit_sqe(ctx: &ProbeContext) -> ProbeResult<()> {
    // Assuming the first argument is the io_kiocb pointer, similar to io_issue_sqe
    let s = sqe_submit::from_ptr(kprobe_arg!(ctx, 2)?);

    let event = alloc::alloc_zero::<IoUringSqeEvent>()?;

    event.init_from_current_task(Type::IoUringSqe)?;

    // Set event data
    event.data.opcode = core_read_kernel!(s, sqe, opcode)?;

    pipe_event(ctx, event);
    Ok(())
}
