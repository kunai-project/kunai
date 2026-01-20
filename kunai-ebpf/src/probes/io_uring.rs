use super::*;
use aya_ebpf::programs::ProbeContext;
use kunai_common::co_re::{io_kiocb, sqe_submit};
/// In order to find the appropriate attach point for this
/// probe search for the call to `audit_uring_entry` in kernel
/// souce code and attach to the caller.
///
/// For kernels in >= 5.5
/// match-proto:v5.5:fs/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe, struct io_kiocb **nxt, bool force_nonblock)
/// match-proto:v5.7:fs/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe, bool force_nonblock)
/// match-proto:v5.9:fs/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, const struct io_uring_sqe *sqe, bool force_nonblock, struct io_comp_state *cs)
/// match-proto:v5.10:fs/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, bool force_nonblock, struct io_comp_state *cs)
/// match-proto:v5.12:fs/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
/// match-proto:v6.0:io_uring/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
/// match-proto:latest:io_uring/io_uring.c:static int io_issue_sqe(struct io_kiocb *req, unsigned int issue_flags)
/// match-proto:v6.19:UNTESTED
#[kprobe(function = "io_issue_sqe")]
pub fn io_uring_enter_io_issue_sqe(ctx: ProbeContext) -> u32 {
    handle_issue_sqe(ctx)
}

/// Since v6.15 io_uring audit is done in an inline function __io_issue_sqe.
/// This function is used in two places io_issue_sqe and io_poll_issue.
/// io_poll_issue probe must be disabled prior to v6.15.
///
/// match-proto:v6.15:io_uring/io_uring.c:int io_poll_issue(struct io_kiocb *req, io_tw_token_t tw)
/// match-proto:latest:io_uring/io_uring.c:int io_poll_issue(struct io_kiocb *req, io_tw_token_t tw)
/// match-proto:v6.19:UNTESTED
#[kprobe(function = "io_poll_issue")]
pub fn io_uring_enter_io_poll_issue(ctx: ProbeContext) -> u32 {
    handle_issue_sqe(ctx)
}

#[inline(always)]
fn handle_issue_sqe(ctx: ProbeContext) -> u32 {
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

    alloc::init()?;

    let event = alloc::alloc_zero::<IoUringSqeEvent>()?;

    event.init_from_current_task(Type::IoUringSqe)?;

    // set event data
    event.data.opcode = core_read_kernel!(req, opcode)?;

    pipe_event(ctx, event);
    Ok(())
}

/// For kernels in [5.1; 5.4]
///
/// match-proto:v5.1:fs/io_uring.c:static int __io_submit_sqe(struct io_ring_ctx *ctx, struct io_kiocb *req, const struct sqe_submit *s, bool force_nonblock)
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

    alloc::init()?;

    let event = alloc::alloc_zero::<IoUringSqeEvent>()?;

    event.init_from_current_task(Type::IoUringSqe)?;

    // Set event data
    event.data.opcode = core_read_kernel!(s, sqe, opcode)?;

    pipe_event(ctx, event);
    Ok(())
}
