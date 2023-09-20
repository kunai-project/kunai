use aya_bpf::programs::ProbeContext;
use kunai_common::{co_re::sock_fprog_kern, net::SocketInfo};

use super::*;

#[kretprobe(name = "sk.exit.__sk_attach_prog")]
pub fn exit_sk_attach_prog(exit_ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::__sk_attach_prog)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|entry_ctx| {
                let entry_ctx = &entry_ctx.restore();

                let prog = co_re::bpf_prog::from_ptr(kprobe_arg!(entry_ctx, 0)?);
                let sk = co_re::sock::from_ptr(kprobe_arg!(entry_ctx, 1)?);

                handle_socket_attach_prog(&exit_ctx, prog, sk)
            })
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&exit_ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[kretprobe(name = "sk.exit.reuseport_attach_prog")]
pub fn exit_reuseport_attach_prog(exit_ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::reuseport_attach_prog)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|entry_ctx| {
                let entry_ctx = &entry_ctx.restore();

                let sk = co_re::sock::from_ptr(kprobe_arg!(entry_ctx, 0)?);
                let prog = co_re::bpf_prog::from_ptr(kprobe_arg!(entry_ctx, 1)?);

                handle_socket_attach_prog(&exit_ctx, prog, sk)
            })
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&exit_ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn handle_socket_attach_prog(
    exit_ctx: &ProbeContext,
    prog: co_re::bpf_prog,
    sk: co_re::sock,
) -> ProbeResult<()> {
    let rc = exit_ctx.ret().unwrap_or(-1);

    let orig = core_read_kernel!(prog, orig_prog)?;
    let filter = core_read_kernel!(orig, filter)?;
    let len = core_read_kernel!(orig, len)?;
    let byte_size = sock_fprog_kern::byte_size_from_len(len);

    // init allocator
    alloc::init()?;

    // specific code to handle attached filter
    if !orig.is_null() {
        let event = alloc::alloc_zero::<BpfSocketFilterEvent>()?;

        // event initialization
        event.init_from_current_task(Type::BpfSocketFilter)?;

        // setting up socket info
        event.data.socket_info = SocketInfo::try_from(sk).unwrap_or_default();
        // reading filter from kernel
        event
            .data
            .filter
            .read_kernel_at(filter.as_ptr(), byte_size as u32)?;
        event.data.filter_len = len;
        // attached if rc == 0
        event.data.attached = rc == 0;

        pipe_event(exit_ctx, event);
        return Ok(());
    }

    //handle loading of regular bpf program
    warn!(exit_ctx, "bpf program attached to socket not yet supported");

    Ok(())
}
