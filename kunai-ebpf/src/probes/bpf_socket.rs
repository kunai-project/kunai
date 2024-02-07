use aya_bpf::programs::ProbeContext;
use kunai_common::{co_re::sock_fprog_kern, kprobe::ProbeFn, net::SocketInfo};

use super::*;

#[kprobe(name = "sk.enter.__sk_attach_prog")]
pub fn enter_sk_attach_prog(ctx: ProbeContext) -> u32 {
    unsafe { ignore_result!(ProbeFn::sk_sk_attach_prog.save_ctx(&ctx)) }
    0
}

#[kretprobe(name = "sk.exit.__sk_attach_prog")]
pub fn exit_sk_attach_prog(exit_ctx: ProbeContext) -> u32 {
    let rc = match unsafe {
        ProbeFn::sk_sk_attach_prog
            .restore_ctx()
            .map_err(ProbeError::from)
            .and_then(|entry_ctx| {
                let entry_ctx = &entry_ctx.probe_context();

                let prog = co_re::bpf_prog::from_ptr(kprobe_arg!(entry_ctx, 0)?);
                let sk = co_re::sock::from_ptr(kprobe_arg!(entry_ctx, 1)?);

                handle_socket_attach_prog(&exit_ctx, prog, sk)
            })
    } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&exit_ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    // we cleanup entry context
    ignore_result!(unsafe { ProbeFn::sk_sk_attach_prog.clean_ctx() });
    rc
}

#[kprobe(name = "sk.enter.reuseport_attach_prog")]
pub fn enter_reuseport_attach_prog(ctx: ProbeContext) -> u32 {
    unsafe { ignore_result!(ProbeFn::sk_reuseport_attach_prog.save_ctx(&ctx)) }
    0
}

#[kretprobe(name = "sk.exit.reuseport_attach_prog")]
pub fn exit_reuseport_attach_prog(exit_ctx: ProbeContext) -> u32 {
    let rc = match unsafe {
        ProbeFn::sk_reuseport_attach_prog
            .restore_ctx()
            .map_err(ProbeError::from)
            .and_then(|entry_ctx| {
                let entry_ctx = &entry_ctx.probe_context();

                let sk = co_re::sock::from_ptr(kprobe_arg!(entry_ctx, 0)?);
                let prog = co_re::bpf_prog::from_ptr(kprobe_arg!(entry_ctx, 1)?);

                handle_socket_attach_prog(&exit_ctx, prog, sk)
            })
    } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&exit_ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    // we cleanup entry context
    ignore_result!(unsafe { ProbeFn::sk_reuseport_attach_prog.clean_ctx() });
    rc
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
    warn_msg!(exit_ctx, "bpf program attached to socket not yet supported");

    Ok(())
}
