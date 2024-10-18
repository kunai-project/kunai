use super::*;

use aya_ebpf::{cty::c_int, programs::ProbeContext};
use co_re::task_struct;
use kunai_common::{
    kprobe::{KProbeEntryContext, ProbeFn},
    net::{SockAddr, SocketInfo},
};

#[kprobe(function = "__sys_connect")]
pub fn net_enter_sys_connect(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    unsafe { ignore_result!(ProbeFn::net_sys_connect.save_ctx(&ctx)) }
    0
}

#[kretprobe(function = "__sys_connect")]
pub fn net_exit_sys_connect(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    let rc = match unsafe {
        ProbeFn::net_sys_connect
            .restore_ctx()
            .map_err(ProbeError::from)
            .and_then(|ent_ctx| try_exit_connect(ent_ctx, &ctx))
    } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    ignore_result!(unsafe { ProbeFn::net_sys_connect.clean_ctx() });
    rc
}

const EINPROGRESS: i32 = 115;

unsafe fn try_exit_connect(
    entry_ctx: &mut KProbeEntryContext,
    exit_ctx: &ProbeContext,
) -> ProbeResult<()> {
    let rc = exit_ctx.ret().unwrap_or(-1);

    let entry_ctx = &entry_ctx.probe_context();
    let fd: c_int = kprobe_arg!(entry_ctx, 0)?;
    let addr = co_re::sockaddr::from_ptr(kprobe_arg!(entry_ctx, 1)?);
    let sa_family = core_read_user!(addr, sa_family)?;

    let current = task_struct::current();

    // get the file corresponding to that fd
    let file = current
        .get_fd(fd as usize)
        .ok_or(ProbeError::FileNotFound)?;

    // we raise an error if file is null
    if file.is_null() {
        return Err(ProbeError::NullPointer);
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ConnectEvent>()?;

    event.init_from_task(Type::Connect, current)?;

    let dst = match sa_family {
        AF_INET => {
            let in_addr: co_re::sockaddr_in = addr.into();
            let ip = core_read_user!(in_addr, s_addr)?.to_be();
            let port = core_read_user!(in_addr, sin_port)?.to_be();

            SockAddr::new_v4_from_be(ip, port)
        }
        AF_INET6 => {
            let in6_addr: co_re::sockaddr_in6 = addr.into();
            let ip = core_read_user!(in6_addr, sin6_addr)?;
            let port = core_read_user!(in6_addr, sin6_port)?.to_be();
            // in theory we don't need to reverse addr for ipv6 as we read
            // data which is already big endian
            SockAddr::new_v6_from_be(core_read_user!(ip, addr32)?, port)
        }
        _ => return Ok(()),
    };

    let socket = co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _);
    let sk = core_read_kernel!(socket, sk)?;
    // retrieve sock_common to grap src information
    let sk_common = core_read_kernel!(sk, sk_common)?;

    event.data.socket = SocketInfo::try_from(sk)?;
    event.data.src = SockAddr::src_from_sock_common(sk_common)?;
    event.data.dst = dst;
    event.data.connected = rc == 0 || rc == -EINPROGRESS;

    pipe_event(exit_ctx, event);

    Ok(())
}
