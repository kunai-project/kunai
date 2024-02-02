use super::*;

use aya_bpf::programs::ProbeContext;
use kunai_common::net::IpPort;

#[kprobe(name = "net.enter.__sys_connect")]
pub fn enter_sys_connect(ctx: ProbeContext) -> u32 {
    unsafe { ignore_result!(ProbeFn::net_sys_connect.save_ctx(&ctx)) }
    0
}

#[kretprobe(name = "net.exit.__sys_connect")]
pub fn exit_sys_connect(ctx: ProbeContext) -> u32 {
    let rc = match unsafe {
        ProbeFn::net_sys_connect
            .restore_ctx()
            .map_err(ProbeError::from)
            .and_then(|ent_ctx| try_exit_connect(ent_ctx, &ctx))
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
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
    let addr = co_re::sockaddr::from_ptr(kprobe_arg!(entry_ctx, 1)?);
    let sa_family = core_read_user!(addr, sa_family)?;

    alloc::init()?;
    let event = alloc::alloc_zero::<ConnectEvent>()?;

    event.init_from_current_task(Type::Connect)?;

    let ip_port = match sa_family {
        AF_INET => {
            let in_addr: co_re::sockaddr_in = addr.into();
            let ip = core_read_user!(in_addr, s_addr)?.to_be();
            let port = core_read_user!(in_addr, sin_port)?.to_be();

            IpPort::new_v4_from_be(ip, port)
        }
        AF_INET6 => {
            let in6_addr: co_re::sockaddr_in6 = addr.into();
            let ip = core_read_user!(in6_addr, sin6_addr)?;
            let port = core_read_user!(in6_addr, sin6_port)?.to_be();
            // in theory we don't need to reverse addr for ipv6 as we read
            // data which is already big endian
            IpPort::new_v6_from_be(core_read_user!(ip, addr32)?, port)
        }
        _ => return Ok(()),
    };

    event.data.family = sa_family;
    event.data.ip_port = ip_port;
    event.data.connected = rc == 0 || rc == -EINPROGRESS;

    pipe_event(exit_ctx, event);

    Ok(())
}
