use crate::maps::FdMap;

use super::*;
use aya_bpf::{
    cty::{c_int, c_void},
    programs::ProbeContext,
};

use kunai_common::net::IpPort;

enum Udata {
    Buf(*const c_void, usize),
}

struct SockHelper {
    socket: co_re::socket,
    udata: Udata,
}

impl SockHelper {
    fn from_ubuf(s: co_re::socket, ubuf: *const c_void, size: usize) -> Self {
        Self {
            socket: s,
            udata: Udata::Buf(ubuf, size),
        }
    }

    #[inline(always)]
    unsafe fn dns_event(
        &self,
        ctx: &ProbeContext,
        opt_server: Option<IpPort>, // optional server IpPort
        tcp_header: bool,           // whether the data contains tcp_header
    ) -> ProbeResult<()> {
        let socket = self.socket;
        let sock = core_read_kernel!(socket, sk)?;
        let sk_common = core_read_kernel!(sock, sk_common)?;
        let sk_type = core_read_kernel!(sock, sk_type)?;

        let sa_family = core_read_kernel!(sk_common, skc_family)?;

        if sa_family != AF_INET as u16 && sa_family != AF_INET6 as u16 {
            return Ok(());
        }

        // in some cases it ip/port info is empty in socket
        // if there is an optional server it takes precedence over addr got from socket
        let ip_port = match opt_server {
            Some(server) => server,
            None => IpPort::from_sock_common_foreign_ip(&sk_common).unwrap_or_default(),
        };

        // we don't take protocol communicating on other ports than dns
        if ip_port.port() != 53 {
            return Ok(());
        }

        alloc::init()?;
        let event = alloc::alloc_zero::<DnsQueryEvent>()?;

        //event.info.timestamp = event_ts;
        event.data.ip_port = ip_port;
        event.data.proto = sk_type;
        event.data.tcp_header = tcp_header;

        match self.udata {
            Udata::Buf(ubuf, size) => {
                if size < 12 {
                    return Ok(());
                }
                event.data.data.read_user_at(ubuf, size as u32)?
            }
        }

        event.init_from_current_task(Type::DnsQuery)?;
        pipe_event(ctx, event);

        Ok(())
    }
}

#[kretprobe(name = "net.dns.exit.vfs_read")]
pub fn exit_vfs_read(ctx: ProbeContext) -> u32 {
    match unsafe { try_exit_vfs_read(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_exit_vfs_read(ctx: &ProbeContext) -> ProbeResult<()> {
    let rc = ctx.ret().unwrap_or(-1);

    let entry_ctx =
        restore_entry_ctx(ProbeFn::vfs_read).ok_or(ProbeError::KProbeCtxRestoreFailure)?;
    let saved_ctx = entry_ctx.probe_context();

    let file = co_re::file::from_ptr(kprobe_arg!(&saved_ctx, 0)?);
    let ubuf: *const u8 = kprobe_arg!(&saved_ctx, 1)?;

    if !file.is_sock().unwrap_or(false) || ubuf.is_null() {
        return Ok(());
    }

    let sh = SockHelper::from_ubuf(
        co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _),
        ubuf as *const _,
        rc as usize,
    );

    sh.dns_event(ctx, None, true)?;

    Ok(())
}

#[kretprobe(name = "net.dns.exit.__sys_recvfrom")]
pub fn exit_recv(ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::__sys_recvfrom)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|ent_ctx| try_exit_recv(ent_ctx, &ctx))
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_exit_recv(
    entry_ctx: &mut KProbeEntryContext,
    exit_ctx: &ProbeContext,
) -> ProbeResult<()> {
    let rc = exit_ctx.ret().unwrap_or(-1);

    if rc < 0 {
        return Ok(());
    }
    let ent_probe_ctx = &entry_ctx.probe_context();
    let mut fd_map = FdMap::attach();

    let fd: c_int = kprobe_arg!(ent_probe_ctx, 0)?;
    let ubuf: *const u8 = kprobe_arg!(ent_probe_ctx, 1)?;

    let file = fd_map.get(fd as i64).ok_or(MapError::GetFailure)?;

    if !file.is_sock().unwrap_or(false) || ubuf.is_null() {
        return Ok(());
    }

    let sh = SockHelper::from_ubuf(
        co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _),
        ubuf as *const _,
        rc as usize,
    );

    sh.dns_event(exit_ctx, None, false)?;

    Ok(())
}

#[kretprobe(name = "net.dns.exit.__sys_recvmsg")]
pub fn exit_sys_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::__sys_recvmsg)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|ent_ctx| try_exit_recvmsg(ent_ctx, &ctx))
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_exit_recvmsg(
    entry_ctx: &mut KProbeEntryContext,
    exit_ctx: &ProbeContext,
) -> ProbeResult<()> {
    let rc = exit_ctx.ret().unwrap_or(-1);

    if rc < 0 {
        return Ok(());
    }

    let saved_ctx = &entry_ctx.probe_context();
    let mut fd_map = FdMap::attach();

    let fd: c_int = kprobe_arg!(saved_ctx, 0)?;
    let file = fd_map.get(fd as i64).ok_or(MapError::GetFailure)?;

    if !file.is_sock().unwrap_or(false) {
        return Ok(());
    }

    let msg = co_re::user_msghdr::from_ptr(kprobe_arg!(saved_ctx, 1)?);

    let ubuf = core_read_user!(msg, msg_iov, iov_base)?;

    let socket = co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _);

    let sh = SockHelper::from_ubuf(socket, ubuf, rc as usize);

    let msg_name = core_read_user!(msg, msg_name)?;

    let mut server = None;

    if !msg_name.is_null() {
        let addr = co_re::sockaddr::from_ptr(msg_name as *const _);
        let sa_family = core_read_user!(addr, sa_family)?;
        if sa_family == AF_INET {
            let in_addr: co_re::sockaddr_in = addr.into();
            let ip = core_read_user!(in_addr, s_addr)?.to_be();
            let port = core_read_user!(in_addr, sin_port)?.to_be();
            server = Some(IpPort::new_v4_from_be(ip, port));
        }
    }

    sh.dns_event(exit_ctx, server, false)?;
    Ok(())
}
