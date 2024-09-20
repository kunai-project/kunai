use super::*;
use aya_ebpf::{
    cty::{c_int, c_void, size_t},
    programs::ProbeContext,
};

use kunai_common::{
    co_re::task_struct,
    kprobe::ProbeFn,
    net::{IpPort, SaFamily, SocketInfo},
};

const DNS_HEADER_SIZE: usize = 12;

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
            None => IpPort::from_sock_common_foreign_ip(sk_common).unwrap_or_default(),
        };

        // we don't take protocol communicating on other ports than dns
        if ip_port.port() != 53 {
            return Ok(());
        }

        alloc::init()?;
        let event = alloc::alloc_zero::<DnsQueryEvent>()?;

        event.data.ip_port = ip_port;
        event.data.proto = sk_type;
        event.data.tcp_header = tcp_header;

        match self.udata {
            Udata::Buf(ubuf, size) => {
                if size < DNS_HEADER_SIZE {
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

unsafe fn is_dns_sock(sock: &co_re::sock) -> Result<bool, ProbeError> {
    let si = SocketInfo::try_from(*sock)?;

    // return if socket neither is INET nor INET6
    if !si.is_family(SaFamily::AF_INET) && !si.is_family(SaFamily::AF_INET6) {
        return Ok(false);
    }

    let sock_common = core_read_kernel!(sock, sk_common)?;
    let ip_port = IpPort::from_sock_common_foreign_ip(sock_common)?;

    // filter on dst port
    Ok(ip_port.port() == 53)
}

#[kprobe(function = "vfs_read")]
pub fn net_dns_enter_vfs_read(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_vfs_read(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

// many vfs_read ar happening (not only on sockets) so this function
// aims at filtering as much as we can to save only interesting contexts
unsafe fn try_enter_vfs_read(ctx: &ProbeContext) -> ProbeResult<()> {
    let file = co_re::file::from_ptr(kprobe_arg!(ctx, 0)?);
    let ubuf: *const u8 = kprobe_arg!(ctx, 1)?;
    let count: size_t = kprobe_arg!(ctx, 2)?;

    if !file.is_sock().unwrap_or(false) || ubuf.is_null() || count == 0 {
        return Ok(());
    }

    let socket = co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _);
    let sock = core_read_kernel!(socket, sk)?;

    // check if it looks like a connection to a DNS server
    if !is_dns_sock(&sock)? {
        return Ok(());
    }

    // we report saving error as we are going to
    // miss entries later if that is the case
    ProbeFn::dns_vfs_read.save_ctx(ctx)?;

    Ok(())
}

#[kretprobe(function = "vfs_read")]
pub fn net_dns_exit_vfs_read(ctx: ProbeContext) -> u32 {
    let rc = match unsafe { try_exit_vfs_read(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    // we cleanup saved entry context
    ignore_result!(unsafe { ProbeFn::dns_vfs_read.clean_ctx() });
    rc
}

unsafe fn try_exit_vfs_read(ctx: &ProbeContext) -> ProbeResult<()> {
    // we restore entry context
    let saved_ctx = match ProbeFn::dns_vfs_read.restore_ctx() {
        Ok(ctx) => ctx.probe_context(),
        _ => return Ok(()),
    };

    let rc = ctx.ret().unwrap_or(-1);

    // rc is also the size of the data read so we don't irrelevant cases
    if rc < DNS_HEADER_SIZE as i32 {
        return Ok(());
    }

    let file = co_re::file::from_ptr(kprobe_arg!(&saved_ctx, 0)?);
    let ubuf: *const u8 = kprobe_arg!(&saved_ctx, 1)?;

    if file.is_null() {
        return Err(ProbeError::NullPointer);
    }

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

#[kprobe(function = "__sys_recvfrom")]
pub fn net_dns_enter_sys_recvfrom(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_sys_recvfrom(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_enter_sys_recvfrom(ctx: &ProbeContext) -> ProbeResult<()> {
    let fd: c_int = kprobe_arg!(ctx, 0)?;
    let ubuf: *const u8 = kprobe_arg!(ctx, 1)?;

    let current = task_struct::current();
    let file = current
        .get_fd(fd as usize)
        .ok_or(ProbeError::FileNotFound)?;

    if file.is_null() {
        return Err(ProbeError::NullPointer);
    }

    if !file.is_sock().unwrap_or(false) || ubuf.is_null() {
        return Ok(());
    }

    let socket = co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _);
    let sock = core_read_kernel!(socket, sk)?;

    if !is_dns_sock(&sock)? {
        return Ok(());
    }

    ProbeFn::dns_sys_recv_from.save_ctx(ctx)?;

    Ok(())
}

#[kretprobe(function = "__sys_recvfrom")]
pub fn net_dns_exit_sys_recvfrom(ctx: ProbeContext) -> u32 {
    let rc = match unsafe { try_exit_sys_recvfrom(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    ignore_result!(unsafe { ProbeFn::dns_sys_recv_from.clean_ctx() });
    rc
}

#[inline(always)]
unsafe fn try_exit_sys_recvfrom(exit_ctx: &ProbeContext) -> ProbeResult<()> {
    // we restore entry context
    let ent_probe_ctx = match ProbeFn::dns_sys_recv_from.restore_ctx() {
        Ok(ctx) => ctx.probe_context(),
        _ => return Ok(()),
    };

    let rc = exit_ctx.ret().unwrap_or(-1);

    // rc is also the size of the data read so we don't irrelevant cases
    if rc < DNS_HEADER_SIZE as i32 {
        return Ok(());
    }

    let fd: c_int = kprobe_arg!(ent_probe_ctx, 0)?;
    let ubuf: *const u8 = kprobe_arg!(ent_probe_ctx, 1)?;

    let file = task_struct::current()
        .get_fd(fd as usize)
        .ok_or(ProbeError::FileNotFound)?;

    if file.is_null() {
        return Err(ProbeError::NullPointer);
    }

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

#[kprobe(function = "__sys_recvmsg")]
pub fn net_dns_enter_sys_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_enter_sys_recvmsg(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_enter_sys_recvmsg(ctx: &ProbeContext) -> ProbeResult<()> {
    let fd: c_int = kprobe_arg!(ctx, 0)?;
    let current = task_struct::current();

    // here getting file from FdMap always fails
    // so we need to lookup task_struct's files->fd_array
    let file = current
        .get_fd(fd as usize)
        .ok_or(ProbeError::FileNotFound)?;

    // file should not be null
    if file.is_null() {
        return Err(ProbeError::NullPointer);
    }

    if !file.is_sock().unwrap_or(false) {
        return Ok(());
    }

    let socket = co_re::socket::from_ptr(core_read_kernel!(file, private_data)? as *const _);
    let sock = core_read_kernel!(socket, sk)?;

    if !is_dns_sock(&sock)? {
        return Ok(());
    }

    // we save context
    ProbeFn::net_dns_sys_recvmsg.save_ctx(ctx)?;

    Ok(())
}

#[kretprobe(function = "__sys_recvmsg")]
pub fn net_dns_exit_sys_recvmsg(ctx: ProbeContext) -> u32 {
    let rc = match unsafe { try_exit_recvmsg(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    };
    // we cleanup saved entry context
    ignore_result!(unsafe { ProbeFn::net_dns_sys_recvmsg.clean_ctx() });
    rc
}

#[inline(always)]
unsafe fn try_exit_recvmsg(exit_ctx: &ProbeContext) -> ProbeResult<()> {
    // we restore saved context
    let saved_ctx = match ProbeFn::net_dns_sys_recvmsg.restore_ctx() {
        Ok(ctx) => ctx.probe_context(),
        _ => return Ok(()),
    };

    let rc = exit_ctx.ret().unwrap_or(-1);

    // rc is also the size of the data read so we don't irrelevant cases
    if rc < DNS_HEADER_SIZE as i32 {
        return Ok(());
    }

    let fd: c_int = kprobe_arg!(saved_ctx, 0)?;

    let file = task_struct::current()
        .get_fd(fd as usize)
        .ok_or(ProbeError::FileNotFound)?;

    if file.is_null() {
        return Err(ProbeError::NullPointer);
    }

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
