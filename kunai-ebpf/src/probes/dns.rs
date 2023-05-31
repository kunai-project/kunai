use crate::maps::FdMap;

use super::*;
use aya_bpf::{
    cty::{c_int, c_void},
    programs::ProbeContext,
};

use kunai_common::net::IpPort;

/*const QUERY: u16 = 0b1000_0000_0000_0000;
#[allow(dead_code)]
const OPCODE: u16 = 0b0111_1000_0000_0000;
#[allow(dead_code)]
const TC: u16 = 0b0000_0010_0000_0000;
#[allow(dead_code)]
const ZERO: u16 = 0b0000_0000_0111_0000;
#[allow(dead_code)]
const RCODE: u16 = 0b0000_0000_0000_0000;

#[map]
static mut DNS_EVENTS: LruHashMap<u64, DnsQueryEvent> = LruHashMap::with_max_entries(1024, 0);

#[map]
static mut RECVMSG_ARGS: LruHashMap<u64, RecvmsgArgs> = LruHashMap::with_max_entries(1024, 0);

struct RecvmsgArgs {
    socket: co_re::socket,
    msghdr: co_re::msghdr,
}

#[kprobe(name = "dns.entry.sock_recvmsg")]
pub fn fentry_sock_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_fentry_snoop_dns_data(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            s.log_err(&ctx);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_fentry_snoop_dns_data(ctx: &ProbeContext) -> BpfResult<()> {
    let socket = co_re::socket::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    let msghdr = co_re::msghdr::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);

    // error case will be handled later when trying to retrieve args
    ignore_result!(RECVMSG_ARGS.insert(
        &bpf_task_tracking_id(),
        &RecvmsgArgs { socket, msghdr },
        0,
    ));

    let sock = socket.sk().ok_or(ProbeError::CoReFieldMissing)?;

    let sock_common = socket
        .sk()
        .and_then(|sk| sk.sk_common())
        .ok_or(ProbeError::CoReFieldMissing)?;

    let sa_family = sock_common
        .skc_family()
        .ok_or(ProbeError::CoReFieldMissing)?;

    if sa_family as u32 != AF_INET && sa_family as u32 != AF_INET6 {
        return Ok(());
    }

    let ip_port = IpPort::from_sock_common_foreign_ip(&sock_common)?;

    // we filter only traffic coming from port 53
    //if !ip_port.is_zero() && ip_port.port() == 53 {
    alloc::init()?;
    let event = alloc::alloc_zero::<DnsQueryEvent>()?;
    event.data.ip_port = ip_port;
    // we need protocol info in packet_data call
    event.data.proto = sock.sk_type().ok_or(ProbeError::CoReFieldMissing)?;

    let skb = sock
        .sk_receive_queue()
        .and_then(|l| l.next())
        .ok_or(ProbeError::CoReFieldMissing)?;

    // sk_buff data can be collected only on fentry
    // sk_buff seems to be used by TCP and DNS response
    // has two additional bytes to encode packet size at front
    let skb_len = skb.len().ok_or(ProbeError::CoReFieldMissing)?;
    let pdata = skb.data().ok_or(ProbeError::CoReFieldMissing)?;

    info!(
        ctx,
        "trying to read skb_len={} pdata=0x{:x}", skb_len, pdata as u64
    );
    if skb_len > 14 && pdata as usize != i64::MAX as usize {
        // reading skb_data into data buffer
        inspect_err!(
            event
                .data
                .data
                .read_kernel_at(pdata, skb_len)
                .map_err(|e| e.into()),
            |e: ProbeError| warn!(
                ctx,
                "failed to read sk_buff with data=0x{:x} skb_len={}: {}",
                pdata as usize,
                skb_len,
                e.description()
            )
        );

        // we reset buffer if header is null so that it gives a chance to be handled properly at exit
        if event.data.header_is_null() {
            //event.data.data.reset();
        }
    }

    DNS_EVENTS
        .insert(&bpf_task_tracking_id(), event, 0)
        .map_err(|_| MapError::InsertFailure)?;
    //}

    Ok(())
}

#[kretprobe(name = "dns.exit.sock_recvmsg")]
pub fn fexit_sock_recvmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_fexit_snoop_dns_data(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            s.log_err(&ctx);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_fexit_snoop_dns_data(ctx: &ProbeContext) -> BpfResult<()> {
    let key = bpf_task_tracking_id();

    // return code is valid only on fexit
    //let rc = bpf_get_fexit_rc(ctx).unwrap_or(-1i32 as u64) as i32;
    let rc: c_int = ctx.ret().unwrap_or(-1);

    // we send to userland only if there is no error
    if rc > 12 {
        let args = RECVMSG_ARGS
            .get(&bpf_task_tracking_id())
            .ok_or(ProbeError::KProbeArgFailure)?;

        /* Test */
        let sock_common = args
            .socket
            .sk()
            .and_then(|sk| sk.sk_common())
            .ok_or(ProbeError::CoReFieldMissing)?;

        let sa_family = sock_common
            .skc_family()
            .ok_or(ProbeError::CoReFieldMissing)?;

        if sa_family as u32 != AF_INET && sa_family as u32 != AF_INET6 {
            return Ok(());
        }

        let sk_type = args
            .socket
            .sk()
            .and_then(|sk| sk.sk_type())
            .ok_or(ProbeError::CoReFieldMissing)?;
        let ip_port = IpPort::from_sock_common_foreign_ip(&sock_common)?;
        if ip_port.port() != 53 {
            return Ok(());
        }
        info!(
            ctx,
            "rc={} sa_family={} ip={:ipv4} port={} sk_type={} event_there={}",
            rc,
            sa_family,
            ip_port.ip() as u32,
            ip_port.port(),
            sk_type,
            DNS_EVENTS.get_ptr_mut(&key).is_some() as u8,
        );

        /* end Test */
        if let Some(event) = DNS_EVENTS.get_ptr_mut(&key) {
            let event = &mut (*event);

            // we did not manage to get data from sk_buff so we get it from msghdr
            if event.data.data.is_empty() {
                let iov_iter = args.msghdr.msg_iter().ok_or(ProbeError::CoReFieldMissing)?;

                // we work on another buffer as for an unknown reason the verifier
                // is impossible to satisfy when used directly on event.data.data
                alloc::init()?;
                let packet = alloc::alloc_zero::<Buffer<DNS_MAX_PACKET_SIZE>>()?;

                // rc is the amount of bytes received so we don't need to read more than that
                packet.fill_from_iov_iter::<16>(&iov_iter, Some(rc as usize))?;
                event.data.data.copy(packet);
                let nr_segs = iov_iter.nr_segs().unwrap_or_default();
                let count = iov_iter.count().unwrap_or_default();
                let iov_base = iov_iter
                    .iov()
                    .and_then(|iov| iov.iov_base())
                    .unwrap_or(core::ptr::null_mut());
                let iov_len = iov_iter
                    .iov()
                    .and_then(|iov| iov.iov_len())
                    .unwrap_or_default();
                info!(
                    ctx,
                    "reading msghdr: iov_base=0x{:x} iov_len={} nr_segs={} count={} packet.len={}",
                    iov_base as usize,
                    iov_len,
                    nr_segs,
                    count,
                    packet.len(),
                );
            }

            let header = &event.data.packet_data()[..12];
            let flags = u16::from_be_bytes([header[2], header[3]]);
            let is_dns_query = flags & QUERY == 0;

            // filtering out packet with non compliant DNS headers
            //if !is_dns_query {
            // we initialize from btf task
            event.init_from_btf_task(events::Type::DnsQuery);
            pipe_event(ctx, event);
            //}

            // message showing that we are likely lacking some implementation
            if event.data.data.is_empty() {
                warn!(
                    ctx,
                    "a case seems unhandled server_ip={:ipv4}:53",
                    event.data.ip_port.ip() as u32
                );
            }
        }
    }

    // we don't need to handle error here as we use a LruHashMap
    ignore_result!(DNS_EVENTS.remove(&key));

    Ok(())
}*/
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

        event.init_from_btf_task(events::Type::DnsQuery)?;
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

    let entry_ctx = restore_entry_ctx(ProbeFn::vfs_read).ok_or(ProbeError::KProbeArgFailure)?;
    let saved_ctx = entry_ctx.restore();

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
    let ent_probe_ctx = &entry_ctx.restore();
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

    let saved_ctx = &entry_ctx.restore();
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
