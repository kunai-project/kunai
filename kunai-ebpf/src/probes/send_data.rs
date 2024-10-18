use super::*;
use aya_ebpf::programs::ProbeContext;
use kunai_common::{
    buffer::Buffer,
    net::{SaFamily, SockAddr, SocketInfo},
};

/*
Experimental probe to detect encrypted trafic based
on packet entropy. The idea is that hooking into SSL/TLS
with uprobes requires a lot of effort and is not guaranteed to
work all the time (static compilation for instance). So the
idea came of a more generic event giving more high level information,
such as the shannon entropy, of the data sent over the network.
 */

#[kprobe(function = "security_socket_sendmsg")]
pub fn net_security_socket_sendmsg(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_sock_send_data(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sock_send_data(ctx: &ProbeContext) -> ProbeResult<()> {
    // returns early if event is disabled
    if_disabled_return!(Type::SendData, ());

    // we get bpf configuration
    let c = get_cfg!()?;

    let socket = co_re::socket::from_ptr(kprobe_arg!(ctx, 0)?);

    let pmsg = co_re::msghdr::from_ptr(kprobe_arg!(ctx, 1)?);

    let sock = core_read_kernel!(socket, sk)?;
    let sk_common = core_read_kernel!(sock, sk_common)?;
    let si = SocketInfo::try_from(sock)?;

    // we process only IPv4 and IPv6
    if !si.is_family(SaFamily::AF_INET) && !si.is_family(SaFamily::AF_INET6) {
        return Ok(());
    }

    let iov_iter = core_read_kernel!(pmsg, msg_iter)?;

    alloc::init()?;

    let iov_buf = alloc::alloc_zero::<Buffer<ENCRYPT_DATA_MAX_BUFFER_SIZE>>()?;

    let msg_size = core_read_kernel!(iov_iter, count)?;

    // if iov_iter contains enough bytes to trigger event
    if msg_size < c.send_data_min_len {
        return Ok(());
    }

    let dst_ip_port = {
        // handle this particular case: https://elixir.bootlin.com/linux/v6.9.5/source/net/socket.c#L2180
        if pmsg.has_msg_name() {
            let sock_addr = core_read_kernel!(pmsg, sockaddr)?;
            SockAddr::from_sockaddr(sock_addr)?
        } else {
            SockAddr::dst_from_sock_common(sk_common)?
        }
    };

    let src_ip_port = SockAddr::src_from_sock_common(sk_common)?;

    let iov_iter = core_read_kernel!(pmsg, msg_iter)?;
    if let Err(e) = iov_buf.fill_from_iov_iter::<128>(iov_iter, None) {
        match e {
            // buffer full is not a bad error it just tell we have no more space in our buffer
            kunai_common::buffer::Error::BufferFull => {}
            e => return Err(e.into()),
        }
    }

    let event = alloc::alloc_zero::<SendEntropyEvent>()?;

    event.init_from_current_task(Type::SendData)?;

    // setting events' data
    event.data.socket = si;
    event.data.src = src_ip_port;
    event.data.dst = dst_ip_port;
    event.data.real_data_size = msg_size;
    // we update the frequencies we are going to send to userland
    event.update_frequencies(iov_buf.as_slice());

    pipe_event(ctx, event);

    Ok(())
}
