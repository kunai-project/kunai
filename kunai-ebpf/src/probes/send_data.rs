use super::*;
use aya_ebpf::programs::ProbeContext;
use kunai_common::{buffer::Buffer, net::IpPort};

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

    let psock = co_re::socket::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    let pmsg = co_re::msghdr::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);

    let sk_common = core_read_kernel!(psock, sk, sk_common)?;

    let sa_family = core_read_kernel!(sk_common, skc_family)?;

    // we want to process only INET sock families
    if sa_family as u32 != AF_INET && sa_family as u32 != AF_INET6 {
        return Ok(());
    }

    let iov_iter = core_read_kernel!(pmsg, msg_iter)?;

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
            IpPort::from_sockaddr(sock_addr)?
        } else {
            IpPort::dst_from_sock_common(sk_common)?
        }
    };

    let iov_iter = core_read_kernel!(pmsg, msg_iter)?;
    if let Err(e) = iov_buf.fill_from_iov_iter::<128>(iov_iter, None) {
        match e {
            // buffer full is not a bad error it just tell we have no more space in our buffer
            kunai_common::buffer::Error::BufferFull => {}
            e => return Err(e.into()),
        }
    }

    alloc::init()?;

    let event = alloc::alloc_zero::<SendEntropyEvent>()?;

    event.init_from_current_task(Type::SendData)?;

    // setting events' data
    event.data.ip_port = dst_ip_port;
    event.data.real_data_size = msg_size;
    // we update the frequencies we are going to send to userland
    event.update_frequencies(iov_buf.as_slice());

    pipe_event(ctx, event);

    Ok(())
}
