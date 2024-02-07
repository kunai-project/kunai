use super::*;
use aya_bpf::programs::ProbeContext;
use kunai_common::{buffer::Buffer, net::IpPort};

/*
Experimental probe to detect encrypted trafic based
on packet entropy. The idea is that hooking into SSL/TLS
with uprobes requires a lot of effort and is not guaranteed to
work all the time (static compilation for instance). So the
idea came of a more generic event giving more high level information,
such as the shannon entropy, of the data sent over the network.
 */

#[kprobe(name = "net.security_socket_sendmsg")]
pub fn sock_sendmsg(ctx: ProbeContext) -> u32 {
    match unsafe { try_sock_send_data(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sock_send_data(ctx: &ProbeContext) -> ProbeResult<()> {
    let psock = co_re::socket::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    let pmsg = co_re::msghdr::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);

    let sk_common = psock
        .sk()
        .and_then(|sk| sk.sk_common())
        .ok_or(ProbeError::CoReFieldMissing)?;

    let sa_family = sk_common.skc_family().ok_or(ProbeError::CoReFieldMissing)?;

    // we want to process only INET sock families
    if sa_family as u32 != AF_INET && sa_family as u32 != AF_INET6 {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<SendEntropyEvent>()?;

    event.init_from_current_task(Type::SendData)?;

    let iov_iter = pmsg.msg_iter().ok_or(ProbeError::CoReFieldMissing)?;

    let iov_buf = alloc::alloc_zero::<Buffer<ENCRYPT_DATA_MAX_BUFFER_SIZE>>()?;

    let msg_size = iov_iter.count().ok_or(ProbeError::CoReFieldMissing)?;
    let nr_segs = iov_iter.nr_segs().ok_or(ProbeError::CoReFieldMissing)?;

    let ip_port = IpPort::from_sock_common_foreign_ip(&sk_common)?;

    // if iov_iter contains enough bytes, is valid and ip_port is not zeros (might be the case if connection not established yet)
    if msg_size < 256 || nr_segs == 0 || ip_port.is_zero() {
        return Ok(());
    }

    let iov_iter = pmsg.msg_iter().ok_or(ProbeError::CoReFieldMissing)?;
    if let Err(e) = iov_buf.fill_from_iov_iter::<128>(&iov_iter, None) {
        match e {
            // buffer full is not a bad error it just tell we have no more space in our buffer
            kunai_common::buffer::Error::BufferFull => {}
            e => return Err(e.into()),
        }
    }

    // setting events' data
    event.data.ip_port = ip_port;
    event.data.real_data_size = msg_size;
    // we update the frequencies we are going to send to userland
    event.update_frequencies(iov_buf.as_slice());

    pipe_event(ctx, event);

    Ok(())
}
