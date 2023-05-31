use chrono::prelude::*;
use core::mem::{size_of, zeroed, MaybeUninit};
use ip_network::IpNetwork;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::net::IpAddr;

pub mod bpf;

#[inline]
pub(crate) fn is_public_ip(ip: IpAddr) -> bool {
    let ip_network: IpNetwork = ip.into();

    match ip_network {
        IpNetwork::V4(v4) => !v4.is_private(),
        IpNetwork::V6(v6) => !v6.is_unique_local(),
    }
}

pub(crate) fn get_clk_tck() -> i64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) }
}

// inspired from: https://github.com/itchyny/uptime-rs
// the code panics if we cannot retrieve boot time
#[allow(dead_code)]
pub(crate) fn get_boot_time() -> DateTime<Utc> {
    let mut info: libc::sysinfo = unsafe { zeroed() };
    let ret = unsafe { libc::sysinfo(&mut info) };
    if ret != 0 {
        panic!("failed to retrieve sysinfo");
    }
    // we have to work with seconds as sysinfo returns time since boot in seconds
    let boot_time_sec = Utc::now()
        .timestamp()
        .checked_sub(info.uptime as i64)
        .unwrap();
    DateTime::<Utc>::from_utc(
        NaiveDateTime::from_timestamp_opt(boot_time_sec, 0).unwrap(),
        Utc,
    )
}

#[derive(Debug)]
pub enum RandError {
    CallFailure,
    PartiallyRandomized,
}

pub(crate) fn getrandom<T: Sized>() -> Result<T, RandError> {
    let mut t = MaybeUninit::<T>::uninit();
    let buflen = size_of::<T>();
    let rc = unsafe { libc::getrandom(t.as_mut_ptr() as *mut _, buflen, 0) };
    if rc == -1 {
        return Err(RandError::CallFailure);
    }
    if rc as usize != buflen {
        return Err(RandError::PartiallyRandomized);
    }
    Ok(unsafe { t.assume_init() })
}

#[inline]
pub(crate) fn md5_data<T: AsRef<[u8]>>(data: T) -> String {
    let mut h = Md5::new();
    h.update(data.as_ref());
    hex::encode(h.finalize())
}

#[inline]
pub(crate) fn sha1_data<T: AsRef<[u8]>>(data: T) -> String {
    let mut h = Sha1::new();
    h.update(data.as_ref());
    hex::encode(h.finalize())
}

#[inline]
pub(crate) fn sha256_data<T: AsRef<[u8]>>(data: T) -> String {
    let mut h = Sha256::new();
    h.update(data.as_ref());
    hex::encode(h.finalize())
}

#[inline]
pub(crate) fn sha512_data<T: AsRef<[u8]>>(data: T) -> String {
    let mut h = Sha512::new();
    h.update(data.as_ref());
    hex::encode(h.finalize())
}

#[cfg(test)]
mod test {
    #[test]
    fn toast() {}
}
