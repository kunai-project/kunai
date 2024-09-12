use std::io::Error as IoError;
use std::num::ParseIntError;

use std::os::unix::io::RawFd;

use std::path::PathBuf;
use std::process;
use std::{fs::File, os::fd::AsRawFd};

use kunai_macros::StrEnum;
use libc::{c_int, pid_t, syscall, SYS_pidfd_open, CLONE_NEWNS};
use thiserror::Error;

#[allow(dead_code)]
pub fn pidfd_open(pid: pid_t, flags: c_int) -> Result<RawFd, IoError> {
    let result = unsafe { syscall(SYS_pidfd_open, pid, flags) };

    if result < 0 {
        return Err(IoError::last_os_error());
    }

    Ok(result as RawFd)
}

pub fn setns(fd: c_int, nstype: c_int) -> Result<(), IoError> {
    let rc = unsafe { libc::setns(fd, nstype) };

    if rc < 0 {
        return Err(IoError::last_os_error());
    }

    Ok(())
}

pub fn unshare(flags: c_int) -> Result<(), IoError> {
    let rc = unsafe { libc::unshare(flags) };

    if rc < 0 {
        return Err(IoError::last_os_error());
    }
    Ok(())
}

#[derive(StrEnum, Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Kind {
    #[str("cgroup")]
    Cgroup,
    #[str("ipc")]
    Ipc,
    #[str("mnt")]
    Mnt,
    #[str("net")]
    Net,
    #[str("pid")]
    Pid,
    #[str("time")]
    Time,
    #[str("user")]
    User,
    #[str("uts")]
    Uts,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Kind {
    #[inline]
    pub fn path(&self, pid: u32) -> PathBuf {
        PathBuf::from(format!("/proc/{pid}/ns")).join(self.as_str())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Namespace {
    pub inum: u32,
    pub kind: Kind,
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "inum={} kind={}", self.inum, self.kind.as_str())
    }
}

#[derive(Error, Debug)]
pub enum NsError {
    #[error("link format error")]
    Format,
    #[error("parsing inum error {0}")]
    Parse(#[from] ParseIntError),
    #[error("{0}")]
    Io(#[from] IoError),
}

impl Namespace {
    #[inline(always)]
    pub const fn new(kind: Kind, inum: u32) -> Namespace {
        Self { inum, kind }
    }

    #[inline(always)]
    pub const fn cgroup(inum: u32) -> Namespace {
        Self::new(Kind::Cgroup, inum)
    }

    #[inline(always)]
    pub const fn ipc(inum: u32) -> Namespace {
        Self::new(Kind::Ipc, inum)
    }

    #[inline(always)]
    pub const fn mnt(inum: u32) -> Namespace {
        Self::new(Kind::Mnt, inum)
    }

    #[inline(always)]
    pub const fn net(inum: u32) -> Namespace {
        Self::new(Kind::Net, inum)
    }

    #[inline(always)]
    pub const fn pid(inum: u32) -> Namespace {
        Self::new(Kind::Pid, inum)
    }

    #[inline(always)]
    pub const fn time(inum: u32) -> Namespace {
        Self::new(Kind::Time, inum)
    }

    #[inline(always)]
    pub const fn user(inum: u32) -> Namespace {
        Self::new(Kind::User, inum)
    }

    #[inline(always)]
    pub const fn uts(inum: u32) -> Namespace {
        Self::new(Kind::Uts, inum)
    }

    #[inline(always)]
    pub fn is_kind(&self, kind: Kind) -> bool {
        self.kind == kind
    }

    #[inline]
    pub fn from_pid(kind: Kind, pid: u32) -> Result<Self, NsError> {
        let link = kind.path(pid).read_link()?;
        let tmp = link.to_string_lossy();
        let prefix = format!("{}:[", kind.as_str());

        let s = tmp
            .strip_prefix(prefix.as_str())
            .and_then(|s| s.strip_suffix(']'))
            .ok_or(NsError::Format)?;

        Ok(Namespace {
            inum: s.parse::<u32>()?,
            kind,
        })
    }

    #[inline(always)]
    pub fn open(kind: Kind, pid: u32) -> Result<File, NsError> {
        File::options()
            .read(true)
            .open(kind.path(pid))
            .map_err(NsError::from)
    }
}

#[derive(Debug)]
pub struct Switcher {
    pub namespace: Namespace,
    src: File,
    dst: File,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("setns failure namespace={0}: {1}")]
    SetNs(Namespace, IoError),
    #[error("{0}")]
    Namespace(#[from] NsError),
}

impl Switcher {
    pub fn new(kind: Kind, pid: u32) -> Result<Self, Error> {
        let self_pid = process::id();
        let ns = Namespace::from_pid(kind, pid)?;

        // namespace of the current process
        let src = Namespace::open(kind, self_pid)?;
        // namespace of the target process
        let dst = Namespace::open(kind, pid)?;

        Ok(Self {
            namespace: ns,
            src,
            dst,
        })
    }

    #[inline]
    pub fn enter(&self) -> Result<(), Error> {
        // according to setns doc we can set nstype = 0 if we know what kind of NS we navigate into
        setns(self.dst.as_raw_fd(), CLONE_NEWNS).map_err(|e| Error::SetNs(self.namespace, e))
    }

    #[inline]
    pub fn exit(&self) -> Result<(), Error> {
        // according to setns doc we can set nstype = 0 if we know what kind of NS we navigate into
        setns(self.src.as_raw_fd(), CLONE_NEWNS).map_err(|e| Error::SetNs(self.namespace, e))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_open() {
        let pid = process::id();
        for kind in [
            Kind::Cgroup,
            Kind::Ipc,
            Kind::Mnt,
            Kind::Net,
            Kind::Pid,
            Kind::Time,
            Kind::User,
            Kind::Uts,
        ] {
            Switcher::new(kind, pid).unwrap();
        }
    }

    #[test]
    fn test_read() {
        let pid = process::id();
        for kind in [
            Kind::Cgroup,
            Kind::Ipc,
            Kind::Mnt,
            Kind::Net,
            Kind::Pid,
            Kind::Time,
            Kind::User,
            Kind::Uts,
        ] {
            let ns = Namespace::from_pid(kind, pid).unwrap();
            assert_eq!(ns.kind, kind);
            assert!(ns.inum > 0);
            println!("{:#?}", ns)
        }
    }

    #[test]
    fn test_eq() {
        let pid = process::id();
        let ns = Namespace::from_pid(Kind::Pid, pid).unwrap();
        let other = Namespace::from_pid(Kind::Pid, pid).unwrap();
        assert_eq!(ns, other)
    }
}
