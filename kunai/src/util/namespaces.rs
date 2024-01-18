use std::io::Error as IoError;
use std::num::ParseIntError;

use std::os::unix::io::RawFd;

use std::path::PathBuf;
use std::process;
use std::{fs::File, os::fd::AsRawFd};

use libc::{c_int, pid_t, syscall, SYS_pidfd_open};
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

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum Kind {
    Cgroup,
    Ipc,
    Mnt,
    Net,
    Pid,
    Time,
    User,
    Uts,
}

impl std::fmt::Display for Kind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_str())
    }
}

impl Kind {
    #[inline]
    pub fn path(&self, pid: u32) -> PathBuf {
        PathBuf::from(format!("/proc/{pid}/ns")).join(self.to_str())
    }

    #[inline]
    pub const fn to_str(&self) -> &str {
        match self {
            Self::Cgroup => "cgroup",
            Self::Ipc => "ipc",
            Self::Mnt => "mnt",
            Self::Net => "net",
            Self::Pid => "pid",
            Self::Time => "time",
            Self::User => "user",
            Self::Uts => "uts",
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub struct Namespace {
    pub inum: u32,
    pub kind: Kind,
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "inum={} kind={}", self.inum, self.kind.to_str())
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
        let prefix = format!("{}:[", kind.to_str());

        let s = tmp
            .strip_prefix(prefix.as_str())
            .and_then(|s| s.strip_suffix(']'))
            .ok_or(NsError::Format)?;

        Ok(Namespace {
            inum: s.parse::<u32>()?,
            kind: kind,
        })
    }

    #[inline(always)]
    pub fn open(&self, pid: u32) -> Result<File, NsError> {
        File::options()
            .read(true)
            .open(self.kind.path(pid))
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
    pub fn new(ns: Namespace, pid: u32) -> Result<Self, Error> {
        let self_pid = process::id();
        let self_ns = Namespace::from_pid(ns.kind, self_pid)?;

        let fd = ns.open(pid)?;
        let saved = self_ns.open(self_pid)?;

        Ok(Self {
            namespace: ns,
            dst: fd,
            src: saved,
        })
    }

    #[inline]
    pub fn enter(&self) -> Result<(), Error> {
        // according to setns doc we can set nstype = 0 if we know what kind of NS we navigate into
        setns(self.dst.as_raw_fd(), 0).map_err(|e| Error::SetNs(self.namespace, e))
    }

    #[inline]
    pub fn exit(&self) -> Result<(), Error> {
        // according to setns doc we can set nstype = 0 if we know what kind of NS we navigate into
        setns(self.src.as_raw_fd(), 0).map_err(|e| Error::SetNs(self.namespace, e))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_open() {
        let pid = process::id() as i32;
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
            Switcher::new(Namespace::new(kind, 0), pid).unwrap();
        }
    }

    #[test]
    fn test_read() {
        let pid = process::id() as i32;
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
        let pid = process::id() as i32;
        let ns = Namespace::from_pid(Kind::Pid, pid).unwrap();
        let other = Namespace::from_pid(Kind::Pid, pid).unwrap();
        assert_eq!(ns, other)
    }
}
