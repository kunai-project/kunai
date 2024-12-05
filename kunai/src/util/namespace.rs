use std::hash::Hash;
use std::io::Error as IoError;
use std::num::ParseIntError;

use std::os::unix::io::RawFd;

use std::path::PathBuf;
use std::process;
use std::{fs::File, os::fd::AsRawFd};

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

pub trait Namespace: Default + std::fmt::Debug + PartialEq + Eq + Hash + Clone + Copy {
    fn inum(&self) -> u32;
    fn with_inum(&mut self, inum: u32) -> &mut Self;

    fn as_str() -> &'static str;

    fn path<N: Namespace>(pid: u32) -> PathBuf {
        PathBuf::from(format!("/proc/{pid}/ns")).join(N::as_str())
    }

    fn from_inum<N: Namespace>(inum: u32) -> N {
        let mut n = N::default();
        n.with_inum(inum);
        n
    }

    #[inline(always)]
    fn from_pid<N: Namespace>(pid: u32) -> Result<N, NsError> {
        let mut ns = N::default();
        let link = N::path::<N>(pid).read_link()?;
        let tmp = link.to_string_lossy();
        let prefix = format!("{}:[", N::as_str());

        let s = tmp
            .strip_prefix(prefix.as_str())
            .and_then(|s| s.strip_suffix(']'))
            .ok_or(NsError::Format)?;

        ns.with_inum(s.parse::<u32>()?);

        Ok(ns)
    }

    #[inline(always)]
    fn open<N: Namespace>(pid: u32) -> Result<File, NsError> {
        File::options()
            .read(true)
            .open(N::path::<N>(pid))
            .map_err(NsError::from)
    }
}

macro_rules! impl_ns {
    ($ty: ident, $s: literal) => {
        #[derive(Default, Debug, PartialEq, Eq, Hash, Clone, Copy)]
        pub struct $ty {
            pub inum: u32,
        }

        impl std::fmt::Display for $ty {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "kind={} inum={}", $ty::as_str(), self.inum)
            }
        }

        impl Namespace for $ty {
            #[inline(always)]
            fn inum(&self) -> u32 {
                self.inum
            }

            #[inline(always)]
            fn as_str() -> &'static str {
                $s
            }

            #[inline(always)]
            fn with_inum(&mut self, inum: u32) -> &mut Self {
                self.inum = inum;
                self
            }
        }
    };
}

impl_ns!(Cgroup, "cgroup");
impl_ns!(Ipc, "ipc");
impl_ns!(Mnt, "mnt");
impl_ns!(Net, "net");
impl_ns!(Pid, "pid");
impl_ns!(Time, "time");
impl_ns!(User, "user");
impl_ns!(Uts, "uts");

#[derive(Error, Debug)]
pub enum NsError {
    #[error("link format error")]
    Format,
    #[error("parsing inum error {0}")]
    Parse(#[from] ParseIntError),
    #[error("{0}")]
    Io(#[from] IoError),
}

#[derive(Debug)]
pub struct Switcher<N: Namespace> {
    pub namespace: N,
    src: Option<File>,
    dst: Option<File>,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("setns enter error kind={0} inum={1}: {2}")]
    Enter(String, u32, IoError),
    #[error("setns exit error kind={0} inum{1}: {2}")]
    Exit(String, u32, IoError),
    #[error("{0}")]
    Namespace(#[from] NsError),
    #[error("{0}")]
    Other(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    pub fn enter<N: Namespace>(ns: N, io: IoError) -> Self {
        Self::Enter(N::as_str().to_string(), ns.inum(), io)
    }

    pub fn exit<N: Namespace>(ns: N, io: IoError) -> Self {
        Self::Exit(N::as_str().to_string(), ns.inum(), io)
    }

    pub fn other<E>(err: E) -> Self
    where
        E: Into<Box<dyn std::error::Error + Send + Sync>>,
    {
        Self::Other(err.into())
    }
}

impl<N> Switcher<N>
where
    N: Namespace,
{
    pub fn new(pid: u32) -> Result<Self, Error> {
        let self_pid = process::id();
        let self_ns = N::from_pid::<N>(self_pid)?;
        let target_ns = N::from_pid::<N>(pid)?;

        let (src, dst) = if self_ns == target_ns {
            (None, None)
        } else {
            // namespace of the current process
            let src = N::open::<N>(self_pid)?;
            // namespace of the target process
            let dst = N::open::<N>(pid)?;
            (Some(src), Some(dst))
        };

        Ok(Self {
            namespace: target_ns,
            src,
            dst,
        })
    }

    /// Run function `f` after switching into the namespace. If
    /// switching into/from a namespace fails the approriate error
    /// is returned [Error::Enter] or [Error::Exit]. If any namespace
    /// error is met it returns immediately, otherwise the result of
    /// `f` is returned.
    #[inline(always)]
    pub fn do_in_namespace<F, T>(&self, f: F) -> Result<T, Error>
    where
        F: FnOnce() -> Result<T, Error>,
    {
        self.enter()?;
        let res = f();
        self.exit()?;
        res
    }

    #[inline]
    fn enter(&self) -> Result<(), Error> {
        if let Some(dst) = self.dst.as_ref() {
            // according to setns doc we can set nstype = 0 if we know what kind of NS we navigate into
            setns(dst.as_raw_fd(), CLONE_NEWNS).map_err(|e| Error::enter(self.namespace, e))
        } else {
            Ok(())
        }
    }

    #[inline]
    fn exit(&self) -> Result<(), Error> {
        if let Some(src) = self.src.as_ref() {
            // according to setns doc we can set nstype = 0 if we know what kind of NS we navigate into
            setns(src.as_raw_fd(), CLONE_NEWNS).map_err(|e| Error::exit(self.namespace, e))
        } else {
            Ok(())
        }
    }
}
