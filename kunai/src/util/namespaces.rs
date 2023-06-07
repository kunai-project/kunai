use std::io::Error as IoError;
use std::os::fd::FromRawFd;
use std::os::unix::io::RawFd;
use std::path::PathBuf;
use std::process;
use std::{fs::File, os::fd::AsRawFd};

use libc::{c_int, pid_t, syscall, SYS_pidfd_open};
use thiserror::Error;

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

fn open_rdonly<T: AsRef<str>>(path: T) -> Result<RawFd, IoError> {
    let path = std::ffi::CString::new(path.as_ref()).unwrap();
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDONLY) } as RawFd;
    if fd < 0 {
        return Err(IoError::last_os_error());
    }
    Ok(fd)
}

pub fn unshare(flags: c_int) -> Result<(), IoError> {
    let rc = unsafe { libc::unshare(flags) };

    if rc < 0 {
        return Err(IoError::last_os_error());
    }
    Ok(())
}

#[derive(Debug)]
pub struct MntNamespace {
    pub inum: u32,
    fd: File,
    saved: File,
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("pidfd_open failure pid={0}: {1}")]
    PidFdOpen(i32, IoError),
    #[error("failed to open /proc/{0}/ns/mnt: {1}")]
    ProcMntOpen(i32, IoError),
    #[error("setns failure inum={0}: {1}")]
    SetNs(u32, IoError),
    #[error("unshare failure: {0}")]
    Unshare(#[from] IoError),
}

impl MntNamespace {
    #[inline]
    fn procfs_path(pid: pid_t) -> String {
        format!("/proc/{pid}/ns/mnt")
    }

    pub fn from_pid_with_inum(pid: pid_t, inum: u32) -> Result<Self, Error> {
        let self_pid = process::id() as i32;

        /*let fd =
        unsafe { File::from_raw_fd(pidfd_open(pid, 0).map_err(|e| Error::PidFdOpen(pid, e))?) };*/

        let fd = unsafe {
            File::from_raw_fd(
                open_rdonly(Self::procfs_path(pid)).map_err(|e| Error::ProcMntOpen(pid, e))?,
            )
        };

        /*let saved = unsafe {
            File::from_raw_fd(
                pidfd_open(process::id() as i32, 0).map_err(|e| Error::PidFdOpen(self_pid, e))?,
            )
        };*/

        let saved = unsafe {
            File::from_raw_fd(
                open_rdonly(Self::procfs_path(self_pid))
                    .map_err(|e| Error::ProcMntOpen(self_pid, e))?,
            )
        };

        Ok(Self { inum, fd, saved })
    }

    pub fn switch(&self) -> Result<(), Error> {
        unshare(libc::CLONE_FS).map_err(Error::Unshare)?;
        setns(self.fd.as_raw_fd(), libc::CLONE_NEWNS).map_err(|e| Error::SetNs(self.inum, e))
    }

    pub fn restore(&self) -> Result<(), Error> {
        unshare(libc::CLONE_FS).map_err(Error::Unshare)?;
        setns(self.saved.as_raw_fd(), libc::CLONE_NEWNS).map_err(|e| Error::SetNs(self.inum, e))
    }
}

pub struct PathNs {
    ns: MntNamespace,
    path: PathBuf,
}
