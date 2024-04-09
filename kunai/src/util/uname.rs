use core::ffi::FromBytesUntilNulError;
use std::mem::MaybeUninit;
use std::{io::Error as IoError, str::FromStr};
use thiserror::Error;

use kunai_common::version::{KernelVersion, KernelVersionError};
use libc::{uname, utsname};

pub struct Utsname {
    u: utsname,
}

macro_rules! impl_getter {
    ($getter:ident) => {
        impl Utsname {
            pub fn $getter(&self) -> Result<std::borrow::Cow<'_, str>, FromBytesUntilNulError> {
                Ok(core::ffi::CStr::from_bytes_until_nul(unsafe {
                    core::mem::transmute(self.u.$getter.as_slice())
                })?
                .to_string_lossy())
            }
        }
    };
}

impl_getter!(sysname);
impl_getter!(nodename);
impl_getter!(release);
impl_getter!(version);
impl_getter!(machine);
impl_getter!(domainname);

#[derive(Debug, Error)]
pub enum Error {
    #[error("{0}")]
    Io(#[from] IoError),
    #[error("{0}")]
    KernelVersion(#[from] KernelVersionError),
}

impl Utsname {
    pub fn from_sys() -> Result<Self, IoError> {
        let mut u: MaybeUninit<utsname> = MaybeUninit::zeroed();
        let result = unsafe { uname(u.as_mut_ptr()) };
        if result == -1 {
            return Err(IoError::last_os_error());
        }
        Ok(Self {
            u: unsafe { u.assume_init() },
        })
    }

    pub fn kernel_version() -> Result<KernelVersion, Error> {
        Ok(Self::from_sys()?.try_into_kernel_version()?)
    }

    pub fn try_into_kernel_version(self) -> Result<KernelVersion, KernelVersionError> {
        TryInto::<KernelVersion>::try_into(self)
    }
}

impl TryInto<KernelVersion> for Utsname {
    type Error = KernelVersionError;
    fn try_into(self) -> Result<KernelVersion, Self::Error> {
        let release = self.release()?;

        // we take only something looking like "[0-9]*?\.[0-9]*?\.[0-9]*?"
        let release = release
            .splitn(2, |c: char| !(c == '.' || c.is_numeric()))
            .collect::<Vec<&str>>();

        if release.is_empty() {
            return Err(KernelVersionError::EmptyVersionString);
        }

        KernelVersion::from_str(release[0])
    }
}

#[cfg(test)]
mod test {
    use super::Utsname;

    #[test]
    fn test_sysname() {
        let u = Utsname::from_sys().unwrap();
        assert_eq!(u.sysname().unwrap(), "Linux");

        assert!(!u.nodename().unwrap().is_empty());
        assert!(u.nodename().unwrap().len() < 64);

        assert!(!u.release().unwrap().is_empty());
        assert!(u.release().unwrap().len() < 64);

        assert!(!u.version().unwrap().is_empty());
        assert!(u.version().unwrap().len() < 64);

        assert!(!u.machine().unwrap().is_empty());
        assert!(u.machine().unwrap().len() < 64);

        assert!(!u.domainname().unwrap().is_empty());
        assert!(u.domainname().unwrap().len() < 64);
    }
}
