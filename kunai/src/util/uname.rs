use core::ffi::FromBytesUntilNulError;
use std::io::Error as IoError;
use std::mem::MaybeUninit;

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
