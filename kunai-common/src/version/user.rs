use super::KernelVersion;
use aya::Pod;
use core::ffi::FromBytesUntilNulError;
use core::num::ParseIntError;
use std::fmt::Display;
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum KernelVersionError {
    #[error("parse int error {0}")]
    ParseIntError(ParseIntError),
    #[error("major digit is missing")]
    MajorIsMissing,
    #[error("minor digit is missing")]
    MinorIsMissing,
    #[error("version string is empty")]
    EmptyVersionString,
    #[error("{0}")]
    ByteUntilNull(#[from] FromBytesUntilNulError),
}

unsafe impl Pod for KernelVersion {}

impl From<ParseIntError> for KernelVersionError {
    fn from(value: ParseIntError) -> Self {
        Self::ParseIntError(value)
    }
}

impl Display for KernelVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            Self::MIN_VERSION => write!(f, "KernelVersion::MIN"),
            Self::MAX_VERSION => write!(f, "KernelVersion::MAX"),
            _ => write!(f, "{}.{}.{}", self.major, self.minor, self.patch),
        }
    }
}

impl FromStr for KernelVersion {
    type Err = KernelVersionError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl TryFrom<&str> for KernelVersion {
    type Error = KernelVersionError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut v = Self::default();
        let sp = value.split('.').collect::<Vec<&str>>();
        let major = sp.first().ok_or(KernelVersionError::MajorIsMissing)?;
        if major.is_empty() {
            return Err(KernelVersionError::MajorIsMissing);
        }
        v.major = u16::from_str(major)?;
        v.minor = u16::from_str(sp.get(1).ok_or(KernelVersionError::MinorIsMissing)?)?;
        if sp.len() >= 3 {
            v.patch = u16::from_str(sp[2])?;
        }
        Ok(v)
    }
}
