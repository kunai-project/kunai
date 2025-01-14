use std::{
    fs, io,
    num::ParseFloatError,
    time::{Duration, TryFromFloatSecsError},
};

use chrono::{OutOfRangeError, Utc};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("failed to read uptime")]
    Read,
    #[error("parse: {0}")]
    ParseFloat(#[from] ParseFloatError),
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("try_from: {0}")]
    TryFromFloatSecs(#[from] TryFromFloatSecsError),
    #[error("oor: {0}")]
    OutOfRange(#[from] OutOfRangeError),
    #[error("out of range date computation")]
    ComputeOutOfRange,
}

#[derive(Debug)]
pub struct Uptime(f64, chrono::Duration);

impl Uptime {
    #[inline]
    pub fn from_sys() -> Result<Self, Error> {
        // Read the content of /proc/uptime
        let uptime_content = fs::read_to_string("/proc/uptime")?;

        // Extract the uptime in seconds
        let uptime_seconds: f64 = uptime_content
            .split_whitespace()
            .next()
            .ok_or(Error::Read)?
            .parse()?;

        Ok(Self(
            uptime_seconds,
            chrono::Duration::from_std(Duration::try_from_secs_f64(uptime_seconds)?)?,
        ))
    }

    #[inline(always)]
    pub fn as_secs(&self) -> f64 {
        self.0
    }

    #[inline(always)]
    pub fn boot_time(&self) -> Result<chrono::DateTime<Utc>, Error> {
        Utc::now()
            .checked_sub_signed(self.1)
            .ok_or(Error::ComputeOutOfRange)
    }
}
