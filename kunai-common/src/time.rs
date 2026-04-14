#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub sec: i64,
    pub nsec: i64,
}

impl Time {
    pub fn new(sec: i64, nsec: i64) -> Self {
        Self { sec, nsec }
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;
    use core::time::Duration;
    use std::time::{SystemTime, UNIX_EPOCH};

    impl From<&Time> for SystemTime {
        fn from(value: &Time) -> Self {
            let duration = Duration::new(value.sec as u64, value.nsec as u32);
            UNIX_EPOCH + duration
        }
    }

    impl Time {
        pub fn into_system_time(self) -> SystemTime {
            (&self).into()
        }
    }
}

#[cfg(target_arch = "bpf")]
mod bpf {
    use super::*;
    use crate::co_re::timespec64;

    impl From<timespec64> for Time {
        fn from(value: timespec64) -> Self {
            Self {
                sec: value.tv_sec,
                nsec: value.tv_nsec,
            }
        }
    }
}
