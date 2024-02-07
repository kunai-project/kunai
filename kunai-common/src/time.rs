use crate::macros::{bpf_target_code, not_bpf_target_code};

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Time {
    pub sec: i64,
    pub nsec: i64,
}

not_bpf_target_code! {
    use std::time::{SystemTime, UNIX_EPOCH};
    use core::time::Duration;

    impl From<&Time> for SystemTime{
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

bpf_target_code! {
    use crate::{co_re::gen::timespec64};

    impl From<timespec64> for Time{
        fn from(value: timespec64) -> Self {
            Self { sec: value.tv_sec, nsec: value.tv_nsec }
        }
    }

}
