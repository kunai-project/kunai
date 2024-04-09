not_bpf_target_code! {
    mod user;
    pub use user::*;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct KernelVersion {
    pub major: u16,
    pub minor: u16,
    pub patch: u16,
}


#[macro_export]
macro_rules! kernel {
    ($major:literal) => {
        $crate::version::KernelVersion::new($major, 0, 0)
    };
    ($major:literal, $minor:literal) => {
        $crate::version::KernelVersion::new($major, $minor, 0)
    };
    ($major:literal,$minor:literal,$patch:literal) => {
        $crate::version::KernelVersion::new($major, $minor, $patch)
    };
}

use crate::macros::{bpf_target_code, not_bpf_target_code};

impl KernelVersion {
    pub const MAX_VERSION: KernelVersion = KernelVersion {
        major: u16::MAX,
        minor: u16::MAX,
        patch: u16::MAX,
    };

    pub const MIN_VERSION: KernelVersion = KernelVersion {
        major: u16::MIN,
        minor: u16::MIN,
        patch: u16::MIN,
    };

    pub const fn new(major: u16, minor: u16, patch: u16) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl PartialOrd for KernelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(
            self.major
                .cmp(&other.major)
                .then_with(|| self.minor.cmp(&other.minor))
                .then_with(|| self.patch.cmp(&other.patch)),
        )
    }
}
