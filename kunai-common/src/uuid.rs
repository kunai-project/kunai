use crate::macros::{bpf_target_code, not_bpf_target_code};

not_bpf_target_code! {
    mod user;
    pub use user::*;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Uuid([u8; 16]);

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskUuid {
    pub start_time_ns: u64,
    pub random: u32,
    pub pid: u32,
}

impl TaskUuid {
    pub fn new(high: u64, random: u32, low: u32) -> Self {
        TaskUuid {
            start_time_ns: high,
            random,
            pid: low,
        }
    }

    #[allow(dead_code)]
    pub fn init(&mut self, high: u64, low: u32) {
        self.start_time_ns = high;
        self.pid = low;
    }
}

impl From<TaskUuid> for u128 {
    fn from(value: TaskUuid) -> Self {
        (value.start_time_ns as u128) << 64 | (value.random as u128) << 32 | value.pid as u128
    }
}

impl From<u128> for TaskUuid {
    fn from(value: u128) -> Self {
        Self {
            start_time_ns: (value >> 64) as u64,
            random: (value >> 32) as u32,
            pid: value as u32,
        }
    }
}
