use crate::macros::{bpf_target_code, not_bpf_target_code};

not_bpf_target_code! {
    mod user;

}

bpf_target_code! {
    mod bpf;
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Uuid([u8; 16]);

/// Represents a UUID for a given task group / process
#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct ProcUuid {
    // start time of the task group leader
    pub leader_start_time_ns: u64,
    // a random part to make this unique across machines
    pub random: u32,
    // task group id in kernel or PID in userland
    pub tgid: u32,
}

impl ProcUuid {
    pub fn new(leader_start_time_ns: u64, random: u32, tgid: u32) -> Self {
        ProcUuid {
            leader_start_time_ns,
            random,
            tgid,
        }
    }

    #[allow(dead_code)]
    pub fn init(&mut self, start_time_ns: u64, tgid: u32) {
        self.leader_start_time_ns = start_time_ns;
        self.tgid = tgid;
    }
}

impl From<ProcUuid> for u128 {
    fn from(value: ProcUuid) -> Self {
        (value.leader_start_time_ns as u128) << 64
            | (value.random as u128) << 32
            | value.tgid as u128
    }
}

impl From<u128> for ProcUuid {
    fn from(value: u128) -> Self {
        Self {
            leader_start_time_ns: (value >> 64) as u64,
            random: (value >> 32) as u32,
            tgid: value as u32,
        }
    }
}
