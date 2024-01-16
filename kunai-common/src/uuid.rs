use crate::{bpf_target_code, not_bpf_target_code};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Uuid([u8; 16]);

bpf_target_code! {
use crate::helpers::{bpf_get_prandom_u32};

impl Uuid {
    pub fn new_random() -> Self {
        unsafe {
            core::mem::transmute([
                bpf_get_prandom_u32(),
                bpf_get_prandom_u32(),
                bpf_get_prandom_u32(),
                bpf_get_prandom_u32(),
                ])
            }
        }
    }
}

not_bpf_target_code! {
    use uuid;

    impl From<Uuid> for uuid::Uuid {
        fn from(value: Uuid) -> Self {
            Self::from_bytes(value.0)
        }
    }

    impl From<uuid::Uuid> for Uuid {
        fn from(value: uuid::Uuid) -> Self {
            Self(value.into_bytes())
        }
    }


    impl Uuid {
        pub fn new_v4() -> Self {
            uuid::Uuid::new_v4().into()
        }

        pub fn into_uuid(self) -> uuid::Uuid {
            self.into()
        }
    }
}

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

not_bpf_target_code! {

    impl From<TaskUuid> for uuid::Uuid {
        fn from(value: TaskUuid) -> Self {
            unsafe { core::mem::transmute(value) }
        }
    }


    impl TaskUuid {
        pub fn into_uuid(self) -> uuid::Uuid {
            self.into()
        }
    }
}
