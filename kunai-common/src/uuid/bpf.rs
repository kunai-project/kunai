use crate::helpers::bpf_get_prandom_u32;

use super::Uuid;

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
