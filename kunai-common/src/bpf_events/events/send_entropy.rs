use crate::{bpf_events::Event, macros::not_bpf_target_code};

use crate::net::SockAddr;

pub const ENCRYPT_DATA_MAX_BUFFER_SIZE: usize = 4096;

#[repr(C)]
pub struct SendEntropyData {
    pub src: SockAddr,
    pub dst: SockAddr,
    pub freq: [u32; 256],
    pub freq_sum: u32,
    pub real_data_size: u64,
}

pub type SendEntropyEvent = Event<SendEntropyData>;

impl SendEntropyEvent {
    #[inline]
    pub fn update_frequencies<T: AsRef<[u8]>>(&mut self, buf: T) {
        // increases bytes frequencies
        let bytes = buf.as_ref();
        for i in 0..ENCRYPT_DATA_MAX_BUFFER_SIZE {
            if i >= bytes.len() {
                return;
            }
            let b = bytes[i];
            self.data.freq[b as usize] += 1;
            self.data.freq_sum += 1;
        }
    }
}

not_bpf_target_code! {
    impl SendEntropyEvent {
        // we cannot do complicated operations of f32 in eBPF
        #[inline]
        pub fn shannon_entropy(&self) -> f32{
            let mut entropy = 0.0;

            for &freq in &self.data.freq{
                if freq == 0{
                    continue
                }
                let p = freq as f32 / self.data.freq_sum as f32;
                entropy -= p * p.log2();
            }

            entropy
        }
    }

}
