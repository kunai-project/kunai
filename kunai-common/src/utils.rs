use crate::macros::bpf_target_code;

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}
