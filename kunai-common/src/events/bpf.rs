use super::Event;
use crate::string::String;

pub const KSYM_NAME_LEN: usize = 512;
pub const BPF_OBJ_NAME_LEN: usize = 16;
pub const BPF_INSN_SIZE: usize = 8192;
pub const BPF_TAG_SIZE: usize = 8;

pub type BpfProgLoadEvent = Event<BpfProgData>;

#[repr(C)]
pub struct BpfProgData {
    pub id: u32,
    pub tag: [u8; BPF_TAG_SIZE],
    pub name: String<BPF_OBJ_NAME_LEN>,
    pub ksym: String<KSYM_NAME_LEN>,
    pub attached_func_name: String<512>,
    pub prog_type: u32,
    pub attach_type: u32,
    //pub insns_tid: u64, // put here a transfer id
    //pub insns_len: u32,
    pub verified_insns: Option<u32>,
    pub loaded: bool,
}
