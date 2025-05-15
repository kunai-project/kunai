use crate::bpf_events::Event;
use crate::{buffer::Buffer, net::SocketInfo, string::String};

pub const KSYM_NAME_LEN: usize = 512;
pub const BPF_OBJ_NAME_LEN: usize = 16;
pub const BPF_INSN_SIZE: usize = 8192;
pub const BPF_TAG_SIZE: usize = 8;

pub type BpfProgLoadEvent = Event<BpfProgData>;

#[repr(C)]
pub struct ProgHashes {
    pub md5: String<32>,
    pub sha1: String<40>,
    pub sha256: String<64>,
    pub sha512: String<128>,
    pub size: usize,
}

#[repr(C)]
pub struct BpfProgData {
    pub id: u32,
    pub tag: [u8; BPF_TAG_SIZE],
    pub name: String<BPF_OBJ_NAME_LEN>,
    pub ksym: String<KSYM_NAME_LEN>,
    pub attached_func_name: String<512>,
    pub prog_type: u32,
    pub attach_type: u32,
    pub hashes: Option<ProgHashes>,
    pub verified_insns: Option<u32>,
    pub loaded: bool,
}

pub type BpfSocketFilterEvent = Event<BpfSocketFilterData>;

#[repr(C)]
pub struct BpfSocketFilterData {
    pub socket_info: SocketInfo,
    pub filter: Buffer<2048>,
    pub filter_len: u16,
    pub attached: bool,
}
