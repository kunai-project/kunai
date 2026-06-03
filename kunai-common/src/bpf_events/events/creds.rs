use crate::bpf_events::Event;
use kunai_macros::StrEnum;

pub type CredsEvent = Event<CredsData>;

#[repr(u32)]
#[derive(StrEnum, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum CredsChangeKind {
    #[str("unknown")]
    #[default]
    Unknown = 0,
    #[str("setuid")]
    SetUid = 1,
    #[str("setgid")]
    SetGid = 2,
    #[str("capset")]
    Capset = 3,
}

#[repr(u32)]
#[derive(StrEnum, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum SetIdFlag {
    #[str("unknown")]
    #[default]
    Unknown = 0,
    #[str("LSM_SETID_ID")]
    Id = 1,
    #[str("LSM_SETID_RE")]
    Re = 2,
    #[str("LSM_SETID_RES")]
    Res = 4,
    #[str("LSM_SETID_FS")]
    Fs = 8,
}

#[repr(C)]
pub struct CredSnapshot {
    pub uid: u32,
    pub gid: u32,
    pub euid: u32,
    pub egid: u32,
    pub suid: u32,
    pub sgid: u32,
    pub fsuid: u32,
    pub fsgid: u32,
    pub cap_effective: u64,
    pub cap_permitted: u64,
    pub cap_inheritable: u64,
}

#[repr(C)]
pub struct CredsData {
    pub kind: CredsChangeKind,
    /// LSM_SETID_* flags (0 for capset).
    pub flags: u32,
    pub old: CredSnapshot,
    pub new: CredSnapshot,
}
