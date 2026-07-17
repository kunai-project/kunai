use crate::bpf_events::Event;
use flaglet::flags;
use kunai_macros::StrEnum;

#[cfg(feature = "user")]
mod user;

pub type CredsEvent = Event<CredsData>;

#[repr(C)]
#[derive(StrEnum, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum CredsChangeKind {
    #[str("setuid")]
    SetUid,
    #[str("setgid")]
    SetGid,
    #[str("capset")]
    Capset,
}

#[flags(i32)]
#[derive(StrEnum, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// defined in : https://elixir.bootlin.com/linux/v7.1.3/source/include/linux/security.h#L242
pub enum LsmSetId {
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
    pub flags: LsmSetIdFlags,
    pub old: CredSnapshot,
    pub new: CredSnapshot,
}
