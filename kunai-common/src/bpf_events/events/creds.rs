use crate::bpf_events::Event;
use flaglet::flags;
use kunai_macros::StrEnum;

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

#[cfg(feature = "user")]
mod user {
    use crate::bpf_events::LsmSetId;

    use super::LsmSetIdFlags;

    impl std::fmt::Display for LsmSetIdFlags {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
            let mut init = false;

            for flag in LsmSetId::variants() {
                if self.contains(flag) {
                    if init {
                        write!(f, "|")?;
                    }
                    write!(f, "{}", flag.as_str())?;
                    init = true;
                }
            }
            Ok(())
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_empty_flags() {
        let flags = LsmSetIdFlags::empty();
        assert_eq!(format!("{}", flags), "");
    }

    #[test]
    fn test_display_single_flag() {
        let flags = LsmSetIdFlags::from(LsmSetId::Id);
        assert_eq!(format!("{}", flags), "LSM_SETID_ID");
    }

    #[test]
    fn test_display_multiple_flags() {
        let flags = LsmSetId::Id | LsmSetId::Re;
        let result = format!("{}", flags);
        assert_eq!(result, "LSM_SETID_ID|LSM_SETID_RE");
    }

    #[test]
    fn test_display_all_flags() {
        let flags = LsmSetId::Id | LsmSetId::Re | LsmSetId::Res | LsmSetId::Fs;
        let result = format!("{}", flags);
        assert_eq!(
            result,
            "LSM_SETID_ID|LSM_SETID_RE|LSM_SETID_RES|LSM_SETID_FS"
        );
    }

    #[test]
    fn test_display_flag_from_bits() {
        // Test flags created from raw bits
        let flags = LsmSetIdFlags::from_bits(1 | 2); // Id | Re
        let result = format!("{}", flags);
        assert_eq!(result, "LSM_SETID_ID|LSM_SETID_RE");
    }
}
