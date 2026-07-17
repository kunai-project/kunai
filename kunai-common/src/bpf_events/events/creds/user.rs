use crate::bpf_events::LsmSetId;
use std::borrow::Cow;

use super::LsmSetIdFlags;

impl LsmSetIdFlags {
    pub fn to_str_vec(&self) -> Vec<Cow<'static, str>> {
        let mut out = Vec::new();
        for flag in LsmSetId::variants() {
            if self.contains(flag) {
                out.push(Cow::Borrowed(flag.as_str()))
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_str_vec_empty_flags() {
        let flags = LsmSetIdFlags::empty();
        let result = flags.to_str_vec();
        assert!(result.is_empty());
    }

    #[test]
    fn test_to_str_vec_single_flag() {
        let flags = LsmSetIdFlags::from(LsmSetId::Id);
        assert_eq!(flags.to_str_vec(), vec![Cow::Borrowed("LSM_SETID_ID")]);
    }

    #[test]
    fn test_to_str_vec_multiple_flags() {
        let flags = LsmSetId::Id | LsmSetId::Re;
        assert_eq!(
            flags.to_str_vec(),
            vec![Cow::Borrowed("LSM_SETID_ID"), Cow::Borrowed("LSM_SETID_RE")]
        );
    }

    #[test]
    fn test_to_str_vec_all_flags() {
        let flags = LsmSetId::Id | LsmSetId::Re | LsmSetId::Res | LsmSetId::Fs;
        assert_eq!(
            flags.to_str_vec(),
            vec![
                Cow::Borrowed("LSM_SETID_ID"),
                Cow::Borrowed("LSM_SETID_RE"),
                Cow::Borrowed("LSM_SETID_RES"),
                Cow::Borrowed("LSM_SETID_FS")
            ]
        );
    }

    #[test]
    fn test_to_str_vec_flag_from_bits() {
        let flags = LsmSetIdFlags::from_bits(1 | 2); // Id | Re
        assert_eq!(
            flags.to_str_vec(),
            vec![Cow::Borrowed("LSM_SETID_ID"), Cow::Borrowed("LSM_SETID_RE")]
        );
    }
}
