use super::Capability;
use std::borrow::Cow;

/// Iterates over all set bits in a u64 bitmask.
#[inline]
pub fn caps_to_str_vec(mut bits: u64) -> Vec<Cow<'static, str>> {
    let mut out = Vec::new();
    while bits != 0 {
        let bit = bits.trailing_zeros();
        if bit > Capability::cap_last_cap() as u32 {
            break;
        }

        // Err should never happen as we already tested bit is in range
        if let Ok(cap) = Capability::try_from_uint(bit) {
            out.push(Cow::Borrowed(cap.as_str()))
        }

        bits &= !(1 << bit); // Clear the bit
    }
    out
}

impl Capability {
    #[inline(always)]
    const fn cap_last_cap() -> Self {
        Self::CheckpointRestore
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::borrow::Cow;

    #[test]
    fn test_caps_to_string_empty() {
        let result: Vec<Cow<'static, str>> = caps_to_str_vec(0);
        assert!(result.is_empty());
    }

    #[test]
    fn test_caps_to_string_single_cap() {
        assert_eq!(caps_to_str_vec(1 << 0), vec![Cow::Borrowed("CAP_CHOWN")]);
        assert_eq!(caps_to_str_vec(1 << 5), vec![Cow::Borrowed("CAP_KILL")]);
        assert_eq!(
            caps_to_str_vec(1 << 40),
            vec![Cow::Borrowed("CAP_CHECKPOINT_RESTORE")]
        );
    }

    #[test]
    fn test_caps_to_string_multiple_caps() {
        assert_eq!(
            caps_to_str_vec((1 << 0) | (1 << 1)),
            vec![
                Cow::Borrowed("CAP_CHOWN"),
                Cow::Borrowed("CAP_DAC_OVERRIDE")
            ]
        );
        assert_eq!(
            caps_to_str_vec((1 << 5) | (1 << 6)),
            vec![Cow::Borrowed("CAP_KILL"), Cow::Borrowed("CAP_SETGID")]
        );
    }

    #[test]
    fn test_caps_to_string_all_caps() {
        let mut all_bits = 0u64;
        for i in 0..=40 {
            all_bits |= 1u64 << i;
        }
        let result = caps_to_str_vec(all_bits);
        assert_eq!(result.len(), 41);
        assert_eq!(result[0], Cow::Borrowed("CAP_CHOWN"));
        assert_eq!(result[40], Cow::Borrowed("CAP_CHECKPOINT_RESTORE"));
    }

    #[test]
    fn test_caps_to_string_bits_beyond_last_cap() {
        let bits = (1u64 << 40) | (1u64 << 41);
        assert_eq!(
            caps_to_str_vec(bits),
            vec![Cow::Borrowed("CAP_CHECKPOINT_RESTORE")]
        );
    }

    #[test]
    fn test_caps_to_string_non_contiguous() {
        // Bits 0 (CHOWN), 12 (NET_ADMIN), 21 (SYS_ADMIN), 39 (BPF)
        // Order is deterministic: lowest to highest bit
        let bits = (1u64 << 0) | (1u64 << 12) | (1u64 << 21) | (1u64 << 39);
        assert_eq!(
            caps_to_str_vec(bits),
            vec![
                Cow::Borrowed("CAP_CHOWN"),
                Cow::Borrowed("CAP_NET_ADMIN"),
                Cow::Borrowed("CAP_SYS_ADMIN"),
                Cow::Borrowed("CAP_BPF")
            ]
        );
    }
}
