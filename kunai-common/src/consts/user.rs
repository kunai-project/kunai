use super::Capability;
use std::borrow::Cow;
use std::sync::LazyLock;

pub static CAP_LAST_CAP: LazyLock<u64> = LazyLock::new(|| {
    std::fs::read_to_string("/proc/sys/kernel/cap_last_cap")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        // ref: https://elixir.bootlin.com/linux/v7.1.7/source/include/uapi/linux/capability.h#L423
        .unwrap_or(Capability::CheckpointRestore as u64) // fallback: highest known cap at time of writing
});

/// Iterates over all set bits in a u64 bitmask.
#[inline]
pub fn caps_to_str_vec(mut bits: u64) -> Vec<Cow<'static, str>> {
    let mut out = Vec::new();

    if bits == Capability::cap_full_set() {
        out.push(Cow::Borrowed("CAP_FULL_SET"));
        return out;
    }

    while bits != 0 {
        let bit = bits.trailing_zeros();
        if bit > *CAP_LAST_CAP as u32 {
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
    // ref: https://elixir.bootlin.com/linux/v7.1.7/source/include/linux/capability.h#L67
    fn cap_full_set() -> u64 {
        (1 << (1 + *CAP_LAST_CAP)) - 1
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
    fn test_caps_to_string_all_known_caps() {
        // deliberately go up to (not through) CAP_LAST_CAP, so this bitmask can
        // never equal Capability::cap_full_set() and always exercises the
        // per-capability enumeration path, whatever the live kernel's
        // /proc/sys/kernel/cap_last_cap happens to be.
        let last = *CAP_LAST_CAP as u32;
        let mut all_bits = 0u64;
        for i in 0..last {
            all_bits |= 1u64 << i;
        }
        let result = caps_to_str_vec(all_bits);
        assert_eq!(result.len(), last as usize);
        assert_eq!(result[0], Cow::Borrowed("CAP_CHOWN"));
    }

    #[test]
    fn test_caps_to_string_full_set_shortcut() {
        assert_eq!(
            caps_to_str_vec(Capability::cap_full_set()),
            vec![Cow::Borrowed("CAP_FULL_SET")]
        );
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
