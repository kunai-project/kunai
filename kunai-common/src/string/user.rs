use std::borrow::Cow;
use std::fmt::{Display, Write};
use thiserror::Error;

use super::String;

#[derive(Error, Debug)]
pub enum StringError {
    #[error("source string is too big")]
    SourceTooBig,
}

impl<const N: usize> TryFrom<std::string::String> for String<N> {
    type Error = StringError;

    fn try_from(value: std::string::String) -> Result<Self, Self::Error> {
        let b = value.as_bytes();

        if b.len() > N {
            return Err(StringError::SourceTooBig);
        }

        let size = core::cmp::min(b.len(), N);
        let mut out = Self {
            len: b.len(),
            ..Default::default()
        };
        out.s[..size].copy_from_slice(&b[..size]);

        Ok(out)
    }
}

impl<const N: usize> From<String<N>> for std::string::String {
    fn from(value: String<N>) -> Self {
        value.to_string_lossy().into()
    }
}

impl<const N: usize> Display for String<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string_lossy())
    }
}

/// Converts untrusted bytes to text: valid UTF-8 is kept as is and every
/// invalid byte is written as `\xNN`. Backslashes are not escaped, so the
/// conversion cannot always be reversed.
pub fn escape_invalid_utf8(bytes: &[u8]) -> Cow<'_, str> {
    let mut out = std::string::String::new();
    for chunk in bytes.utf8_chunks() {
        if chunk.valid().len() == bytes.len() {
            return Cow::Borrowed(chunk.valid());
        }
        out.push_str(chunk.valid());
        for byte in chunk.invalid() {
            write!(out, "\\x{byte:02x}").expect("writing to a String cannot fail");
        }
    }
    Cow::Owned(out)
}

impl<const N: usize> String<N> {
    pub fn to_string_lossy(&'_ self) -> Cow<'_, str> {
        escape_invalid_utf8(self.as_bytes())
    }

    fn as_bytes(&self) -> &[u8] {
        let bytes = &self.s[..self.len.min(N)];
        // there is currently a bug in bpf_probe_read_[user|kernel]_str_bytes that returns
        // a len containing NULL byte so we attempt to fix that
        bytes.strip_suffix(&[0]).unwrap_or(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::{String, escape_invalid_utf8};

    #[test]
    fn escape_keeps_text_between_invalid_bytes() {
        assert_eq!(escape_invalid_utf8(b"\xfea\xffb"), "\\xfea\\xffb");
    }

    #[test]
    fn escape_empty_input() {
        assert_eq!(escape_invalid_utf8(b""), "");
    }

    fn string<const N: usize>(bytes: &[u8]) -> String<N> {
        let mut s = String::<N>::new();
        s.s[..bytes.len()].copy_from_slice(bytes);
        s.len = bytes.len();
        s
    }

    #[test]
    fn lossy_escapes_invalid_bytes() {
        let s = string::<16>(b"opt=\xff");
        assert_eq!(s.to_string_lossy(), "opt=\\xff");
    }

    #[test]
    fn lossy_escapes_truncated_multibyte() {
        // "é" is 0xc3 0xa9, a bounded probe read can stop in the middle
        let s = string::<16>(b"caf\xc3");
        assert_eq!(s.to_string_lossy(), "caf\\xc3");
    }

    #[test]
    fn lossy_keeps_valid_non_ascii() {
        let s = string::<16>("café".as_bytes());
        assert_eq!(s.to_string_lossy(), "café");
    }

    #[test]
    fn lossy_keeps_backslashes() {
        let s = string::<16>(b"a\\xff");
        assert_eq!(s.to_string_lossy(), "a\\xff");
    }

    #[test]
    fn lossy_trims_trailing_nul() {
        let s = string::<16>(b"opt=1\0");
        assert_eq!(s.to_string_lossy(), "opt=1");
    }

    #[test]
    fn lossy_trims_nul_after_invalid_bytes() {
        let s = string::<16>(b"opt=\xff\0");
        assert_eq!(s.to_string_lossy(), "opt=\\xff");
    }

    #[test]
    fn lossy_reads_full_buffer_without_nul() {
        let s = string::<4>(b"abcd");
        assert_eq!(s.to_string_lossy(), "abcd");
    }

    #[test]
    fn lossy_clamps_len_to_capacity() {
        let mut s = string::<4>(b"abcd");
        s.len = 32;
        assert_eq!(s.to_string_lossy(), "abcd");
    }

    #[test]
    fn into_std_string_escapes_invalid_bytes() {
        let s: std::string::String = string::<16>(b"opt=\xff").into();
        assert_eq!(s, "opt=\\xff");
    }
}
