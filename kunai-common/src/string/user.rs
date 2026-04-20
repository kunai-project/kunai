use std::borrow::Cow;
use std::fmt::Display;
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

impl<const N: usize> String<N> {
    pub fn to_string_lossy(&'_ self) -> Cow<'_, str> {
        Cow::from(self.as_str())
    }

    #[inline(always)]
    pub fn as_str(&self) -> &str {
        // String API guarantee that characters are valid UTF8 chars
        let s = {
            #[cfg(not(debug_assertions))]
            unsafe {
                core::str::from_utf8_unchecked(&self.s[..self.len])
            }
            #[cfg(debug_assertions)]
            core::str::from_utf8(&self.s[..self.len]).expect("string should have only valid utf8 char")
        };
        // there is currently a bug in bpf_probe_read_[user|kernel]_str_bytes that returns
        // a len containing NULL byte so we attempt to fix that
        if s.ends_with(0 as char) && !s.is_empty() {
            return &s[..s.len() - 1];
        }
        s
    }
}
