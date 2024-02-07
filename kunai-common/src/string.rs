use crate::{
    errors::ProbeError, macros::bpf_target_code, macros::not_bpf_target_code,
    utils::bound_value_for_verifier,
};
use core::mem;
use kunai_macros::BpfError;

not_bpf_target_code! {
    mod user;
    pub use user::*;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

#[repr(C)]
#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("bpf probe for read failure")]
    BpfProbeReadFailure,
    #[error("string is full")]
    StringIsFull,
    #[error("reached append limit")]
    AppendLimit,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        ProbeError::StringError(value)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct String<const N: usize> {
    pub s: [u8; N],
    pub len: usize,
}

impl<const N: usize> Default for String<N> {
    fn default() -> Self {
        String { s: [0; N], len: 0 }
    }
}

pub const fn concat_static<const N: usize>(st1: &'static str, st2: &'static str) -> String<N> {
    let mut i = 0;
    let st1_bytes = st1.as_bytes();
    let st2_bytes = st2.as_bytes();
    let mut s = String { s: [0; N], len: 0 };

    let mut j = 0;
    loop {
        if i == s.cap() || j == st1.len() {
            break;
        }
        s.s[i] = st1_bytes[j];
        s.len += 1;
        i += 1;
        j += 1;
    }

    j = 0;
    loop {
        if i == s.cap() || j == st2.len() {
            break;
        }
        s.s[i] = st2_bytes[j];
        s.len += 1;
        i += 1;
        j += 1;
    }
    s
}

pub const fn from_static<const N: usize>(st: &'static str) -> String<N> {
    let mut s = String { s: [0; N], len: 0 };
    let mut i = 0;
    let bytes = st.as_bytes();

    assert!(st.len() < N, "source string is too big");

    loop {
        // we leave a 0 to terminate the string if string
        // larger than capacity
        if i == s.cap() - 1 || i == st.len() {
            break;
        }
        s.s[i] = bytes[i];
        s.len += 1;
        i += 1
    }
    s
}

impl<const N: usize> String<N> {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            ..Default::default()
        }
    }

    #[inline(always)]
    fn push_byte_at(&mut self, b: u8, at: usize) {
        if self.is_full() {
            return;
        }
        let k = bound_value_for_verifier(at as isize, 0, (self.cap() - 1) as isize);
        self.s.as_mut()[k as usize] = b;
        self.len += 1;
    }

    #[inline(always)]
    pub fn push_byte(&mut self, b: u8) {
        self.push_byte_at(b, self.len)
    }

    #[inline(always)]
    pub fn push_bytes_unchecked<U: AsRef<[u8]>>(&mut self, s: U) {
        let src = s.as_ref();

        for i in 0..self.cap() {
            if self.is_full() || i == src.len() {
                return;
            }
            self.push_byte(src[i]);
        }
    }

    pub fn copy_from(&mut self, other: &Self) {
        unsafe { core::ptr::copy_nonoverlapping(other as *const _, self as *mut _, 1) }
    }

    #[inline(always)]
    pub fn join<U: Sized + AsRef<[u8]>>(&mut self, s1: U, sep: u8, s2: U) {
        let mut bytes = s1.as_ref();
        let mut i = 0;
        let mut flag_second_slice = false;

        for j in 0..self.cap() {
            if i == bytes.len() && !flag_second_slice {
                i = 0;
                bytes = s2.as_ref();
                self.push_byte_at(sep, j);
                flag_second_slice = true;
                continue;
            }

            if self.is_full() || (flag_second_slice && i == bytes.len()) {
                return;
            }

            self.push_byte_at(bytes[i], j);
            i += 1
        }
    }

    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.len() == self.cap() - 1
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub const fn cap(&self) -> usize {
        N
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.s = unsafe { mem::zeroed() };
        self.len = 0;
    }
}

#[cfg(test)]
mod test {

    use super::*;
    #[test]
    fn test_sized() {
        let mut s: String<256> = String::new();
        s.push_bytes_unchecked("test");
        assert_eq!(s.len(), 4);
        assert_eq!(s.cap(), 256);
        assert_eq!(s.as_str(), "test");
        s.reset();
        assert_eq!(s.len(), 0);
        assert_eq!(s.cap(), 256);
        s.join("test", b' ', "toast");
        assert_eq!(s.as_str(), "test toast");
    }

    #[test]
    fn test_overflow() {
        let mut s: String<6> = String::new();
        assert_eq!(s.len(), 0);
        assert_eq!(s.cap(), 6);
        s.join("toaster", b' ', "is nice");
        assert_eq!(s.as_str(), "toast");

        s.reset();
        s.join("h", b' ', "world");
        assert_eq!(s.as_str(), "h wor");

        s.reset();
        s.join("hello", b' ', "world");
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn test_const_vstring() {
        let s = from_static::<42>("hello world");
        assert_eq!(s.as_str(), "hello world");
        assert_eq!(s.to_string_lossy(), "hello world");
        assert_eq!(s.to_string_lossy().to_string(), "hello world");
    }
}
