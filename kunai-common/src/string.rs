use crate::{bpf_target_code, bpf_utils::bound_value_for_verifier, not_bpf_target_code};
use core::mem;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct String<const N: usize> {
    s: [u8; N],
    len: usize,
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
    pub fn as_str(&self) -> &str {
        // all bytes are supposed to be valid utf8 code points
        // verifier does not like reading until self.len
        bpf_target_code!(return unsafe { core::str::from_utf8_unchecked(&(self.s.as_ref())[..]) });
        not_bpf_target_code!(
            // there is currently a bug in bpf_probe_read_[user|kernel]_str_bytes that returns
            // a len containing NULL byte so we attempt to fix that
            let s = unsafe { core::str::from_utf8_unchecked(&(self.s.as_ref())[..self.len]) };
            if s.ends_with(0 as char) && !s.is_empty(){
                return &s[..s.len()-1];
            }
            #[allow(clippy::needless_return)]
            return s;
        );
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

// BPF specific implementation
bpf_target_code! {
    use kunai_macros::BpfError;
    use crate::helpers::{bpf_probe_read_user_str_bytes,bpf_probe_read_kernel_str_bytes};

    #[repr(C)]
    #[derive(BpfError)]
    pub enum Error {
        #[error("bpf probe for read failure")]
        BpfProbeReadFailure,
        #[error("string is full")]
        StringIsFull,
        #[error("reached append limit")]
        AppendLimit,
    }

    impl<const N: usize> String<N>
    {
        #[inline(always)]
        pub unsafe fn read_user_str_bytes<T>(&mut self, src: *const T) -> Result<(),Error> {
            // do not return error if attempting to read null pointer
            if !src.is_null() {
                let s = bpf_probe_read_user_str_bytes(src as *const _, self.s.as_mut()).map_err(|_| Error::BpfProbeReadFailure)?;
                self.len = s.len();
            }
            Ok(())
        }

        /// This function can be used to append reading to the current string. However there is
        /// a limitation so that the verifier does not complain. It can read only up to half the size
        /// of the String. This is because we don't have the size of the string prior to reading it.
        /// Without the string len before bpf_probe_read_kernel_str we cannot upper bound the read limit
        /// efficiently so bpf_probe_read_kernel_str always think upper bound is the String size.
        pub unsafe fn append_kernel_str_bytes<T>(&mut self, src: *const T) -> Result<(),Error> {
            let limit = self.s.len() / 2;

            // do not return error if attempting to read null pointer
            if !src.is_null() {
                let k = self.len;

                if k >= limit {
                    return Err(Error::AppendLimit);
                }

                let dst = self.s[k..limit].as_mut();
                let s = bpf_probe_read_kernel_str_bytes(src as *const _, dst).map_err(|_| Error::BpfProbeReadFailure)?;
                self.len += s.len();
            }
            Ok(())
        }

        #[inline(always)]
        pub unsafe fn read_kernel_str_bytes<T>(&mut self, src: *const T) -> Result<(),Error> {
            // do not return error if attempting to read null pointer
            if !src.is_null() {
                let s = bpf_probe_read_kernel_str_bytes(src as *const _, self.s.as_mut()).map_err(|_| Error::BpfProbeReadFailure)?;
                self.len = s.len();
            }
            Ok(())
        }
    }
}

// Specific code to all other arch than BPF
not_bpf_target_code! {

    use std::borrow::Cow;
    use std::fmt::Display;
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("source string is too big")]
        SourceTooBig,
    }

    impl<const N: usize> TryFrom<std::string::String> for String<N> {
        type Error = Error;

        fn try_from(value: std::string::String) -> Result<Self, Error> {
            let b = value.as_bytes();

            if b.len() > N{
                return Err(Error::SourceTooBig);
            }

            let size = core::cmp::min(b.len(), N);
            let mut out = Self{
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

    impl<const N: usize> String<N>
    {
        pub fn to_string_lossy(&self) -> Cow<str>{
            Cow::from(self.as_str())
        }
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
