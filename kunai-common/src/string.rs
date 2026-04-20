use crate::errors::ProbeError;
use kunai_macros::BpfError;

#[cfg(feature = "user")]
mod user;
#[cfg(feature = "user")]
pub use user::*;

#[cfg(target_arch = "bpf")]
mod bpf;

// https://tools.ietf.org/html/rfc3629
const UTF8_CHAR_WIDTH: &[u8; 256] = &[
    // 1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 0
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 1
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 2
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 3
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 4
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 5
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 6
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 7
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 8
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 9
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // A
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // B
    0, 0, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // C
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, // D
    3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, // E
    4, 4, 4, 4, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // F
];

#[inline(always)]
const fn utf8_char_width(b: u8) -> usize {
    UTF8_CHAR_WIDTH[b as usize] as usize
}

#[inline(always)]
const fn decode_utf8(array: [u8; 4]) -> Option<char> {
    let char_len = utf8_char_width(array[0]);

    // Decode the code point
    let code_point = match char_len {
        1 => array[0] as u32,
        2 => (array[0] as u32 & 0b00011111) << 6 | (array[1] as u32 & 0b00111111),
        3 => {
            (array[0] as u32 & 0b00001111) << 12
                | (array[1] as u32 & 0b00111111) << 6
                | (array[2] as u32 & 0b00111111)
        }
        4 => {
            (array[0] as u32 & 0b00000111) << 18
                | (array[1] as u32 & 0b00111111) << 12
                | (array[2] as u32 & 0b00111111) << 6
                | (array[3] as u32 & 0b00111111)
        }
        _ => unreachable!(),
    };

    core::char::from_u32(code_point)
}

/// Encodes a char into UTF-8 bytes, returning a 4-byte buffer.
/// The actual UTF-8 length is determined by the character's code point.
/// Unused bytes in the buffer will be zero.
#[inline(always)]
const fn encode_utf8(c: char) -> [u8; 4] {
    let code = c as u32;
    let mut buf = [0u8; 4];

    match code {
        0x0000..=0x007F => {
            buf[0] = code as u8;
        }
        0x0080..=0x07FF => {
            buf[0] = 0b11000000 | ((code >> 6) as u8);
            buf[1] = 0b10000000 | ((code & 0b00111111) as u8);
        }
        0x0800..=0xFFFF => {
            buf[0] = 0b11100000 | ((code >> 12) as u8);
            buf[1] = 0b10000000 | ((code >> 6) as u8 & 0b00111111);
            buf[2] = 0b10000000 | ((code & 0b00111111) as u8);
        }
        0x10000..=0x10FFFF => {
            buf[0] = 0b11110000 | ((code >> 18) as u8);
            buf[1] = 0b10000000 | ((code >> 12) as u8 & 0b00111111);
            buf[2] = 0b10000000 | ((code >> 6) as u8 & 0b00111111);
            buf[3] = 0b10000000 | ((code & 0b00111111) as u8);
        }
        _ => unreachable!(),
    }

    buf
}

pub struct CharsIterator<'s> {
    s: &'s str,
    i: usize,
    char_count: usize,
}

impl<'s> CharsIterator<'s> {
    pub const fn from_str(s: &'s str) -> Self {
        CharsIterator {
            s,
            i: 0,
            char_count: 0,
        }
    }

    pub const fn next_char(&mut self) -> Option<char> {
        match self.peek_char() {
            Some(c) => {
                self.i += c.len_utf8();
                self.char_count += 1;
                Some(c)
            }
            None => None,
        }
    }

    pub const fn is_done(&self) -> bool {
        self.i == self.s.len()
    }

    pub const fn peek_char(&mut self) -> Option<char> {
        if self.i >= self.s.len() {
            return None;
        }

        let bytes = self.s.as_bytes();
        let mut buf = [0u8; 4];
        let n = utf8_char_width(bytes[self.i]);
        let mut k = 0;

        while k < n {
            buf[k] = bytes[self.i + k];
            k += 1;
        }

        decode_utf8(buf)
    }

    pub const fn chars_until(&mut self, needle: &str) -> Option<usize> {
        while let Some(c) = self.next_char() {
            let mut nit = CharsIterator::from_str(needle);
            let first_char = match nit.next_char() {
                Some(c) => c,
                None => return None,
            };

            if c == first_char {
                self.skip(1);
                nit.skip(1);

                while let Some(c) = self.peek_char() {
                    let Some(n) = nit.peek_char() else { break };
                    if c != n {
                        break;
                    }
                    self.skip(1);
                    nit.skip(1);
                }

                if nit.is_done() {
                    return Some(self.char_count - nit.char_count);
                }
            }
        }

        None
    }

    pub const fn chars_until_last(&mut self, needle: &str) -> Option<usize> {
        let mut count = None;
        while let Some(n) = self.chars_until(needle) {
            count = Some(n)
        }
        count
    }

    #[inline(always)]
    pub const fn skip(&mut self, mut n: usize) {
        while n > 0 {
            if self.next_char().is_none() {
                return;
            }
            n -= 1
        }
    }

    #[inline(always)]
    pub const fn reset(&mut self) {
        self.i = 0;
        self.char_count = 0
    }
}

#[repr(C)]
#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("bpf probe for read failure")]
    BpfProbeReadFailure,
    #[error("insufficient space")]
    InsufficientSpace,
    #[error("reached append limit")]
    AppendLimit,
    #[error("index out of bounds")]
    OutOfBounds,
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
        String::new()
    }
}

pub const fn from_str_fitting<const N: usize>(st: &'static str) -> String<N> {
    let mut s = String::new();
    let mut it = CharsIterator::from_str(st);

    while let Some(c) = it.next_char() {
        if s.push_char(c).is_err() {
            break;
        }
    }
    s
}

impl<const N: usize> String<N> {
    #[inline(always)]
    pub const fn new() -> Self {
        String { s: [0; N], len: 0 }
    }

    #[inline(always)]
    pub const fn push_char(&mut self, c: char) -> Result<(), Error> {
        if self.remaining() < c.len_utf8() {
            return Err(Error::InsufficientSpace);
        }

        if c.is_ascii() {
            let _ = self.push_byte(c as u8);
            return Ok(());
        }

        let mut i = 0;
        let buf = encode_utf8(c);

        // Note: this makes the loop more eBPF friendly
        while i < 4 {
            if i == c.len_utf8() {
                break;
            }
            // we have checked that we can copy all bytes
            let _ = self.push_byte(buf[i]);
            i += 1
        }

        Ok(())
    }

    #[inline(always)]
    const fn push_byte(&mut self, b: u8) -> Result<(), Error> {
        if self.is_full() {
            return Err(Error::InsufficientSpace);
        }

        if self.len < N {
            self.s[self.len] = b;
            self.len += 1;
        } else {
            return Err(Error::OutOfBounds);
        }

        Ok(())
    }

    pub const fn clone_from(&mut self, other: &Self) {
        self.s = other.s;
        self.len = other.len;
    }

    #[inline(always)]
    pub const fn is_full(&self) -> bool {
        self.len() == self.cap()
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub const fn remaining(&self) -> usize {
        N - self.len
    }

    #[inline(always)]
    pub const fn cap(&self) -> usize {
        N
    }

    #[inline(always)]
    #[allow(dead_code)]
    pub(crate) fn reset(&mut self) {
        self.s = [0; N];
        self.len = 0;
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // --- from_str_fitting tests ---

    #[test]
    fn test_from_str_fitting_exact_fit() {
        let s = from_str_fitting::<5>("hello");
        assert_eq!(s.len(), 5);
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn test_from_str_fitting_truncates() {
        let s = from_str_fitting::<5>("hello world");
        assert_eq!(s.len(), 5);
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn test_from_str_fitting_empty() {
        let s = from_str_fitting::<10>("");
        assert_eq!(s.len(), 0);
        assert!(s.is_empty());
    }

    #[test]
    fn test_from_str_fitting_utf8_multi_byte() {
        // Only fits "caf" (3 bytes) if N=3
        let s = from_str_fitting::<3>("café");
        assert_eq!(s.len(), 3);
        assert_eq!(s.as_str(), "caf");

        // "café" is 5 bytes: c(1) a(1) f(1) é(2)
        let s = from_str_fitting::<5>("café");
        assert_eq!(s.len(), 5);
        assert_eq!(s.as_str(), "café");
    }

    #[test]
    fn test_from_str_fitting_zero_capacity() {
        let s = from_str_fitting::<0>("hello");
        assert_eq!(s.len(), 0);
        assert!(s.is_full());
    }

    // --- push_byte tests ---

    #[test]
    fn test_push_byte_success() {
        let mut s: String<10> = String::new();
        assert!(s.push_byte(b'a').is_ok());
        assert_eq!(s.len(), 1);
        assert_eq!(s.as_str(), "a");
    }

    #[test]
    fn test_push_byte_fills_completely() {
        let mut s: String<3> = String::new();
        assert!(s.push_byte(b'a').is_ok());
        assert!(s.push_byte(b'b').is_ok());
        assert!(s.push_byte(b'c').is_ok());
        assert!(s.is_full());
        assert!(matches!(s.push_byte(b'b'), Err(Error::InsufficientSpace)));
        assert_eq!(s.as_str(), "abc");
    }

    // --- copy_from tests ---

    #[test]
    fn test_copy_from() {
        let s1: String<10> = from_str_fitting("hello");

        let mut s2: String<10> = String::new();
        s2.clone_from(&s1);

        assert_eq!(s2.len(), 5);
        assert_eq!(s2.as_str(), "hello");
    }

    // --- Property tests ---

    #[test]
    fn test_sized() {
        let mut s: String<256> = from_str_fitting("test");
        assert_eq!(s.len(), 4);
        assert_eq!(s.cap(), 256);
        assert_eq!(s.as_str(), "test");
        s.reset();
        assert_eq!(s.len(), 0);
        assert_eq!(s.cap(), 256);
    }

    #[test]
    fn test_const_vstring() {
        let s = from_str_fitting::<42>("hello world");
        assert_eq!(s.len(), 11);
        assert_eq!(s.as_str(), "hello world");
        assert_eq!(s.to_string_lossy(), "hello world");
    }

    #[test]
    fn test_remaining() {
        let mut s: String<10> = String::new();
        assert_eq!(s.remaining(), 10);
        assert!(s.push_byte(b'a').is_ok());
        assert_eq!(s.remaining(), 9);
        assert!(s.push_char('b').is_ok());
        assert!(s.push_char('c').is_ok());
        assert_eq!(s.remaining(), 7);
    }

    #[test]
    fn test_is_full_and_is_empty() {
        let mut s: String<3> = String::new();
        assert!(s.is_empty());
        assert!(!s.is_full());

        assert!(s.push_byte(b'a').is_ok());
        assert!(!s.is_empty());
        assert!(!s.is_full());

        assert!(s.push_byte(b'b').is_ok());
        assert!(s.push_byte(b'c').is_ok());
        assert!(!s.is_empty());
        assert!(s.is_full());
    }

    #[test]
    fn test_len_and_cap() {
        let s: String<100> = String::new();
        assert_eq!(s.len(), 0);
        assert_eq!(s.cap(), 100);
    }

    #[test]
    fn test_error_conversion() {
        let err = Error::InsufficientSpace;
        let probe_err: ProbeError = err.into();
        assert!(matches!(
            probe_err,
            ProbeError::StringError(Error::InsufficientSpace)
        ));
    }

    // --- Edge cases ---

    #[test]
    fn test_utf8_char_width() {
        // ASCII
        assert_eq!(utf8_char_width(b'a'), 1);
        // Continuation byte (invalid as first byte)
        assert_eq!(utf8_char_width(0x80), 0);
        // 2-byte character start
        assert_eq!(utf8_char_width(0xC2), 2);
        // 3-byte character start
        assert_eq!(utf8_char_width(0xE2), 3);
        // 4-byte character start
        assert_eq!(utf8_char_width(0xF0), 4);
    }

    #[test]
    fn test_from_str_fitting_utf8_boundary() {
        // "a" (1 byte) + "€" (3 bytes) = 4 bytes total
        // With N=3, only "a" should fit (1 byte), not enough for "€" (3 bytes)
        let s = from_str_fitting::<3>("a€");
        assert_eq!(s.len(), 1);
        assert_eq!(s.as_str(), "a");
    }

    #[test]
    fn test_default() {
        let s: String<10> = String::default();
        assert_eq!(s.len(), 0);
        assert_eq!(s.cap(), 10);
    }

    // --- CharIterator tests ---

    #[test]
    fn test_char_iterator_empty() {
        let mut iter = CharsIterator::from_str("");
        assert!(iter.next_char().is_none());
    }

    #[test]
    fn test_char_iterator_ascii_single() {
        let mut iter = CharsIterator::from_str("a");
        assert_eq!(iter.next_char(), Some('a'));
        assert!(iter.next_char().is_none());
    }

    #[test]
    fn test_char_iterator_ascii_multiple() {
        let mut iter = CharsIterator::from_str("abc");
        assert_eq!(iter.next_char(), Some('a'));
        assert_eq!(iter.next_char(), Some('b'));
        assert_eq!(iter.next_char(), Some('c'));
        assert!(iter.next_char().is_none());
    }

    #[test]
    fn test_char_iterator_utf8_multi_byte() {
        // "café" = 'c', 'a', 'f', 'é' (U+00E9)
        let mut iter = CharsIterator::from_str("café");
        assert_eq!(iter.next_char(), Some('c'));
        assert_eq!(iter.next_char(), Some('a'));
        assert_eq!(iter.next_char(), Some('f'));
        assert_eq!(iter.next_char(), Some('é'));
        assert!(iter.next_char().is_none());
    }

    #[test]
    fn test_char_iterator_utf8_emoji() {
        // "a🎉b" - emoji is 4 bytes
        let mut iter = CharsIterator::from_str("a🎉b");
        assert_eq!(iter.next_char(), Some('a'));
        assert_eq!(iter.next_char(), Some('🎉'));
        assert_eq!(iter.next_char(), Some('b'));
        assert!(iter.next_char().is_none());
    }

    #[test]
    fn test_char_iterator_exhaustive() {
        let s = "Hello, 世界! ";
        let mut iter = CharsIterator::from_str(s);
        let expected: Vec<char> = s.chars().collect();
        for c in &expected {
            assert_eq!(iter.next_char(), Some(*c));
        }
        assert!(iter.next_char().is_none());
    }

    // --- chars_until tests ---

    #[test]
    fn test_chars_until_match_start() {
        let mut iter = CharsIterator::from_str("hello world");
        assert_eq!(iter.chars_until("hello"), Some(0));
    }

    #[test]
    fn test_chars_until_match_middle() {
        let mut iter = CharsIterator::from_str("hello world");
        assert_eq!(iter.chars_until("world"), Some(6));
    }

    #[test]
    fn test_chars_until_no_match() {
        let mut iter = CharsIterator::from_str("hello world");
        assert_eq!(iter.chars_until("foo"), None);
    }

    #[test]
    fn test_chars_until_empty_needle() {
        let mut iter = CharsIterator::from_str("hello");
        assert_eq!(iter.chars_until(""), None);
    }

    #[test]
    fn test_chars_until_needle_longer() {
        let mut iter = CharsIterator::from_str("hi");
        assert_eq!(iter.chars_until("hello"), None);
    }

    #[test]
    fn test_chars_until_utf8_single_char() {
        // "é" is one character at index 3
        let mut iter = CharsIterator::from_str("café");
        assert_eq!(iter.chars_until("é"), Some(3));
    }

    #[test]
    fn test_chars_until_utf8_multi_char() {
        // "世界" is two characters at indices 6-7 in "hello 世界 world"
        let mut iter = CharsIterator::from_str("hello 世界 world");
        assert_eq!(iter.chars_until("世界"), Some(6));
    }

    #[test]
    fn test_chars_until_consumes_iterator() {
        let mut iter = CharsIterator::from_str("abcdef");
        assert_eq!(iter.chars_until("cde"), Some(2));
        // After finding "cde" (chars 2-4), next char should be 'f' (char 5)
        assert_eq!(iter.next_char(), Some('f'));
    }

    #[test]
    fn test_chars_until_returns_char_position() {
        // Verifies it returns character count, not byte position
        // "café" - 'é' is 2 bytes but is 1 character (index 3)
        let mut iter = CharsIterator::from_str("café");
        assert_eq!(iter.chars_until("é"), Some(3));
    }

    #[test]
    fn test_chars_until_partial_no_match() {
        let mut iter = CharsIterator::from_str("hellow");
        // "hello" is 5 chars
        assert_eq!(iter.chars_until("hello"), Some(0));
        assert_eq!(iter.chars_until("orld"), None); // not "world"
    }

    // --- chars_until_last tests ---

    #[test]
    fn test_chars_until_last_single_occurrence() {
        let mut iter = CharsIterator::from_str("hello world");
        assert_eq!(iter.chars_until_last("world"), Some(6));
    }

    #[test]
    fn test_chars_until_last_multiple_occurrences() {
        let mut iter = CharsIterator::from_str("ababab");
        assert_eq!(iter.chars_until_last("ab"), Some(4));
        // Occurrences at 0, 2, 4 - last is 4
    }

    #[test]
    fn test_chars_until_last_no_match() {
        let mut iter = CharsIterator::from_str("hello world");
        assert_eq!(iter.chars_until_last("foo"), None);
    }

    #[test]
    fn test_chars_until_last_empty_needle() {
        let mut iter = CharsIterator::from_str("hello");
        assert_eq!(iter.chars_until_last(""), None);
    }

    #[test]
    fn test_chars_until_last_needle_at_end() {
        let mut iter = CharsIterator::from_str("hello world");
        assert_eq!(iter.chars_until_last("world"), Some(6));
    }

    #[test]
    fn test_chars_until_last_utf8() {
        let mut iter = CharsIterator::from_str("é é é");
        assert_eq!(iter.chars_until_last("é"), Some(4));
        // Positions: 0, 2, 4 (each 'é ' is 2 chars: é + space)
        // Last 'é' is at char position 4
    }

    #[test]
    fn test_chars_until_last_consumes_iterator() {
        let mut iter = CharsIterator::from_str("ababab");
        let last = iter.chars_until_last("ab");
        assert_eq!(last, Some(4));
        // Iterator should be at end after finding all occurrences
        assert!(iter.next_char().is_none());
    }

    #[test]
    fn test_chars_until_last_adjacent_matches() {
        let mut iter = CharsIterator::from_str("aaa");
        assert_eq!(iter.chars_until_last("aa"), Some(1));
        // Finds "aa" at char 0-1, returns position 0
        // Next iteration: only char 2 ('a') left, no match
        // Returns last found position: 0
    }

    #[test]
    fn test_chars_until_last_overlapping_matches() {
        // Non-overlapping matches only (skip advances past match)
        let mut iter = CharsIterator::from_str("ababab");
        assert_eq!(iter.chars_until_last("ab"), Some(4));
        // Finds at 0, 2, 4 - returns 4
    }
}
