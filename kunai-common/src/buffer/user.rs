use super::Buffer;
use crate::string::escape_invalid_utf8;

impl<const N: usize> Buffer<N> {
    /// Returns the NUL separated arguments, with invalid UTF-8 bytes escaped.
    #[inline]
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec![];

        for token in self.as_slice().split(|&b| b == b'\0') {
            if token.is_empty() {
                continue;
            }

            let s = escape_invalid_utf8(token);
            if s.chars().any(|c| c.is_whitespace()) {
                // we wrap strings containg space between double quotes
                // but we also need to replace double quotes by escaped double quotes
                argv.push(format!(r#""{}""#, s.replace(r#"""#, r#"\""#)));
            } else {
                argv.push(s.into_owned());
            }
        }

        argv
    }
}

#[cfg(test)]
mod tests {
    use super::Buffer;

    fn buffer(bytes: &[u8]) -> Buffer<64> {
        let mut b = Buffer::<64>::new();
        b.buf[..bytes.len()].copy_from_slice(bytes);
        b.len = bytes.len();
        b
    }

    #[test]
    fn to_argv_keeps_invalid_tokens() {
        let argv = buffer(b"cp\0/bin/true\0/tmp/kunai_bad_\xff\0").to_argv();
        assert_eq!(argv, ["cp", "/bin/true", "/tmp/kunai_bad_\\xff"]);
    }

    #[test]
    fn to_argv_quotes_invalid_tokens_with_whitespace() {
        // an invalid byte in a shell comment must not hide the whole script
        let argv = buffer(b"sh\0-c\0id # \xff\0").to_argv();
        assert_eq!(argv, ["sh", "-c", "\"id # \\xff\""]);
    }

    #[test]
    fn to_argv_keeps_truncated_last_token() {
        let argv = buffer(b"echo\0caf\xc3").to_argv();
        assert_eq!(argv, ["echo", "caf\\xc3"]);
    }
}
