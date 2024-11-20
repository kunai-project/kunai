use core::str;

use super::Buffer;

impl<const N: usize> Buffer<N> {
    #[inline]
    pub fn to_command_line(&self) -> String {
        self.to_argv().join(" ")
    }

    #[inline]
    pub fn to_argv(&self) -> Vec<String> {
        self.as_slice()
            .split(|&b| b == b'\0')
            // this must not panic as we are sure to have utf8 from kernel
            .map(|s| str::from_utf8(s).unwrap().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.chars().any(|c| c.is_whitespace()) {
                    // we wrap strings containg space between double quotes
                    // but we also need to replace double quotes by escaped double quotes
                    format!(r#""{}""#, s.replace(r#"""#, r#"\""#))
                } else {
                    s
                }
            })
            .collect()
    }
}
