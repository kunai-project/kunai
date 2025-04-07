use core::str::{self, Utf8Error};

use super::Buffer;

impl<const N: usize> Buffer<N> {
    /// Returns a tuple made of the argv and an optional last decoding error.
    #[inline]
    pub fn to_argv(&self) -> (Vec<String>, Option<Utf8Error>) {
        let mut last_err = None;
        let mut argv = vec![];

        for s in self.as_slice().split(|&b| b == b'\0') {
            let s = match str::from_utf8(s) {
                Ok(s) => {
                    if s.is_empty() {
                        continue;
                    }

                    if s.chars().any(|c| c.is_whitespace()) {
                        // we wrap strings containg space between double quotes
                        // but we also need to replace double quotes by escaped double quotes
                        &format!(r#""{}""#, s.replace(r#"""#, r#"\""#))
                    } else {
                        s
                    }
                }
                Err(e) => {
                    let _ = last_err.insert(e);
                    continue;
                }
            };

            argv.push(s.to_string());
        }

        (argv, last_err)
    }
}
