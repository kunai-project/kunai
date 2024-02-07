use crate::utils::cstr_to_string;

use super::Buffer;

impl<const N: usize> Buffer<N> {
    pub fn to_command_line(&self) -> String {
        self.to_argv().join(" ")
    }

    pub fn to_argv(&self) -> Vec<String> {
        self.as_slice()
            .split(|&b| b == b'\0')
            .map(cstr_to_string)
            .filter(|s| !s.is_empty())
            .collect()
    }
}