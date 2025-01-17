use core::cmp::min;

use super::{Error, Mode, Path};

use {core::fmt::Display, std::path};

impl std::error::Error for Error {
    fn cause(&self) -> Option<&dyn std::error::Error> {
        None
    }

    fn description(&self) -> &str {
        self.description()
    }

    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl From<Path> for path::PathBuf {
    fn from(value: Path) -> Self {
        // Path is supposed to hold valid utf8 characters controlled by the kernel
        let p = unsafe { core::str::from_utf8_unchecked(value.as_slice()) };
        path::PathBuf::from(p)
    }
}

impl TryFrom<path::PathBuf> for Path {
    type Error = Error;
    fn try_from(value: path::PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(&value)
    }
}

impl TryFrom<&path::PathBuf> for Path {
    type Error = Error;

    fn try_from(value: &path::PathBuf) -> Result<Self, Self::Error> {
        let mut out = Self::default();
        let path_buf_len = value.to_string_lossy().len();

        if path_buf_len > out.buffer.len() {
            return Err(Error::FilePathTooLong);
        }

        let len = min(path_buf_len, out.buffer.len());

        out.buffer[..len]
            .as_mut()
            .copy_from_slice(&value.to_string_lossy().as_bytes()[..len]);

        out.mode = Mode::Append;
        out.len = len as u32;

        Ok(out)
    }
}

impl Display for Path {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_path_buf().to_string_lossy())
    }
}

impl Path {
    pub fn try_from_realpath<T: AsRef<path::Path>>(p: T) -> Result<Self, Error> {
        let mut p = Self::try_from(p.as_ref().to_path_buf())?;
        p.real = true;
        Ok(p)
    }

    pub fn to_path_buf(self) -> path::PathBuf {
        self.into()
    }
}
