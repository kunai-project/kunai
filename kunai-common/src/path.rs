use crate::{errors::ProbeError, macros::bpf_target_code, macros::not_bpf_target_code};

use super::time::Time;

use kunai_macros::BpfError;

#[allow(unused_imports)]
use core::{cmp::min, ffi::c_long};

not_bpf_target_code! {
    mod user;
}

bpf_target_code! {
    mod bpf;
}

// for path resolution
pub const MAX_PATH_DEPTH: u16 = 128;
// in theory MAX_PATH_LEN is 4096, however (considering the
// TM where someones wants to fool path resolution) path resolution can
// be exhausted by making a path depth > 128 so it is not so
// relevant to use 4096 as MAX_PATH_LEN (as it does not prevent
// anything to be bypassed). However, making a smaller PATH_LEN makes
// the program less memory consuming. Maybe a path exhaustion event should
// be raised when limits are reached.
pub const MAX_PATH_LEN: usize = 1024;
pub const MAX_NAME: usize = u8::MAX as usize;

#[repr(C)]
#[derive(BpfError, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("filename is too long")]
    FileNameTooLong,
    #[error("filepath is too long")]
    FilePathTooLong,
    #[error("max path depth has been reached")]
    ReachedMaxPathDepth,
    #[error("failed to read path segment")]
    RFPathSegment,
    #[error("bpf probe read failed")]
    BpfProbeReadFailure,
    #[error("path is truncated")]
    TruncPath,
    #[error("mount.mnt member is missing in btf info")]
    MissingMountMnt,
    #[error("failed to read field path.mnt")]
    RFPathMnt,
    #[error("failed to read mount ptr")]
    RFMountPtr,
    #[error("failed to read mount.mnt_parent")]
    RFMntParent,
    #[error("failed to read mnt_root")]
    RFMntRoot,
    #[error("failed to read dentry")]
    RFDentry,
    #[error("failed to read mnt_mountpoint")]
    RFMntMountpoint,
    #[error("failed to read dentry.d_parent")]
    RFDparent,
    #[error("failed to read dentry.d_name")]
    RFDName,
    #[error("mnt_parent field missing")]
    MntParentMissing,
    #[error("mnt_root field missing")]
    MntRootMissing,
    #[error("mnt_mountpoint field missing")]
    MntMountpointMissing,
    #[error("d_parent field missing")]
    DParentMissing,
    #[error("f_path field missing")]
    FPathMissing,
    #[error("dentry field missing")]
    DentryMissing,
    #[error("d_name.name field missing")]
    DNameNameMissing,
    #[error("d_name.len field missing")]
    DNameLenMissing,
    #[error("d_name.hash_len field missing")]
    DNameHashLenMissing,
    #[error("failed to get path ino")]
    PathInoFailure,
    #[error("failed to get path sb ino")]
    PathSbInoFailure,
    #[error("failed to read dentry.d_inode")]
    DentryDinode,
    #[error("failed to read dentry atime")]
    DentryAtime,
    #[error("failed to read dentry ctime")]
    DentryCtime,
    #[error("failed to read dentry mtime")]
    DentryMtime,
    #[error("failed to read inode.i_size")]
    InodeIsize,
    #[error("out of bound")]
    OutOfBound,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::PathError(value)
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Append,
    Prepend,
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    // inode number of the file
    pub ino: u64,
    // inode number of superblock
    pub sb_ino: u64,
    pub size: i64,
    pub atime: Time,
    pub mtime: Time,
    pub ctime: Time,
}

#[allow(dead_code)]
#[repr(C)]
#[derive(Default, Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct MapKey {
    hash: u64,
    // depth is a u32 to force structure alignment
    // without this kernel 5.4 fails at using this
    // struct on the eBPF stack
    depth: u32,
    len: u32,
    ino: u64,
    sb_ino: u64,
}

impl From<&Path> for MapKey {
    #[inline(always)]
    fn from(p: &Path) -> Self {
        let meta = p.metadata.unwrap_or_default();
        MapKey {
            hash: p.hash,
            depth: p.depth as u32,
            len: p.len,
            ino: meta.ino,
            sb_ino: meta.sb_ino,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Eq)]
pub struct Path {
    buffer: [u8; MAX_PATH_LEN],
    null: u8, // easy str break
    len: u32,
    depth: u16,
    real: bool, // flag if path is a realpath
    pub hash: u64,
    pub metadata: Option<Metadata>,
    pub mode: Mode,
    pub error: Option<Error>,
}

impl PartialEq for Path {
    fn eq(&self, other: &Self) -> bool {
        let meta_eq = match (self.metadata, other.metadata) {
            (Some(sm), Some(om)) => {
                sm.ino == om.ino
                    && sm.sb_ino == om.sb_ino
                    && sm.size == om.size
                    && sm.mtime == om.mtime
                    && sm.ctime == om.ctime
            }
            (None, None) => true,
            _ => false,
        };

        meta_eq
            && self.len == other.len
            && self.depth == other.depth
            && self.real == other.real
            && self.buffer == other.buffer
    }
}

impl Default for Path {
    fn default() -> Self {
        Path {
            buffer: [0; MAX_PATH_LEN],
            null: 0,
            len: 0,
            depth: 0,
            hash: 0,
            real: false,
            metadata: None,
            mode: Mode::Append,
            error: None,
        }
    }
}

// common implementation
impl Path {
    #[inline(always)]
    pub fn map_key(&self) -> MapKey {
        MapKey::from(self)
    }

    pub fn copy_from_str<T: AsRef<str>>(
        &mut self,
        s: T,
        mode: Mode,
    ) -> core::result::Result<usize, usize> {
        let src = s.as_ref().as_bytes();
        let n = min(src.len(), self.buffer.len());

        self.len = 0;
        self.mode = mode;
        self.error = None;

        let mut start = 0;
        if matches!(mode, Mode::Prepend) {
            start = self.buffer.len() - n;
        }
        self.buffer[start..start + n].copy_from_slice(&src[..n]);

        self.len = n as u32;

        if src.len() > self.buffer.len() {
            self.error = Some(Error::TruncPath);
            return Err(n);
        }

        Ok(n)
    }

    pub fn copy_from(&mut self, other: &Path) {
        unsafe { core::ptr::copy_nonoverlapping(other as *const Path, self as *mut Path, 1) };
    }

    pub fn is_relative(&self) -> bool {
        !self.is_absolute()
    }

    pub fn is_absolute(&self) -> bool {
        let s = self.as_slice();
        if !s.is_empty() {
            return s[0] == b'/';
        }
        false
    }

    pub fn is_realpath(&self) -> bool {
        self.real
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.buffer.as_ptr()
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn get_byte(&self, i: usize) -> core::result::Result<u8, Error> {
        let i = match self.mode {
            Mode::Append => i,
            Mode::Prepend => {
                let len = self.len;
                if len > self.buffer.len() as u32 {
                    return Err(Error::OutOfBound);
                }
                self.buffer.len() - len as usize + i
            }
        };

        // bound checking
        if i < self.buffer.len() {
            return Ok(unsafe { *self.buffer.get_unchecked(i) });
        }

        Err(Error::OutOfBound)
    }

    #[inline(always)]
    pub fn starts_with<T: Sized + AsRef<[u8]>>(&self, start: T) -> bool {
        let start = start.as_ref();

        // we cannot start with something that is bigger
        if start.len() > self.len() {
            return false;
        }

        for i in 0..core::mem::size_of::<T>() {
            if i == start.len() || i == self.len() {
                break;
            }

            let Ok(b) = self.get_byte(i) else {
                return false;
            };

            if b != unsafe { *start.get_unchecked(i) } {
                return false;
            }
        }
        true
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match self.mode {
            Mode::Append => {
                let len = (self.len as usize).clamp(0, self.buffer.len());
                &self.buffer[..len]
            }
            Mode::Prepend => {
                let len = self.len().clamp(0, MAX_PATH_LEN - 255);
                &self.buffer[(self.buffer.len() - len)..]
            }
        }
    }

    pub fn len(&self) -> usize {
        self.len as usize
    }

    pub fn depth(&self) -> usize {
        self.depth as usize
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use std::{path, println};

    #[test]
    fn test() {
        let mut p = Path::default();
        assert!(p.is_relative());
        let s = "/test/path";
        assert_eq!(p.copy_from_str(s, Mode::Append), Ok(s.len()));
        assert!(p.is_absolute());
    }

    #[test]
    fn test_into_pathbuf() {
        let mut p = Path::default();
        let s = "/bin/true";
        assert_eq!(p.copy_from_str(s, Mode::Prepend), Ok(s.len()));
        assert!(p.is_absolute());
        let pb: path::PathBuf = p.into();
        assert!(pb.exists());
        println!("{}", pb.to_string_lossy());
    }

    #[test]
    fn test_starts_with() {
        let mut p = Path::default();
        let s = "/bin/true";
        assert_eq!(p.copy_from_str(s, Mode::Prepend), Ok(s.len()));
        assert!(p.starts_with("/bin"));
        assert!(p.starts_with("/bin/true"));
        assert!(!p.starts_with("/bin/this is way too long"));
        assert!(!p.starts_with("/bin/truez"));
        // append mode
        p = Path::default();
        let s = "/bin/true";
        assert_eq!(p.copy_from_str(s, Mode::Append), Ok(s.len()));
        assert!(p.starts_with("/bin"));
        assert!(p.starts_with("/bin/true"));
        assert!(!p.starts_with("/bin/this is way too long"));
        assert!(!p.starts_with("/bin/truez"));
    }

    #[test]
    fn test_realpath() {
        let pb = std::path::PathBuf::from("/bin/true");
        let p = Path::try_from(&pb).unwrap();
        assert_eq!(p.to_path_buf(), pb);
    }
}
