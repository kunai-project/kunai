use crate::{bpf_target_code, not_bpf_target_code};

use super::bpf_utils::bound_value_for_verifier;
use super::time::Time;

use kunai_macros::BpfError;

#[allow(unused_imports)]
use core::{cmp::min, ffi::c_long};

// for path resolution
pub const MAX_PATH_DEPTH: u16 = 128;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_NAME: usize = u8::MAX as usize;

#[repr(C)]
#[derive(BpfError, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    #[error("should not happen")]
    ShouldNotHappen,
    #[error("filename is too long")]
    FileNameTooLong(u64, u32),
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

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Path {
    buffer: [u8; MAX_PATH_LEN],
    len: u32,
    depth: u16,
    real: bool, // flag if path is a realpath
    pub metadata: Option<Metadata>,
    pub mode: Mode,
    pub error: Option<Error>,
}

impl Default for Path {
    fn default() -> Self {
        Path {
            buffer: [0; MAX_PATH_LEN],
            len: 0,
            depth: 0,
            real: false,
            metadata: None,
            mode: Mode::Append,
            error: None,
        }
    }
}

// common implementation
impl Path {
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
    pub fn get_byte(&self, i: usize) -> u8 {
        match self.mode {
            Mode::Append => self.buffer[i],
            Mode::Prepend => {
                let i = bound_value_for_verifier(
                    (self.buffer.len() - self.len() + i) as isize,
                    0,
                    (self.buffer.len() - 1) as isize,
                );
                self.buffer[i as usize]
            }
        }
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

            if self.get_byte(i) != start[i] {
                return false;
            }
        }
        true
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        match self.mode {
            Mode::Append => {
                let len =
                    bound_value_for_verifier(self.len as isize, 0, self.buffer.len() as isize);
                &self.buffer[..len as usize]
            }
            Mode::Prepend => {
                let len = super::bpf_utils::cap_size(self.len(), MAX_PATH_LEN - 255);
                // this call is supposed to do nothing if not done from bpf code
                /*let start = super::bpf_utils::bound_value_for_verifier(
                    (self.buffer.len() - len) as isize,
                    0,
                    (self.buffer.len() - 1) as isize,
                );*/

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

// Non BPF implementations
not_bpf_target_code! {

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

    impl Display for Error{
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
            let path_buf_len = value.to_string_lossy().as_bytes().len();

            if  path_buf_len > out.buffer.len(){
                return Err(Error::FilePathTooLong);
            }

            let len = min(path_buf_len, out.buffer.len());

            out.buffer[..len].as_mut().copy_from_slice(&value.to_string_lossy().as_bytes()[..len]);

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
        pub fn try_from_realpath<T:AsRef<path::Path>>(p: T) -> Result<Self,Error> {
            let mut p = Self::try_from(p.as_ref().to_path_buf())?;
            p.real = true;
            Ok(p)
        }

        pub fn to_path_buf(self) -> path::PathBuf {
            self.into()
        }
    }

}

// BPF related implementations
bpf_target_code! {

use aya_bpf::helpers::gen;
use crate::co_re::{self, core_read_kernel};

type Result<T> = core::result::Result<T, Error>;


impl Path {

    #[inline(always)]
    unsafe fn init_from_inode(&mut self, i: &co_re::inode) -> Result<()> {
        let atime = core_read_kernel!(i, i_atime).ok_or(Error::DentryAtime)?;
        let ctime = core_read_kernel!(i, i_ctime).ok_or(Error::DentryCtime)?;
        let mtime = core_read_kernel!(i, i_mtime).ok_or(Error::DentryMtime)?;

        self.metadata = Some(
            Metadata {
                ino: core_read_kernel!(i, i_ino).ok_or(Error::PathInoFailure)?,
                sb_ino: core_read_kernel!(i, i_sb ,s_root, d_inode, i_ino).ok_or(Error::PathSbInoFailure)?,
                size: core_read_kernel!(i,i_size).ok_or(Error::InodeIsize)?,
                atime: atime.into(),
                ctime: ctime.into(),
                mtime: mtime.into(),}
            );

            Ok(())
        }

        #[inline(always)]
        pub unsafe fn core_resolve_file(&mut self, f: &co_re::file, max_depth: u16) -> Result<()> {
            if !f.is_null(){
                return self.core_resolve(&f.f_path().ok_or(Error::FPathMissing)?, max_depth);
            }
            Ok(())
        }

        // without this inline fentry probes get read! error, maybe there is an issue while passing bpf_types to functions
        #[inline(always)]
        pub unsafe fn core_resolve(&mut self, p: &co_re::path, max_depth: u16) -> Result<()> {
            // if path is null we return Ok
            // this is mostly to massage our friend verifier
            if p.is_null(){
                return Ok(());
            }

            let mut entry = p.dentry().ok_or(Error::DentryMissing)?;
            let d_inode = core_read_kernel!(entry, d_inode).ok_or(Error::DentryDinode)?;

            // initialization
            self.mode = Mode::Prepend;
            self.init_from_inode(&d_inode)?;


            let mnt = p.mnt().ok_or(Error::RFPathMnt)?;
            let mut mount = mnt.mount();

            let mut mnt_parent = mount.mnt_parent().ok_or(Error::MntParentMissing)?;

            let mut mnt_root = mnt.mnt_root().ok_or(Error::MntRootMissing)?;


            for _i in 0..max_depth {
                if entry == mnt_root {
                    if mount == mnt_parent {
                        break;
                    }

                    entry = mount.mnt_mountpoint().ok_or(Error::MntMountpointMissing)?;
                    mount = mnt_parent;
                    mnt_parent = mount.mnt_parent().ok_or(Error::MntParentMissing)?;
                    //mnt_root = mount.mnt().mnt_root();
                    mnt_root = core_read_kernel!(mount,mnt,mnt_root).ok_or(Error::MntRootMissing)?;
                    continue;
                }

                let parent = entry.d_parent().ok_or(Error::DParentMissing)?;
                if entry == parent {
                    break;
                }

                // read the qstr
                if !self.is_empty() {
                    self.prepend_path_sep()?;
                }

                let name = core_read_kernel!(entry, d_name, name).ok_or(Error::DNameNameMissing)?;
                let len = core_read_kernel!(entry, d_name, len).ok_or(Error::DNameLenMissing)?;
                //self.prepend_qstr_name(entry.d_name().name(), entry.d_name().len())?;
                self.prepend_qstr_name(name, len)?;
                if parent.is_null(){
                    break;
                }
                entry = parent;
            }

            let name = core_read_kernel!(entry, d_name, name).ok_or(Error::DNameNameMissing)?;
            let len = core_read_kernel!(entry, d_name, len).ok_or(Error::DNameLenMissing)?;
            // we read root
            //self.prepend_qstr_name(entry.d_name().name(), entry.d_name().len())?;
            self.prepend_qstr_name(name, len)?;

            Ok(())
        }

        fn prepend_path_sep(&mut self) -> Result<()> {
            let mut i = (self.buffer.len() - self.len() - 1) as isize;

            // we need to bound check index to massage the verifier
            i = bound_value_for_verifier(i, 0, (self.buffer.len() - 1) as isize);
            self.buffer[i as usize] = b'/';
            self.len += 1;
            Ok(())
        }


        /*pub fn prepend_qstr_name(&mut self, name: *const u8, qstr_len: u32 ) -> Result<()> {
            // needed so that the verifier knows self.len is bounded
            let len = cap_size(self.len, MAX_PATH_LEN as u32);

            // we need this check otherwise verifier fails with invalid numeric error
            if qstr_len > MAX_NAME as u32 {
                self.error = Some(Error::FileNameTooLong(name as u64, qstr_len));
                return Err(Error::FileNameTooLong(name as u64, qstr_len));
            }

            // we check if we can append the qstr to the path
            if len + qstr_len > MAX_PATH_LEN as u32 {
                self.error = Some(Error::FilePathTooLong);
                return Err(Error::FilePathTooLong);
            }

            // we reached max path depth
            if self.depth == MAX_PATH_DEPTH {
                self.error = Some(Error::ReachedMaxPathDepth);
                return Err(Error::ReachedMaxPathDepth);
            }

            // we compute where we should put the qstr
            let start = (self.buffer.len() - len as usize - qstr_len as usize) as isize;

            // verifier massage
            let k =
            bound_value_for_verifier(start, 0, (self.buffer.len() as isize) - qstr_len as isize);

            if unsafe {
                gen::bpf_probe_read(
                    self.buffer[(k as usize)..].as_mut_ptr() as *mut _,
                    cap_size(qstr_len, MAX_NAME as u32),
                    name as *const _,
                )
            } >= 0
            {
                self.len += qstr_len;
                self.depth += 1;
            } else {
                self.error = Some(Error::RFPathSegment);
                return Err(Error::RFPathSegment);
            }

            Ok(())
        }*/

        #[inline(always)]
        fn space_left(&self) -> usize{
            self.buffer.len() - self.len()
        }

        pub unsafe fn prepend_qstr_name(&mut self, name: *const u8, qstr_len: u32 ) -> Result<()> {
            // needed so that the verifier knows self.len is bounded
            let left = self.space_left() as u32;
            // a way to restrict the length to read for the verifier
            let size = (qstr_len as u8) as u32;

            // we need this check otherwise verifier fails with invalid numeric error
            if qstr_len > MAX_NAME as u32 {
                self.error = Some(Error::FileNameTooLong(name as u64, qstr_len));
                return Err(Error::FileNameTooLong(name as u64, qstr_len));
            }

            if left < qstr_len {
                return Err(Error::FilePathTooLong);
            }

            let i = left - size;

            if i > self.buffer.len() as u32{
                return Err(Error::ShouldNotHappen);
            }

            let dst = &mut self.buffer[i as usize..];

             if gen::bpf_probe_read(
                    dst.as_mut_ptr() as *mut _,
                    size,
                    name as *const _,
                )
            >= 0
            {
                self.len += size;
                self.depth += 1;
            } else {
                self.error = Some(Error::RFPathSegment);
                return Err(Error::RFPathSegment);
            }


            Ok(())
        }

        pub unsafe fn bpf_probe_read_str(&mut self, addr: u64) -> Result<()> {
            self.mode = Mode::Append;

            let len = gen::bpf_probe_read_str(
                self.buffer.as_ptr() as *mut _,
                core::mem::size_of_val(&self.buffer) as u32,
                addr as *const _,
            );
            if len <= 0 {
                return Err(Error::BpfProbeReadFailure);
            }
            // len is the size read including NULL byte
            // len cannot be 0 so it is Ok to substract 1
            self.len = (len - 1) as u32;
            Ok(())
        }

        pub unsafe fn to_aya_debug_str(&self) -> &str {
            return core::str::from_utf8_unchecked(&self.buffer[..]);
            //return core::str::from_utf8_unchecked(self.as_slice());
        }
    }

}

#[cfg(target_arch = "x86_64")]
#[cfg(test)]
mod test {

    use super::*;
    use std::println;

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
