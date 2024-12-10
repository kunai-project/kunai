use crate::co_re::{self, core_read_kernel};
use aya_ebpf::check_bounds_signed;
use aya_ebpf::helpers::gen;

use super::{Error, Metadata, Mode, Path, MAX_NAME, MAX_PATH_LEN};

type Result<T> = core::result::Result<T, Error>;

fn xor_shift_star(a: u64, b: u64) -> u64 {
    let mut x = a ^ b;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    return x * 0x2545F4914F6CDD1D;
}

#[allow(dead_code)]
#[repr(C)]
pub struct MapKey {
    hash: u64,
    // depth is a u32 to force structure alignment
    // without this kernel 5.4 fails at using this
    // struct
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

impl Path {
    #[inline(always)]
    unsafe fn init_from_inode(&mut self, i: &co_re::inode) -> Result<()> {
        let atime = core_read_kernel!(i, i_atime).ok_or(Error::DentryAtime)?;
        let ctime = core_read_kernel!(i, i_ctime).ok_or(Error::DentryCtime)?;
        let mtime = core_read_kernel!(i, i_mtime).ok_or(Error::DentryMtime)?;

        self.metadata = Some(Metadata {
            ino: core_read_kernel!(i, i_ino).ok_or(Error::PathInoFailure)?,
            sb_ino: core_read_kernel!(i, i_sb, s_root, d_inode, i_ino)
                .ok_or(Error::PathSbInoFailure)?,
            size: core_read_kernel!(i, i_size).ok_or(Error::InodeIsize)?,
            atime: atime.into(),
            ctime: ctime.into(),
            mtime: mtime.into(),
        });

        Ok(())
    }

    #[inline(always)]
    pub fn map_key(&self) -> MapKey {
        MapKey::from(self)
    }

    #[inline(always)]
    pub unsafe fn core_resolve_file(&mut self, f: &co_re::file, max_depth: u16) -> Result<()> {
        if !f.is_null() {
            return self.core_resolve(&f.f_path().ok_or(Error::FPathMissing)?, max_depth);
        }
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn core_resolve(&mut self, p: &co_re::path, max_depth: u16) -> Result<()> {
        match self.inner_resolve(p, max_depth) {
            Ok(()) => Ok(()),
            Err(e) => {
                self.error = Some(e);
                Err(e)
            }
        }
    }

    #[inline(always)]
    unsafe fn inner_resolve(&mut self, p: &co_re::path, max_depth: u16) -> Result<()> {
        // if path is null we return Ok
        // this is mostly to massage our friend verifier
        if p.is_null() {
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
                mnt_root = core_read_kernel!(mount, mnt, mnt_root).ok_or(Error::MntRootMissing)?;
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

            // prepend segment
            self.prepend_dentry(&entry)?;

            if parent.is_null() {
                break;
            }
            entry = parent;
        }

        // we read root
        self.prepend_dentry(&entry)?;

        Ok(())
    }

    fn prepend_path_sep(&mut self) -> Result<()> {
        let i = (self.buffer.len() - self.len() - 1) as i64;

        // we need to bound check index to massage the verifier
        if check_bounds_signed(i, 0, (MAX_PATH_LEN - 1) as i64) {
            self.buffer[i as usize] = b'/';
            self.len += 1;
        } else {
            return Err(Error::FilePathTooLong);
        }
        Ok(())
    }

    #[inline(always)]
    fn space_left(&self) -> usize {
        self.buffer.len() - self.len()
    }

    #[inline(always)]
    pub unsafe fn prepend_dentry(&mut self, entry: &co_re::dentry) -> Result<()> {
        let hash = core_read_kernel!(entry, d_name, hash_len).ok_or(Error::DNameHashLenMissing)?;
        self.hash = xor_shift_star(self.hash, hash);
        let name = core_read_kernel!(entry, d_name, name).ok_or(Error::DNameNameMissing)?;
        let len = core_read_kernel!(entry, d_name, len).ok_or(Error::DNameLenMissing)?;
        self.prepend_qstr_name(name, len)
    }

    unsafe fn prepend_qstr_name(&mut self, name: *const u8, qstr_len: u32) -> Result<()> {
        let qstr_len = qstr_len as i64;
        // needed so that the verifier knows self.len is bounded
        let left = self.space_left() as i64;

        let i = left - qstr_len;

        // check map bound access
        if !check_bounds_signed(i, 0, (MAX_PATH_LEN - 1) as i64) {
            return Err(Error::FilePathTooLong);
        }

        let dst = self.buffer[i as usize..].as_mut_ptr();

        // check amount of data read
        if !check_bounds_signed(qstr_len, 0, MAX_NAME as i64) {
            return Err(Error::FileNameTooLong);
        }

        if gen::bpf_probe_read(dst as *mut _, qstr_len as u32, name as *const _) >= 0 {
            self.len += qstr_len as u32;
            self.depth += 1;
        } else {
            return Err(Error::RFPathSegment);
        }

        Ok(())
    }

    #[inline]
    /// function aiming at being used in bpf_printk
    pub unsafe fn as_str_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }
}
