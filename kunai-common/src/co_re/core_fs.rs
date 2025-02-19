use aya_ebpf::cty::c_void;

use super::gen::{self, *};
use super::{rust_shim_kernel_impl, CoRe};

#[allow(non_camel_case_types)]
pub type inode = CoRe<gen::inode>;

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;
const S_IFSOCK: u16 = 0o0140000;

impl inode {
    rust_shim_kernel_impl!(inode, i_ino, u64);
    rust_shim_kernel_impl!(inode, i_mode, u16);
    rust_shim_kernel_impl!(inode, i_sb, super_block);
    rust_shim_kernel_impl!(inode, i_size, i64);

    // for kernels < 6.7
    rust_shim_kernel_impl!(pub(self),_i_atime, inode, i_atime, timespec64);
    // for kernels in [6.7; 6.11]
    rust_shim_kernel_impl!(pub(self), ___i_atime, inode, __i_atime, timespec64);
    // for kernels >= 6.11
    rust_shim_kernel_impl!(pub(self), i_atime_sec, inode, i_atime_sec, i64);
    rust_shim_kernel_impl!(pub(self), i_atime_nsec, inode, i_atime_nsec, i64);

    pub unsafe fn i_atime(&self) -> Option<timespec64> {
        self._i_atime().or_else(|| self.___i_atime()).or_else(|| {
            Some(timespec64 {
                tv_sec: self.i_atime_sec()?,
                tv_nsec: self.i_atime_nsec()?,
            })
        })
    }

    // for kernels < 6.7
    rust_shim_kernel_impl!(pub(self),_i_mtime, inode, i_mtime, timespec64);
    // for kernels in [6.7; 6.11]
    rust_shim_kernel_impl!(pub(self), ___i_mtime, inode, __i_mtime, timespec64);
    // for kernels >= 6.11
    rust_shim_kernel_impl!(pub(self),i_mtime_sec, inode, i_mtime_sec, i64);
    rust_shim_kernel_impl!(pub(self),i_mtime_nsec, inode, i_mtime_nsec, i64);

    pub unsafe fn i_mtime(&self) -> Option<timespec64> {
        self._i_mtime().or_else(|| self.___i_mtime()).or_else(|| {
            Some(timespec64 {
                tv_sec: self.i_mtime_sec()?,
                tv_nsec: self.i_mtime_nsec()?,
            })
        })
    }

    // for kernels < 6.6
    rust_shim_kernel_impl!(pub(self),_i_ctime, inode, i_ctime, timespec64);
    // for kernels in [6.6; 6.11]
    rust_shim_kernel_impl!(pub(self), ___i_ctime, inode, __i_ctime, timespec64);
    // for kernels >= 6.11
    rust_shim_kernel_impl!(pub(self),i_ctime_sec, inode, i_ctime_sec, i64);
    rust_shim_kernel_impl!(pub(self),i_ctime_nsec, inode, i_ctime_nsec, i64);

    pub unsafe fn i_ctime(&self) -> Option<timespec64> {
        self._i_ctime().or_else(|| self.___i_ctime()).or_else(|| {
            Some(timespec64 {
                tv_sec: self.i_ctime_sec()?,
                tv_nsec: self.i_ctime_nsec()?,
            })
        })
    }

    #[inline(always)]
    pub unsafe fn is_file(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFREG)
    }

    #[inline(always)]
    pub unsafe fn is_sock(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFSOCK)
    }
}

#[allow(non_camel_case_types)]
pub type file = CoRe<gen::file>;

impl file {
    rust_shim_kernel_impl!(pub, file, f_path, path);
    rust_shim_kernel_impl!(pub, file, f_inode, inode);
    rust_shim_kernel_impl!(pub, file, f_flags, u32);
    rust_shim_kernel_impl!(pub, file, f_mode, u32);

    #[inline(always)]
    pub unsafe fn is_file(&self) -> Option<bool> {
        self.f_inode()?.is_file()
    }

    #[inline(always)]
    pub unsafe fn is_sock(&self) -> Option<bool> {
        self.f_inode()?.is_sock()
    }

    rust_shim_kernel_impl!(pub, file, private_data, *mut c_void);
}

#[allow(non_camel_case_types)]
pub type fd = CoRe<gen::fd>;

impl fd {
    rust_shim_kernel_impl!(pub, fd, file, file);
}

#[allow(non_camel_case_types)]
pub type path = CoRe<gen::path>;

impl path {
    rust_shim_kernel_impl!(pub, path, mnt, vfsmount);
    rust_shim_kernel_impl!(pub, path, dentry, dentry);
}

#[allow(non_camel_case_types)]
pub type qstr = CoRe<gen::qstr>;

impl qstr {
    rust_shim_kernel_impl!(pub, qstr, name, *const u8);
    rust_shim_kernel_impl!(pub, qstr, hash_len, u64);
    rust_shim_kernel_impl!(pub, qstr, hash, u32);
    rust_shim_kernel_impl!(pub, qstr, len, u32);
}

#[allow(non_camel_case_types)]
pub type dentry = CoRe<gen::dentry>;

const DCACHE_MOUNTED: u32 = 0x00010000;

impl dentry {
    rust_shim_kernel_impl!(pub, dentry, d_sb, super_block);
    rust_shim_kernel_impl!(pub, dentry, d_parent, dentry);
    rust_shim_kernel_impl!(pub, dentry, d_flags, u32);

    #[inline(always)]
    pub unsafe fn is_mountpoint(&self) -> Option<bool> {
        Some(self.d_flags()? & DCACHE_MOUNTED == DCACHE_MOUNTED)
    }

    rust_shim_kernel_impl!(pub, dentry, d_name, qstr);
    rust_shim_kernel_impl!(pub, dentry, d_inode, inode);

    #[inline(always)]
    pub unsafe fn is_file(&self) -> Option<bool> {
        self.d_inode()?.is_file()
    }
}

#[allow(non_camel_case_types)]
pub type super_block = CoRe<gen::super_block>;

impl super_block {
    rust_shim_kernel_impl!(pub, super_block, s_root, dentry);
}

#[allow(non_camel_case_types)]
pub type mount = CoRe<gen::mount>;

impl mount {
    rust_shim_kernel_impl!(pub, mount, mnt, vfsmount);
    rust_shim_kernel_impl!(pub, mount, mnt_mountpoint, dentry);
    rust_shim_kernel_impl!(pub, mount, mnt_parent, mount);
    rust_shim_kernel_impl!(mount, mnt_mp, mountpoint);
}

#[allow(non_camel_case_types)]
pub type vfsmount = CoRe<gen::vfsmount>;

impl vfsmount {
    #[inline(always)]
    pub unsafe fn mount(&self) -> mount {
        mount::from_ptr(shim_mount_from_vfsmount(self.as_ptr_mut()))
    }

    rust_shim_kernel_impl!(pub, vfsmount, mnt_root, dentry);
}

#[allow(non_camel_case_types)]
pub type mountpoint = CoRe<gen::mountpoint>;

impl mountpoint {
    rust_shim_kernel_impl!(mountpoint, m_dentry, dentry);
}
