use aya_bpf::cty::c_void;

use super::gen::{self, *};
use super::{rust_shim_impl, CoRe};

#[allow(non_camel_case_types)]
pub type inode = CoRe<gen::inode>;

const S_IFMT: u16 = 0o00170000;
const S_IFREG: u16 = 0o0100000;
const S_IFSOCK: u16 = 0o0140000;

impl inode {
    rust_shim_impl!(pub, inode, i_ino, u64);
    rust_shim_impl!(pub, inode, i_mode, u16);

    pub unsafe fn is_file(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFREG)
    }

    pub unsafe fn is_sock(&self) -> Option<bool> {
        Some(self.i_mode()? & S_IFMT == S_IFSOCK)
    }
}

#[allow(non_camel_case_types)]
pub type file = CoRe<gen::file>;

impl file {
    rust_shim_impl!(pub, file, f_path, path);
    rust_shim_impl!(pub, file, f_inode, inode);

    pub unsafe fn is_file(&self) -> Option<bool> {
        self.f_inode()?.is_file()
        /*match self.f_inode() {
            Some(f_inode) => f_inode.is_file(),
            _ => None,
        }*/
    }

    pub unsafe fn is_sock(&self) -> Option<bool> {
        self.f_inode()?.is_sock()
    }

    rust_shim_impl!(pub, file, private_data, *mut c_void);
}

#[allow(non_camel_case_types)]
pub type fd = CoRe<gen::fd>;

impl fd {
    rust_shim_impl!(pub, fd, file, file);
}

#[allow(non_camel_case_types)]
pub type path = CoRe<gen::path>;

impl path {
    rust_shim_impl!(pub, path, mnt, vfsmount);
    rust_shim_impl!(pub, path, dentry, dentry);
}

#[allow(non_camel_case_types)]
pub type qstr = CoRe<gen::qstr>;

impl qstr {
    rust_shim_impl!(pub, qstr, name, *const u8);
    rust_shim_impl!(pub, qstr, hash_len, u64);

    pub unsafe fn hash(&self) -> Option<u32> {
        Some(self.hash_len()? as u32)
    }

    pub unsafe fn len(&self) -> Option<u32> {
        //(shim_qstr_hash_len(self.as_ptr_mut()) >> 32) as u32
        Some((self.hash_len()? >> 32) as u32)
    }
}

#[allow(non_camel_case_types)]
pub type dentry = CoRe<gen::dentry>;

const DCACHE_MOUNTED: u32 = 0x00010000;

impl dentry {
    rust_shim_impl!(pub, dentry, d_sb, super_block);
    rust_shim_impl!(pub, dentry, d_parent, dentry);
    rust_shim_impl!(pub, dentry, d_flags, u32);

    pub unsafe fn is_mountpoint(&self) -> Option<bool> {
        Some(self.d_flags()? & DCACHE_MOUNTED == DCACHE_MOUNTED)
    }

    rust_shim_impl!(pub, dentry, d_name, qstr);
    rust_shim_impl!(pub, dentry, d_inode, inode);

    pub unsafe fn is_file(&self) -> Option<bool> {
        self.d_inode()?.is_file()
    }
}

#[allow(non_camel_case_types)]
pub type super_block = CoRe<gen::super_block>;

impl super_block {
    rust_shim_impl!(pub, super_block, s_root, dentry);
}

#[allow(non_camel_case_types)]
pub type mount = CoRe<gen::mount>;

impl mount {
    rust_shim_impl!(pub, mount, mnt, vfsmount);
    rust_shim_impl!(pub, mount, mnt_mountpoint, dentry);
    rust_shim_impl!(pub, mount, mnt_parent, mount);
}

#[allow(non_camel_case_types)]
pub type vfsmount = CoRe<gen::vfsmount>;

impl vfsmount {
    pub unsafe fn mount(&self) -> mount {
        mount::from_ptr(shim_mount_from_vfsmount(self.as_ptr_mut()))
    }

    rust_shim_impl!(pub, vfsmount, mnt_root, dentry);
}
