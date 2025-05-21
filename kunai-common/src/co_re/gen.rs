pub type __u64 = ::core::ffi::c_ulonglong;
pub type u64_ = __u64;
pub type __u32 = ::core::ffi::c_uint;
pub type u32_ = __u32;
pub type __u16 = ::core::ffi::c_ushort;
pub type u16_ = __u16;
pub type __u8 = ::core::ffi::c_uchar;
pub type u8_ = __u8;
pub type __be16 = __u16;
pub type __be32 = __u32;
pub type __s64 = ::core::ffi::c_longlong;
pub type __kernel_ulong_t = ::core::ffi::c_ulong;
pub type __kernel_size_t = __kernel_ulong_t;
pub type __kernel_pid_t = ::core::ffi::c_int;
pub type __kernel_uid32_t = ::core::ffi::c_uint;
pub type __kernel_gid32_t = ::core::ffi::c_uint;
pub type __kernel_loff_t = ::core::ffi::c_longlong;
pub type __kernel_sa_family_t = ::core::ffi::c_ushort;
pub type uid_t = __kernel_uid32_t;
pub type gid_t = __kernel_gid32_t;
pub type pid_t = __kernel_pid_t;
pub type size_t = __kernel_size_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kgid_t {
    pub val: gid_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kuid_t {
    pub val: uid_t,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cred {
    pub uid: kuid_t,
    pub gid: kgid_t,
}
unsafe extern "C" {
    pub fn shim_cred_uid(pcred: *mut cred) -> uid_t;
}
unsafe extern "C" {
    pub fn shim_cred_gid(pcred: *mut cred) -> gid_t;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct qstr {
    pub __bindgen_anon_1: qstr__bindgen_ty_1,
    pub name: *const ::core::ffi::c_uchar,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union qstr__bindgen_ty_1 {
    pub hash_len: __u64,
    pub __bindgen_anon_1: qstr__bindgen_ty_1__bindgen_ty_1,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct qstr__bindgen_ty_1__bindgen_ty_1 {
    pub hash: u32_,
    pub len: u32_,
}
unsafe extern "C" {
    pub fn shim_qstr_name(qstr: *mut qstr) -> *const ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_qstr_name_user(qstr: *mut qstr) -> *const ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_qstr_name_exists(qstr: *mut qstr) -> bool;
}
unsafe extern "C" {
    pub fn shim_qstr_hash_len(qstr: *mut qstr) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_qstr_hash_len_user(qstr: *mut qstr) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_qstr_hash_len_exists(qstr: *mut qstr) -> bool;
}
unsafe extern "C" {
    pub fn shim_qstr_hash(qstr: *mut qstr) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_qstr_hash_user(qstr: *mut qstr) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_qstr_hash_exists(qstr: *mut qstr) -> bool;
}
unsafe extern "C" {
    pub fn shim_qstr_len(qstr: *mut qstr) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_qstr_len_user(qstr: *mut qstr) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_qstr_len_exists(qstr: *mut qstr) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct vfsmount {
    pub mnt_root: *mut dentry,
}
unsafe extern "C" {
    pub fn shim_vfsmount_mnt_root(vfsmount: *mut vfsmount) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_vfsmount_mnt_root_user(vfsmount: *mut vfsmount) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_vfsmount_mnt_root_exists(vfsmount: *mut vfsmount) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mount {
    pub mnt_parent: *mut mount,
    pub mnt_mountpoint: *mut dentry,
    pub mnt: vfsmount,
    pub mnt_mp: *mut mountpoint,
}
unsafe extern "C" {
    pub fn shim_mount_mnt_parent(mount: *mut mount) -> *mut mount;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_parent_user(mount: *mut mount) -> *mut mount;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_parent_exists(mount: *mut mount) -> bool;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_mountpoint(mount: *mut mount) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_mountpoint_user(mount: *mut mount) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_mountpoint_exists(mount: *mut mount) -> bool;
}
unsafe extern "C" {
    pub fn shim_mount_mnt(mount: *mut mount) -> *mut vfsmount;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_user(mount: *mut mount) -> *mut vfsmount;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_exists(mount: *mut mount) -> bool;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_mp(mount: *mut mount) -> *mut mountpoint;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_mp_user(mount: *mut mount) -> *mut mountpoint;
}
unsafe extern "C" {
    pub fn shim_mount_mnt_mp_exists(mount: *mut mount) -> bool;
}
unsafe extern "C" {
    pub fn shim_mount_from_vfsmount(vfs: *mut vfsmount) -> *mut mount;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct super_block {
    pub s_root: *mut dentry,
}
unsafe extern "C" {
    pub fn shim_super_block_s_root(super_block: *mut super_block) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_super_block_s_root_user(super_block: *mut super_block) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_super_block_s_root_exists(super_block: *mut super_block) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct dentry {
    pub d_flags: ::core::ffi::c_uint,
    pub d_parent: *mut dentry,
    pub d_name: qstr,
    pub d_sb: *mut super_block,
    pub d_inode: *mut inode,
}
unsafe extern "C" {
    pub fn shim_dentry_d_parent(dentry: *mut dentry) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_dentry_d_parent_user(dentry: *mut dentry) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_dentry_d_parent_exists(dentry: *mut dentry) -> bool;
}
unsafe extern "C" {
    pub fn shim_dentry_d_flags(dentry: *mut dentry) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_dentry_d_flags_user(dentry: *mut dentry) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_dentry_d_flags_exists(dentry: *mut dentry) -> bool;
}
unsafe extern "C" {
    pub fn shim_dentry_d_name(dentry: *mut dentry) -> *mut qstr;
}
unsafe extern "C" {
    pub fn shim_dentry_d_name_user(dentry: *mut dentry) -> *mut qstr;
}
unsafe extern "C" {
    pub fn shim_dentry_d_name_exists(dentry: *mut dentry) -> bool;
}
unsafe extern "C" {
    pub fn shim_dentry_d_sb(dentry: *mut dentry) -> *mut super_block;
}
unsafe extern "C" {
    pub fn shim_dentry_d_sb_user(dentry: *mut dentry) -> *mut super_block;
}
unsafe extern "C" {
    pub fn shim_dentry_d_sb_exists(dentry: *mut dentry) -> bool;
}
unsafe extern "C" {
    pub fn shim_dentry_d_inode(dentry: *mut dentry) -> *mut inode;
}
unsafe extern "C" {
    pub fn shim_dentry_d_inode_user(dentry: *mut dentry) -> *mut inode;
}
unsafe extern "C" {
    pub fn shim_dentry_d_inode_exists(dentry: *mut dentry) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mountpoint {
    pub m_dentry: *mut dentry,
}
unsafe extern "C" {
    pub fn shim_mountpoint_m_dentry(mountpoint: *mut mountpoint) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_mountpoint_m_dentry_user(mountpoint: *mut mountpoint) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_mountpoint_m_dentry_exists(mountpoint: *mut mountpoint) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct path {
    pub mnt: *mut vfsmount,
    pub dentry: *mut dentry,
}
unsafe extern "C" {
    pub fn shim_path_mnt(path: *mut path) -> *mut vfsmount;
}
unsafe extern "C" {
    pub fn shim_path_mnt_user(path: *mut path) -> *mut vfsmount;
}
unsafe extern "C" {
    pub fn shim_path_mnt_exists(path: *mut path) -> bool;
}
unsafe extern "C" {
    pub fn shim_path_dentry(path: *mut path) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_path_dentry_user(path: *mut path) -> *mut dentry;
}
unsafe extern "C" {
    pub fn shim_path_dentry_exists(path: *mut path) -> bool;
}
pub type time64_t = __s64;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct timespec64 {
    pub tv_sec: time64_t,
    pub tv_nsec: ::core::ffi::c_long,
}
pub type umode_t = ::core::ffi::c_ushort;
pub type loff_t = __kernel_loff_t;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct inode {
    pub i_mode: umode_t,
    pub i_ino: ::core::ffi::c_ulong,
    pub i_sb: *mut super_block,
    pub i_size: loff_t,
    pub i_atime_sec: time64_t,
    pub i_mtime_sec: time64_t,
    pub i_ctime_sec: time64_t,
    pub i_atime_nsec: u32_,
    pub i_mtime_nsec: u32_,
    pub i_ctime_nsec: u32_,
    pub __bindgen_anon_1: inode__bindgen_ty_1,
    pub __bindgen_anon_2: inode__bindgen_ty_2,
    pub __bindgen_anon_3: inode__bindgen_ty_3,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union inode__bindgen_ty_1 {
    pub i_atime: timespec64,
    pub __i_atime: timespec64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union inode__bindgen_ty_2 {
    pub i_mtime: timespec64,
    pub __i_mtime: timespec64,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union inode__bindgen_ty_3 {
    pub i_ctime: timespec64,
    pub __i_ctime: timespec64,
}
unsafe extern "C" {
    pub fn shim_inode_i_ino(inode: *mut inode) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_inode_i_ino_user(inode: *mut inode) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_inode_i_ino_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_mode(inode: *mut inode) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_inode_i_mode_user(inode: *mut inode) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_inode_i_mode_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_sb(inode: *mut inode) -> *mut super_block;
}
unsafe extern "C" {
    pub fn shim_inode_i_sb_user(inode: *mut inode) -> *mut super_block;
}
unsafe extern "C" {
    pub fn shim_inode_i_sb_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_size(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_size_user(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_size_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_user(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode___i_atime(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode___i_atime_user(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode___i_atime_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_sec(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_sec_user(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_sec_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_nsec(inode: *mut inode) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_nsec_user(inode: *mut inode) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_inode_i_atime_nsec_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_user(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode___i_mtime(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode___i_mtime_user(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode___i_mtime_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_sec(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_sec_user(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_sec_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_nsec(inode: *mut inode) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_nsec_user(inode: *mut inode) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_inode_i_mtime_nsec_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_user(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode___i_ctime(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode___i_ctime_user(inode: *mut inode) -> timespec64;
}
unsafe extern "C" {
    pub fn shim_inode___i_ctime_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_sec(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_sec_user(inode: *mut inode) -> ::core::ffi::c_longlong;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_sec_exists(inode: *mut inode) -> bool;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_nsec(inode: *mut inode) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_nsec_user(inode: *mut inode) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_inode_i_ctime_nsec_exists(inode: *mut inode) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct file {
    pub f_inode: *mut inode,
    pub f_path: path,
    pub private_data: *mut ::core::ffi::c_void,
    pub f_flags: ::core::ffi::c_uint,
    pub f_mode: ::core::ffi::c_uint,
}
unsafe extern "C" {
    pub fn shim_file_f_path(file: *mut file) -> *mut path;
}
unsafe extern "C" {
    pub fn shim_file_f_path_user(file: *mut file) -> *mut path;
}
unsafe extern "C" {
    pub fn shim_file_f_path_exists(file: *mut file) -> bool;
}
unsafe extern "C" {
    pub fn shim_file_f_inode(file: *mut file) -> *mut inode;
}
unsafe extern "C" {
    pub fn shim_file_f_inode_user(file: *mut file) -> *mut inode;
}
unsafe extern "C" {
    pub fn shim_file_f_inode_exists(file: *mut file) -> bool;
}
unsafe extern "C" {
    pub fn shim_file_private_data(file: *mut file) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_file_private_data_user(file: *mut file) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_file_private_data_exists(file: *mut file) -> bool;
}
unsafe extern "C" {
    pub fn shim_file_f_flags(file: *mut file) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_file_f_flags_user(file: *mut file) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_file_f_flags_exists(file: *mut file) -> bool;
}
unsafe extern "C" {
    pub fn shim_file_f_mode(file: *mut file) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_file_f_mode_user(file: *mut file) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_file_f_mode_exists(file: *mut file) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fd {
    pub file: *mut file,
    pub flags: ::core::ffi::c_uint,
}
unsafe extern "C" {
    pub fn shim_fd_file(fd: *mut fd) -> *mut file;
}
unsafe extern "C" {
    pub fn shim_fd_file_user(fd: *mut fd) -> *mut file;
}
unsafe extern "C" {
    pub fn shim_fd_file_exists(fd: *mut fd) -> bool;
}
unsafe extern "C" {
    pub fn shim_fd_flags(fd: *mut fd) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_fd_flags_user(fd: *mut fd) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_fd_flags_exists(fd: *mut fd) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mm_struct {
    pub arg_start: ::core::ffi::c_ulong,
    pub arg_end: ::core::ffi::c_ulong,
    pub exe_file: *mut file,
}
unsafe extern "C" {
    pub fn shim_mm_struct_arg_start(mm_struct: *mut mm_struct) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_mm_struct_arg_start_user(mm_struct: *mut mm_struct) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_mm_struct_arg_start_exists(mm_struct: *mut mm_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_mm_struct_arg_end(mm_struct: *mut mm_struct) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_mm_struct_arg_end_user(mm_struct: *mut mm_struct) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_mm_struct_arg_end_exists(mm_struct: *mut mm_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_mm_struct_exe_file(mm_struct: *mut mm_struct) -> *mut file;
}
unsafe extern "C" {
    pub fn shim_mm_struct_exe_file_user(mm_struct: *mut mm_struct) -> *mut file;
}
unsafe extern "C" {
    pub fn shim_mm_struct_exe_file_exists(mm_struct: *mut mm_struct) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ns_common {
    pub inum: ::core::ffi::c_uint,
}
unsafe extern "C" {
    pub fn shim_ns_common_inum(ns_common: *mut ns_common) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_ns_common_inum_user(ns_common: *mut ns_common) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_ns_common_inum_exists(ns_common: *mut ns_common) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct mnt_namespace {
    pub ns: ns_common,
    pub root: *mut mount,
    pub mounts: ::core::ffi::c_uint,
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_ns(mnt_namespace: *mut mnt_namespace) -> *mut ns_common;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_ns_user(mnt_namespace: *mut mnt_namespace) -> *mut ns_common;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_ns_exists(mnt_namespace: *mut mnt_namespace) -> bool;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_root(mnt_namespace: *mut mnt_namespace) -> *mut mount;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_root_user(mnt_namespace: *mut mnt_namespace) -> *mut mount;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_root_exists(mnt_namespace: *mut mnt_namespace) -> bool;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_mounts(mnt_namespace: *mut mnt_namespace) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_mounts_user(mnt_namespace: *mut mnt_namespace)
        -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_mnt_namespace_mounts_exists(mnt_namespace: *mut mnt_namespace) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct new_utsname {
    pub sysname: [::core::ffi::c_char; 65usize],
    pub nodename: [::core::ffi::c_char; 65usize],
    pub release: [::core::ffi::c_char; 65usize],
    pub version: [::core::ffi::c_char; 65usize],
    pub machine: [::core::ffi::c_char; 65usize],
    pub domainname: [::core::ffi::c_char; 65usize],
}
unsafe extern "C" {
    pub fn shim_new_utsname_sysname(new_utsname: *mut new_utsname) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_sysname_user(new_utsname: *mut new_utsname)
        -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_sysname_exists(new_utsname: *mut new_utsname) -> bool;
}
unsafe extern "C" {
    pub fn shim_new_utsname_nodename(new_utsname: *mut new_utsname) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_nodename_user(
        new_utsname: *mut new_utsname,
    ) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_nodename_exists(new_utsname: *mut new_utsname) -> bool;
}
unsafe extern "C" {
    pub fn shim_new_utsname_release(new_utsname: *mut new_utsname) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_release_user(new_utsname: *mut new_utsname)
        -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_release_exists(new_utsname: *mut new_utsname) -> bool;
}
unsafe extern "C" {
    pub fn shim_new_utsname_version(new_utsname: *mut new_utsname) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_version_user(new_utsname: *mut new_utsname)
        -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_version_exists(new_utsname: *mut new_utsname) -> bool;
}
unsafe extern "C" {
    pub fn shim_new_utsname_machine(new_utsname: *mut new_utsname) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_machine_user(new_utsname: *mut new_utsname)
        -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_machine_exists(new_utsname: *mut new_utsname) -> bool;
}
unsafe extern "C" {
    pub fn shim_new_utsname_domainname(new_utsname: *mut new_utsname) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_domainname_user(
        new_utsname: *mut new_utsname,
    ) -> *mut ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_new_utsname_domainname_exists(new_utsname: *mut new_utsname) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct uts_namespace {
    pub name: new_utsname,
    pub ns: ns_common,
}
unsafe extern "C" {
    pub fn shim_uts_namespace_ns(uts_namespace: *mut uts_namespace) -> *mut ns_common;
}
unsafe extern "C" {
    pub fn shim_uts_namespace_ns_user(uts_namespace: *mut uts_namespace) -> *mut ns_common;
}
unsafe extern "C" {
    pub fn shim_uts_namespace_ns_exists(uts_namespace: *mut uts_namespace) -> bool;
}
unsafe extern "C" {
    pub fn shim_uts_namespace_name(uts_namespace: *mut uts_namespace) -> *mut new_utsname;
}
unsafe extern "C" {
    pub fn shim_uts_namespace_name_user(uts_namespace: *mut uts_namespace) -> *mut new_utsname;
}
unsafe extern "C" {
    pub fn shim_uts_namespace_name_exists(uts_namespace: *mut uts_namespace) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct nsproxy {
    pub mnt_ns: *mut mnt_namespace,
    pub uts_ns: *mut uts_namespace,
}
unsafe extern "C" {
    pub fn shim_nsproxy_mnt_ns(nsproxy: *mut nsproxy) -> *mut mnt_namespace;
}
unsafe extern "C" {
    pub fn shim_nsproxy_mnt_ns_user(nsproxy: *mut nsproxy) -> *mut mnt_namespace;
}
unsafe extern "C" {
    pub fn shim_nsproxy_mnt_ns_exists(nsproxy: *mut nsproxy) -> bool;
}
unsafe extern "C" {
    pub fn shim_nsproxy_uts_ns(nsproxy: *mut nsproxy) -> *mut uts_namespace;
}
unsafe extern "C" {
    pub fn shim_nsproxy_uts_ns_user(nsproxy: *mut nsproxy) -> *mut uts_namespace;
}
unsafe extern "C" {
    pub fn shim_nsproxy_uts_ns_exists(nsproxy: *mut nsproxy) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kernfs_node {
    pub parent: *mut kernfs_node,
    pub name: *const ::core::ffi::c_char,
}
unsafe extern "C" {
    pub fn shim_kernfs_node_parent(kernfs_node: *mut kernfs_node) -> *mut kernfs_node;
}
unsafe extern "C" {
    pub fn shim_kernfs_node_parent_user(kernfs_node: *mut kernfs_node) -> *mut kernfs_node;
}
unsafe extern "C" {
    pub fn shim_kernfs_node_parent_exists(kernfs_node: *mut kernfs_node) -> bool;
}
unsafe extern "C" {
    pub fn shim_kernfs_node_name(kernfs_node: *mut kernfs_node) -> *const ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_kernfs_node_name_user(kernfs_node: *mut kernfs_node) -> *const ::core::ffi::c_char;
}
unsafe extern "C" {
    pub fn shim_kernfs_node_name_exists(kernfs_node: *mut kernfs_node) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cgroup {
    pub kn: *mut kernfs_node,
}
unsafe extern "C" {
    pub fn shim_cgroup_kn(cgroup: *mut cgroup) -> *mut kernfs_node;
}
unsafe extern "C" {
    pub fn shim_cgroup_kn_user(cgroup: *mut cgroup) -> *mut kernfs_node;
}
unsafe extern "C" {
    pub fn shim_cgroup_kn_exists(cgroup: *mut cgroup) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct cgroup_subsys_state {
    pub cgroup: *mut cgroup,
}
unsafe extern "C" {
    pub fn shim_cgroup_subsys_state_cgroup(
        cgroup_subsys_state: *mut cgroup_subsys_state,
    ) -> *mut cgroup;
}
unsafe extern "C" {
    pub fn shim_cgroup_subsys_state_cgroup_user(
        cgroup_subsys_state: *mut cgroup_subsys_state,
    ) -> *mut cgroup;
}
unsafe extern "C" {
    pub fn shim_cgroup_subsys_state_cgroup_exists(
        cgroup_subsys_state: *mut cgroup_subsys_state,
    ) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct task_group {
    pub css: cgroup_subsys_state,
}
unsafe extern "C" {
    pub fn shim_task_group_css(task_group: *mut task_group) -> *mut cgroup_subsys_state;
}
unsafe extern "C" {
    pub fn shim_task_group_css_user(task_group: *mut task_group) -> *mut cgroup_subsys_state;
}
unsafe extern "C" {
    pub fn shim_task_group_css_exists(task_group: *mut task_group) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct fdtable {
    pub max_fds: ::core::ffi::c_uint,
    pub fd: *mut *mut file,
}
unsafe extern "C" {
    pub fn shim_fdtable_max_fds(fdtable: *mut fdtable) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_fdtable_max_fds_user(fdtable: *mut fdtable) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_fdtable_max_fds_exists(fdtable: *mut fdtable) -> bool;
}
unsafe extern "C" {
    pub fn shim_fdtable_fd(fdtable: *mut fdtable) -> *mut *mut file;
}
unsafe extern "C" {
    pub fn shim_fdtable_fd_user(fdtable: *mut fdtable) -> *mut *mut file;
}
unsafe extern "C" {
    pub fn shim_fdtable_fd_exists(fdtable: *mut fdtable) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct files_struct {
    pub fdt: *mut fdtable,
    pub fd_array: [*mut file; 1usize],
}
unsafe extern "C" {
    pub fn shim_files_struct_fd_array(files_struct: *mut files_struct) -> *mut *mut file;
}
unsafe extern "C" {
    pub fn shim_files_struct_fd_array_user(files_struct: *mut files_struct) -> *mut *mut file;
}
unsafe extern "C" {
    pub fn shim_files_struct_fd_array_exists(files_struct: *mut files_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_files_struct_fdt(files_struct: *mut files_struct) -> *mut fdtable;
}
unsafe extern "C" {
    pub fn shim_files_struct_fdt_user(files_struct: *mut files_struct) -> *mut fdtable;
}
unsafe extern "C" {
    pub fn shim_files_struct_fdt_exists(files_struct: *mut files_struct) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct task_struct {
    pub flags: ::core::ffi::c_uint,
    pub pid: pid_t,
    pub start_time: __u64,
    pub __bindgen_anon_1: task_struct__bindgen_ty_1,
    pub tgid: pid_t,
    pub comm: [::core::ffi::c_uchar; 16usize],
    pub cred: *mut cred,
    pub real_parent: *mut task_struct,
    pub group_leader: *mut task_struct,
    pub mm: *mut mm_struct,
    pub files: *mut files_struct,
    pub nsproxy: *mut nsproxy,
    pub sched_task_group: *mut task_group,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union task_struct__bindgen_ty_1 {
    pub start_boottime: __u64,
    pub real_start_time: __u64,
}
unsafe extern "C" {
    pub fn shim_task_struct_flags(task_struct: *mut task_struct) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_task_struct_flags_user(task_struct: *mut task_struct) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_task_struct_flags_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_start_time(task_struct: *mut task_struct) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_task_struct_start_time_user(
        task_struct: *mut task_struct,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_task_struct_start_time_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_start_boottime(
        task_struct: *mut task_struct,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_task_struct_start_boottime_user(
        task_struct: *mut task_struct,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_task_struct_start_boottime_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_real_start_time(
        task_struct: *mut task_struct,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_task_struct_real_start_time_user(
        task_struct: *mut task_struct,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_task_struct_real_start_time_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_comm(task_struct: *mut task_struct) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_task_struct_comm_user(task_struct: *mut task_struct) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_task_struct_comm_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_pid(task_struct: *mut task_struct) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_task_struct_pid_user(task_struct: *mut task_struct) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_task_struct_pid_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_tgid(task_struct: *mut task_struct) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_task_struct_tgid_user(task_struct: *mut task_struct) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_task_struct_tgid_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_cred(task_struct: *mut task_struct) -> *mut cred;
}
unsafe extern "C" {
    pub fn shim_task_struct_cred_user(task_struct: *mut task_struct) -> *mut cred;
}
unsafe extern "C" {
    pub fn shim_task_struct_cred_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_group_leader(task_struct: *mut task_struct) -> *mut task_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_group_leader_user(task_struct: *mut task_struct) -> *mut task_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_group_leader_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_real_parent(task_struct: *mut task_struct) -> *mut task_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_real_parent_user(task_struct: *mut task_struct) -> *mut task_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_real_parent_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_mm(task_struct: *mut task_struct) -> *mut mm_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_mm_user(task_struct: *mut task_struct) -> *mut mm_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_mm_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_files(task_struct: *mut task_struct) -> *mut files_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_files_user(task_struct: *mut task_struct) -> *mut files_struct;
}
unsafe extern "C" {
    pub fn shim_task_struct_files_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_nsproxy(task_struct: *mut task_struct) -> *mut nsproxy;
}
unsafe extern "C" {
    pub fn shim_task_struct_nsproxy_user(task_struct: *mut task_struct) -> *mut nsproxy;
}
unsafe extern "C" {
    pub fn shim_task_struct_nsproxy_exists(task_struct: *mut task_struct) -> bool;
}
unsafe extern "C" {
    pub fn shim_task_struct_sched_task_group(task_struct: *mut task_struct) -> *mut task_group;
}
unsafe extern "C" {
    pub fn shim_task_struct_sched_task_group_user(task_struct: *mut task_struct)
        -> *mut task_group;
}
unsafe extern "C" {
    pub fn shim_task_struct_sched_task_group_exists(task_struct: *mut task_struct) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_ksym {
    pub name: [::core::ffi::c_uchar; 512usize],
}
unsafe extern "C" {
    pub fn shim_bpf_ksym_name(bpf_ksym: *mut bpf_ksym) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_ksym_name_user(bpf_ksym: *mut bpf_ksym) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_ksym_name_exists(bpf_ksym: *mut bpf_ksym) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_prog_aux {
    pub id: __u32,
    pub name: [::core::ffi::c_uchar; 16usize],
    pub attach_func_name: *const ::core::ffi::c_uchar,
    pub verified_insns: __u32,
    pub ksym: bpf_ksym,
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_id(bpf_prog_aux: *mut bpf_prog_aux) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_id_user(bpf_prog_aux: *mut bpf_prog_aux) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_id_exists(bpf_prog_aux: *mut bpf_prog_aux) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_name(bpf_prog_aux: *mut bpf_prog_aux) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_name_user(
        bpf_prog_aux: *mut bpf_prog_aux,
    ) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_name_exists(bpf_prog_aux: *mut bpf_prog_aux) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_attach_func_name(
        bpf_prog_aux: *mut bpf_prog_aux,
    ) -> *const ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_attach_func_name_user(
        bpf_prog_aux: *mut bpf_prog_aux,
    ) -> *const ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_attach_func_name_exists(bpf_prog_aux: *mut bpf_prog_aux) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_verified_insns(bpf_prog_aux: *mut bpf_prog_aux)
        -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_verified_insns_user(
        bpf_prog_aux: *mut bpf_prog_aux,
    ) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_verified_insns_exists(bpf_prog_aux: *mut bpf_prog_aux) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_ksym(bpf_prog_aux: *mut bpf_prog_aux) -> *mut bpf_ksym;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_ksym_user(bpf_prog_aux: *mut bpf_prog_aux) -> *mut bpf_ksym;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_ksym_exists(bpf_prog_aux: *mut bpf_prog_aux) -> bool;
}
pub const bpf_prog_type_PROG_TYPE: bpf_prog_type = 0;
pub type bpf_prog_type = ::core::ffi::c_uint;
pub const bpf_attach_type_ATTACH_TYPE: bpf_attach_type = 0;
pub type bpf_attach_type = ::core::ffi::c_uint;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bpf_prog {
    pub len: __u32,
    pub type_: bpf_prog_type,
    pub expected_attach_type: bpf_attach_type,
    pub tag: [::core::ffi::c_uchar; 8usize],
    pub aux: *mut bpf_prog_aux,
    pub orig_prog: *mut sock_fprog_kern,
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux(bpf_prog: *mut bpf_prog) -> *mut bpf_prog_aux;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_user(bpf_prog: *mut bpf_prog) -> *mut bpf_prog_aux;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_aux_exists(bpf_prog: *mut bpf_prog) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_orig_prog(bpf_prog: *mut bpf_prog) -> *mut sock_fprog_kern;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_orig_prog_user(bpf_prog: *mut bpf_prog) -> *mut sock_fprog_kern;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_orig_prog_exists(bpf_prog: *mut bpf_prog) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_tag(bpf_prog: *mut bpf_prog) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_tag_user(bpf_prog: *mut bpf_prog) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_tag_exists(bpf_prog: *mut bpf_prog) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_type(bpf_prog: *mut bpf_prog) -> bpf_prog_type;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_type_user(bpf_prog: *mut bpf_prog) -> bpf_prog_type;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_type_exists(bpf_prog: *mut bpf_prog) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_expected_attach_type(bpf_prog: *mut bpf_prog) -> bpf_attach_type;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_expected_attach_type_user(bpf_prog: *mut bpf_prog) -> bpf_attach_type;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_expected_attach_type_exists(bpf_prog: *mut bpf_prog) -> bool;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_len(bpf_prog: *mut bpf_prog) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_len_user(bpf_prog: *mut bpf_prog) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bpf_prog_len_exists(bpf_prog: *mut bpf_prog) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock_filter {
    pub code: __u16,
    pub jt: __u8,
    pub jf: __u8,
    pub k: __u32,
}
unsafe extern "C" {
    pub fn shim_sock_filter_code(sock_filter: *mut sock_filter) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_filter_code_user(sock_filter: *mut sock_filter) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_filter_code_exists(sock_filter: *mut sock_filter) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_filter_jt(sock_filter: *mut sock_filter) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock_filter_jt_user(sock_filter: *mut sock_filter) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock_filter_jt_exists(sock_filter: *mut sock_filter) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_filter_jf(sock_filter: *mut sock_filter) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock_filter_jf_user(sock_filter: *mut sock_filter) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock_filter_jf_exists(sock_filter: *mut sock_filter) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_filter_k(sock_filter: *mut sock_filter) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sock_filter_k_user(sock_filter: *mut sock_filter) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sock_filter_k_exists(sock_filter: *mut sock_filter) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock_fprog {
    pub len: ::core::ffi::c_ushort,
    pub filter: *mut sock_filter,
}
unsafe extern "C" {
    pub fn shim_sock_fprog_len(sock_fprog: *mut sock_fprog) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_len_user(sock_fprog: *mut sock_fprog) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_len_exists(sock_fprog: *mut sock_fprog) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_filter(sock_fprog: *mut sock_fprog) -> *mut sock_filter;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_filter_user(sock_fprog: *mut sock_fprog) -> *mut sock_filter;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_filter_exists(sock_fprog: *mut sock_fprog) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock_fprog_kern {
    pub len: u16_,
    pub filter: *mut sock_filter,
}
unsafe extern "C" {
    pub fn shim_sock_fprog_kern_len(sock_fprog_kern: *mut sock_fprog_kern)
        -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_kern_len_user(
        sock_fprog_kern: *mut sock_fprog_kern,
    ) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_kern_len_exists(sock_fprog_kern: *mut sock_fprog_kern) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_kern_filter(sock_fprog_kern: *mut sock_fprog_kern) -> *mut sock_filter;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_kern_filter_user(
        sock_fprog_kern: *mut sock_fprog_kern,
    ) -> *mut sock_filter;
}
unsafe extern "C" {
    pub fn shim_sock_fprog_kern_filter_exists(sock_fprog_kern: *mut sock_fprog_kern) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct linux_binprm {
    pub mm: *mut mm_struct,
    pub file: *mut file,
    pub cred: *mut cred,
}
unsafe extern "C" {
    pub fn shim_linux_binprm_mm(linux_binprm: *mut linux_binprm) -> *mut mm_struct;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_mm_user(linux_binprm: *mut linux_binprm) -> *mut mm_struct;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_mm_exists(linux_binprm: *mut linux_binprm) -> bool;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_file(linux_binprm: *mut linux_binprm) -> *mut file;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_file_user(linux_binprm: *mut linux_binprm) -> *mut file;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_file_exists(linux_binprm: *mut linux_binprm) -> bool;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_cred(linux_binprm: *mut linux_binprm) -> *mut cred;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_cred_user(linux_binprm: *mut linux_binprm) -> *mut cred;
}
unsafe extern "C" {
    pub fn shim_linux_binprm_cred_exists(linux_binprm: *mut linux_binprm) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct load_info {
    pub name: *const ::core::ffi::c_uchar,
}
unsafe extern "C" {
    pub fn shim_load_info_name(load_info: *mut load_info) -> *const ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_load_info_name_user(load_info: *mut load_info) -> *const ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_load_info_name_exists(load_info: *mut load_info) -> bool;
}
pub type __addrpair = __u64;
pub type __portpair = __u32;
#[repr(C)]
#[derive(Copy, Clone)]
pub struct in6_addr {
    pub in6_u: in6_addr__bindgen_ty_1,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union in6_addr__bindgen_ty_1 {
    pub u6_addr8: [__u8; 16usize],
    pub u6_addr16: [__be16; 8usize],
    pub u6_addr32: [__be32; 4usize],
}
unsafe extern "C" {
    pub fn shim_in6_addr_u6_addr8(in6_addr: *mut in6_addr) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_in6_addr_u6_addr8_user(in6_addr: *mut in6_addr) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_in6_addr_u6_addr8_exists(in6_addr: *mut in6_addr) -> bool;
}
pub type sa_family_t = __kernel_sa_family_t;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr {
    pub sa_family: sa_family_t,
}
unsafe extern "C" {
    pub fn shim_sockaddr_sa_family(sockaddr: *mut sockaddr) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_sa_family_user(sockaddr: *mut sockaddr) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_sa_family_exists(sockaddr: *mut sockaddr) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct in_addr {
    pub s_addr: __be32,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sockaddr_in {
    pub sin_family: __kernel_sa_family_t,
    pub sin_port: __be16,
    pub sin_addr: in_addr,
    pub __pad: [::core::ffi::c_uchar; 8usize],
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_sin_family(sockaddr_in: *mut sockaddr_in) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_sin_family_user(sockaddr_in: *mut sockaddr_in)
        -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_sin_family_exists(sockaddr_in: *mut sockaddr_in) -> bool;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_sin_port(sockaddr_in: *mut sockaddr_in) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_sin_port_user(sockaddr_in: *mut sockaddr_in) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_sin_port_exists(sockaddr_in: *mut sockaddr_in) -> bool;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_s_addr(sockaddr_in: *mut sockaddr_in) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_s_addr_user(sockaddr_in: *mut sockaddr_in) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in_s_addr_exists(sockaddr_in: *mut sockaddr_in) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sockaddr_in6 {
    pub sin6_family: ::core::ffi::c_ushort,
    pub sin6_port: __be16,
    pub sin6_flowinfo: __be32,
    pub sin6_addr: in6_addr,
    pub sin6_scope_id: __u32,
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_family(sockaddr_in6: *mut sockaddr_in6) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_family_user(
        sockaddr_in6: *mut sockaddr_in6,
    ) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_family_exists(sockaddr_in6: *mut sockaddr_in6) -> bool;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_port(sockaddr_in6: *mut sockaddr_in6) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_port_user(
        sockaddr_in6: *mut sockaddr_in6,
    ) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_port_exists(sockaddr_in6: *mut sockaddr_in6) -> bool;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_addr(sockaddr_in6: *mut sockaddr_in6) -> *mut in6_addr;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_addr_user(sockaddr_in6: *mut sockaddr_in6) -> *mut in6_addr;
}
unsafe extern "C" {
    pub fn shim_sockaddr_in6_sin6_addr_exists(sockaddr_in6: *mut sockaddr_in6) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock_common {
    pub __bindgen_anon_1: sock_common__bindgen_ty_1,
    pub __bindgen_anon_2: sock_common__bindgen_ty_2,
    pub skc_family: ::core::ffi::c_ushort,
    pub skc_v6_daddr: in6_addr,
    pub skc_v6_rcv_saddr: in6_addr,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_ty_1 {
    pub skc_addrpair: __addrpair,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union sock_common__bindgen_ty_2 {
    pub skc_portpair: __portpair,
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_family(sock_common: *mut sock_common) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_family_user(sock_common: *mut sock_common)
        -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_family_exists(sock_common: *mut sock_common) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_addrpair(sock_common: *mut sock_common)
        -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_addrpair_user(
        sock_common: *mut sock_common,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_addrpair_exists(sock_common: *mut sock_common) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_portpair(sock_common: *mut sock_common) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_portpair_user(sock_common: *mut sock_common)
        -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_portpair_exists(sock_common: *mut sock_common) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_v6_daddr(sock_common: *mut sock_common) -> *mut in6_addr;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_v6_daddr_user(sock_common: *mut sock_common) -> *mut in6_addr;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_v6_daddr_exists(sock_common: *mut sock_common) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_v6_rcv_saddr(sock_common: *mut sock_common) -> *mut in6_addr;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_v6_rcv_saddr_user(sock_common: *mut sock_common) -> *mut in6_addr;
}
unsafe extern "C" {
    pub fn shim_sock_common_skc_v6_rcv_saddr_exists(sock_common: *mut sock_common) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff {
    pub len: ::core::ffi::c_uint,
    pub data: *mut ::core::ffi::c_uchar,
}
unsafe extern "C" {
    pub fn shim_sk_buff_len(sk_buff: *mut sk_buff) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sk_buff_len_user(sk_buff: *mut sk_buff) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sk_buff_len_exists(sk_buff: *mut sk_buff) -> bool;
}
unsafe extern "C" {
    pub fn shim_sk_buff_data(sk_buff: *mut sk_buff) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sk_buff_data_user(sk_buff: *mut sk_buff) -> *mut ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sk_buff_data_exists(sk_buff: *mut sk_buff) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff_list {
    pub next: *mut sk_buff,
    pub prev: *mut sk_buff,
}
unsafe extern "C" {
    pub fn shim_sk_buff_list_next(sk_buff_list: *mut sk_buff_list) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_list_next_user(sk_buff_list: *mut sk_buff_list) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_list_next_exists(sk_buff_list: *mut sk_buff_list) -> bool;
}
unsafe extern "C" {
    pub fn shim_sk_buff_list_prev(sk_buff_list: *mut sk_buff_list) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_list_prev_user(sk_buff_list: *mut sk_buff_list) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_list_prev_exists(sk_buff_list: *mut sk_buff_list) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sk_buff_head {
    pub next: *mut sk_buff,
    pub prev: *mut sk_buff,
    pub list: sk_buff_list,
    pub qlen: __u32,
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_next(sk_buff_head: *mut sk_buff_head) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_next_user(sk_buff_head: *mut sk_buff_head) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_next_exists(sk_buff_head: *mut sk_buff_head) -> bool;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_prev(sk_buff_head: *mut sk_buff_head) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_prev_user(sk_buff_head: *mut sk_buff_head) -> *mut sk_buff;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_prev_exists(sk_buff_head: *mut sk_buff_head) -> bool;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_list(sk_buff_head: *mut sk_buff_head) -> *mut sk_buff_list;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_list_user(sk_buff_head: *mut sk_buff_head) -> *mut sk_buff_list;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_list_exists(sk_buff_head: *mut sk_buff_head) -> bool;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_qlen(sk_buff_head: *mut sk_buff_head) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_qlen_user(sk_buff_head: *mut sk_buff_head) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_sk_buff_head_qlen_exists(sk_buff_head: *mut sk_buff_head) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct sock {
    pub __sk_common: sock_common,
    pub sk_protocol: __u8,
    pub sk_type: __u16,
    pub sk_receive_queue: sk_buff_head,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sock___pre_5_6 {
    pub sk_protocol: __u8,
}
unsafe extern "C" {
    pub fn shim_sock___pre_5_6_sk_protocol(
        sock___pre_5_6: *mut sock___pre_5_6,
    ) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock___pre_5_6_sk_protocol_exists(sock___pre_5_6: *mut sock___pre_5_6) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock___sk_common(sock: *mut sock) -> *mut sock_common;
}
unsafe extern "C" {
    pub fn shim_sock___sk_common_user(sock: *mut sock) -> *mut sock_common;
}
unsafe extern "C" {
    pub fn shim_sock___sk_common_exists(sock: *mut sock) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_sk_protocol(sock: *mut sock) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock_sk_protocol_user(sock: *mut sock) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_sock_sk_protocol_exists(sock: *mut sock) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_sk_type(sock: *mut sock) -> ::core::ffi::c_ushort;
}
unsafe extern "C" {
    pub fn shim_sock_sk_type_exists(sock: *mut sock) -> bool;
}
unsafe extern "C" {
    pub fn shim_sock_sk_receive_queue(sock: *mut sock) -> *mut sk_buff_head;
}
unsafe extern "C" {
    pub fn shim_sock_sk_receive_queue_user(sock: *mut sock) -> *mut sk_buff_head;
}
unsafe extern "C" {
    pub fn shim_sock_sk_receive_queue_exists(sock: *mut sock) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct socket {
    pub sk: *mut sock,
}
unsafe extern "C" {
    pub fn shim_socket_sk(socket: *mut socket) -> *mut sock;
}
unsafe extern "C" {
    pub fn shim_socket_sk_user(socket: *mut socket) -> *mut sock;
}
unsafe extern "C" {
    pub fn shim_socket_sk_exists(socket: *mut socket) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iovec {
    pub iov_base: *mut ::core::ffi::c_void,
    pub iov_len: __kernel_size_t,
}
unsafe extern "C" {
    pub fn shim_iovec_iov_base(iovec: *mut iovec) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_iovec_iov_base_user(iovec: *mut iovec) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_iovec_iov_base_exists(iovec: *mut iovec) -> bool;
}
unsafe extern "C" {
    pub fn shim_iovec_iov_len(iovec: *mut iovec) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_iovec_iov_len_user(iovec: *mut iovec) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_iovec_iov_len_exists(iovec: *mut iovec) -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_IOVEC() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_IOVEC_exists() -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_KVEC() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_KVEC_exists() -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_BVEC() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_BVEC_exists() -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_PIPE() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_PIPE_exists() -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_XARRAY() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_XARRAY_exists() -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_DISCARD() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_DISCARD_exists() -> bool;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_UBUF() -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iter_type_ITER_UBUF_exists() -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct page {
    pub flags: ::core::ffi::c_ulong,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct bio_vec {
    pub bv_page: *mut page,
    pub bv_len: ::core::ffi::c_uint,
    pub bv_offset: ::core::ffi::c_uint,
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_page(bio_vec: *mut bio_vec) -> *mut page;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_page_user(bio_vec: *mut bio_vec) -> *mut page;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_page_exists(bio_vec: *mut bio_vec) -> bool;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_len(bio_vec: *mut bio_vec) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_len_user(bio_vec: *mut bio_vec) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_len_exists(bio_vec: *mut bio_vec) -> bool;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_offset(bio_vec: *mut bio_vec) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_offset_user(bio_vec: *mut bio_vec) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_bio_vec_bv_offset_exists(bio_vec: *mut bio_vec) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct iov_iter {
    pub __bindgen_anon_1: iov_iter__bindgen_ty_1,
    pub count: size_t,
    pub __bindgen_anon_2: iov_iter__bindgen_ty_2,
    pub __bindgen_anon_3: iov_iter__bindgen_ty_3,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union iov_iter__bindgen_ty_1 {
    pub iter_type: u8_,
    pub type_: ::core::ffi::c_uint,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union iov_iter__bindgen_ty_2 {
    pub iov: *mut iovec,
    pub __iov: *mut iovec,
    pub ubuf: *mut ::core::ffi::c_void,
    pub bvec: *mut bio_vec,
}
#[repr(C)]
#[derive(Copy, Clone)]
pub union iov_iter__bindgen_ty_3 {
    pub nr_segs: ::core::ffi::c_ulong,
}
unsafe extern "C" {
    pub fn shim_iov_iter_iter_type(iov_iter: *mut iov_iter) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_iov_iter_iter_type_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_iov_iter_iter_type_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter_type(iov_iter: *mut iov_iter) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iov_iter_type_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_uint;
}
unsafe extern "C" {
    pub fn shim_iov_iter_type_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter_count(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_iov_iter_count_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_iov_iter_count_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter_nr_segs(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_iov_iter_nr_segs_user(iov_iter: *mut iov_iter) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_iov_iter_nr_segs_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter_ubuf(iov_iter: *mut iov_iter) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_iov_iter_ubuf_user(iov_iter: *mut iov_iter) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_iov_iter_ubuf_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter_iov(iov_iter: *mut iov_iter) -> *mut iovec;
}
unsafe extern "C" {
    pub fn shim_iov_iter_iov_user(iov_iter: *mut iov_iter) -> *mut iovec;
}
unsafe extern "C" {
    pub fn shim_iov_iter_iov_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter___iov(iov_iter: *mut iov_iter) -> *mut iovec;
}
unsafe extern "C" {
    pub fn shim_iov_iter___iov_user(iov_iter: *mut iov_iter) -> *mut iovec;
}
unsafe extern "C" {
    pub fn shim_iov_iter___iov_exists(iov_iter: *mut iov_iter) -> bool;
}
unsafe extern "C" {
    pub fn shim_iov_iter_bvec(iov_iter: *mut iov_iter) -> *mut bio_vec;
}
unsafe extern "C" {
    pub fn shim_iov_iter_bvec_user(iov_iter: *mut iov_iter) -> *mut bio_vec;
}
unsafe extern "C" {
    pub fn shim_iov_iter_bvec_exists(iov_iter: *mut iov_iter) -> bool;
}
#[repr(C)]
#[derive(Copy, Clone)]
pub struct msghdr {
    pub msg_name: *mut ::core::ffi::c_void,
    pub msg_namelen: ::core::ffi::c_int,
    pub msg_iter: iov_iter,
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_name(msghdr: *mut msghdr) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_name_user(msghdr: *mut msghdr) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_name_exists(msghdr: *mut msghdr) -> bool;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_namelen(msghdr: *mut msghdr) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_namelen_user(msghdr: *mut msghdr) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_namelen_exists(msghdr: *mut msghdr) -> bool;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_iter(msghdr: *mut msghdr) -> *mut iov_iter;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_iter_user(msghdr: *mut msghdr) -> *mut iov_iter;
}
unsafe extern "C" {
    pub fn shim_msghdr_msg_iter_exists(msghdr: *mut msghdr) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct user_msghdr {
    pub msg_name: *mut ::core::ffi::c_void,
    pub msg_namelen: ::core::ffi::c_int,
    pub msg_iov: *mut iovec,
    pub msg_iovlen: __kernel_size_t,
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_name(user_msghdr: *mut user_msghdr) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_name_user(
        user_msghdr: *mut user_msghdr,
    ) -> *mut ::core::ffi::c_void;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_name_exists(user_msghdr: *mut user_msghdr) -> bool;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_namelen(user_msghdr: *mut user_msghdr) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_namelen_user(user_msghdr: *mut user_msghdr) -> ::core::ffi::c_int;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_namelen_exists(user_msghdr: *mut user_msghdr) -> bool;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_iov(user_msghdr: *mut user_msghdr) -> *mut iovec;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_iov_user(user_msghdr: *mut user_msghdr) -> *mut iovec;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_iov_exists(user_msghdr: *mut user_msghdr) -> bool;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_iovlen(user_msghdr: *mut user_msghdr) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_iovlen_user(user_msghdr: *mut user_msghdr) -> ::core::ffi::c_ulong;
}
unsafe extern "C" {
    pub fn shim_user_msghdr_msg_iovlen_exists(user_msghdr: *mut user_msghdr) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct kernel_clone_args {
    pub flags: u64_,
}
unsafe extern "C" {
    pub fn shim_kernel_clone_args_flags(
        kernel_clone_args: *mut kernel_clone_args,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_kernel_clone_args_flags_user(
        kernel_clone_args: *mut kernel_clone_args,
    ) -> ::core::ffi::c_ulonglong;
}
unsafe extern "C" {
    pub fn shim_kernel_clone_args_flags_exists(kernel_clone_args: *mut kernel_clone_args) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct sqe_submit {
    pub sqe: *const io_uring_sqe,
}
unsafe extern "C" {
    pub fn shim_sqe_submit_sqe(sqe_submit: *mut sqe_submit) -> *const io_uring_sqe;
}
unsafe extern "C" {
    pub fn shim_sqe_submit_sqe_user(sqe_submit: *mut sqe_submit) -> *const io_uring_sqe;
}
unsafe extern "C" {
    pub fn shim_sqe_submit_sqe_exists(sqe_submit: *mut sqe_submit) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_uring_sqe {
    pub opcode: __u8,
}
unsafe extern "C" {
    pub fn shim_io_uring_sqe_opcode(io_uring_sqe: *mut io_uring_sqe) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_io_uring_sqe_opcode_user(io_uring_sqe: *mut io_uring_sqe) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_io_uring_sqe_opcode_exists(io_uring_sqe: *mut io_uring_sqe) -> bool;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct io_kiocb {
    pub opcode: u8_,
}
unsafe extern "C" {
    pub fn shim_io_kiocb_opcode(io_kiocb: *mut io_kiocb) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_io_kiocb_opcode_user(io_kiocb: *mut io_kiocb) -> ::core::ffi::c_uchar;
}
unsafe extern "C" {
    pub fn shim_io_kiocb_opcode_exists(io_kiocb: *mut io_kiocb) -> bool;
}
