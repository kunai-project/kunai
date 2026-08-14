#[allow(non_camel_case_types)]
#[allow(non_upper_case_globals)]
#[allow(dead_code)]
mod gen;
pub use gen::timespec64;

mod core_task_struct;
pub use core_task_struct::*;

mod core_cred;
pub use core_cred::*;

mod core_mm_struct;
pub use core_mm_struct::*;

mod core_fs;
pub use core_fs::*;

mod core_exec;
pub use core_exec::*;

mod core_bpf;
pub use core_bpf::*;

mod core_socket_filters;
pub use core_socket_filters::*;

mod core_lkm;
pub use core_lkm::*;

mod core_sock;
pub use core_sock::*;

mod core_iov;
pub use core_iov::*;

mod core_ns;
pub use core_ns::*;

mod core_cgroup;
pub use core_cgroup::*;

mod core_kernfs;
pub use core_kernfs::*;

mod core_clone_args;
pub use core_clone_args::*;

mod core_files_struct;
pub use core_files_struct::*;

mod core_page;
pub use core_page::*;

mod core_io_uring;
pub use core_io_uring::*;

#[derive(Clone, Copy)]
pub struct CoRe<P> {
    ptr: *const P,
}

impl<P> PartialEq for CoRe<P> {
    fn eq(&self, other: &Self) -> bool {
        self.ptr == other.ptr
    }
}

impl<P> From<*mut P> for CoRe<P> {
    fn from(value: *mut P) -> Self {
        Self::from_ptr(value)
    }
}

impl<P> From<*const P> for CoRe<P> {
    fn from(value: *const P) -> Self {
        Self::from_ptr(value)
    }
}

impl<P> CoRe<P> {
    #[inline(always)]
    pub fn is_null(&self) -> bool {
        self.ptr.is_null()
    }

    pub fn as_ptr(&self) -> *const P {
        self.ptr
    }

    fn as_ptr_mut(&self) -> *mut P {
        self.ptr as *mut _
    }

    pub fn from_ptr(ptr: *const P) -> Self {
        CoRe {
            ptr: ptr as *const _,
        }
    }
}

/// Generates a safe accessor for kernel struct fields.
///
/// Creates an `unsafe fn` that reads a field via shim functions, returning
/// `Option<$ret>`. Returns `None` if the pointer is null or the field doesn't
/// exist in the current kernel version.
///
/// The function checks `self.is_null()`, then calls `shim_$struct_$member_exists`
/// and `shim_$struct_$member` to safely read the field.
///
/// # Patterns
///
/// - `rust_shim_kernel_impl!(task_struct, flags, u32)` - public method named `flags`
/// - `rust_shim_kernel_impl!(pub, task_struct, tgid, pid_t)` - explicit visibility
/// - `rust_shim_kernel_impl!(pub, my_name, task_struct, comm, *mut u8)` - custom name
///
/// # Safety
///
/// The generated function is `unsafe`. Callers must ensure the `CoRe` pointer
/// is valid and the kernel struct is not modified during access.
macro_rules! rust_shim_kernel_impl {
    ($struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl! (pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $struct:ident, $member:ident, $ret:ty) => {
        rust_shim_kernel_impl! ($pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $fn_name:ident, $struct: ident, $member:ident, $ret:ty) => {
        #[inline(always)]
        #[allow(clippy::len_without_is_empty)]
        $pub unsafe fn $fn_name(&self) -> Option<$ret> {
            if !self.is_null()
                && paste::paste! {[<shim_ $struct _ $member _exists>]}(self.as_ptr_mut())
            {
                return Some(paste::paste! {[<shim_ $struct _ $member>]}(self.as_ptr_mut()).into());
            }
            None
        }
    };
}

pub(crate) use rust_shim_kernel_impl;

/// Generates a userspace accessor for kernel struct fields.
///
/// Similar to [`rust_shim_kernel_impl`] but generates functions with `_user` suffix
/// that use userspace-compatible shim functions.
///
/// # Patterns
///
/// - `rust_shim_user_impl!(pub, task_struct, tgid, pid_t)` - explicit visibility
/// - `rust_shim_user_impl!(pub, my_name, task_struct, comm, *mut u8)` - custom name with `_user` suffix
///
/// # Safety
///
/// The generated function is `unsafe`. Callers must ensure the `CoRe` pointer
/// is valid and the kernel struct is not modified during access.
macro_rules! rust_shim_user_impl {
    ($pub:vis, $struct:ident, $member:ident, $ret:ty) => {
        rust_shim_user_impl! ($pub, $member, $struct, $member, $ret);
    };

    ($pub:vis, $fn_name:ident, $struct: ident, $member:ident, $ret:ty) => {
        paste::item!{
        #[inline(always)]
        $pub unsafe fn [<$fn_name _user>] (&self) -> Option<$ret> {
            if !self.is_null()
                && [<shim_ $struct _ $member _exists>](self.as_ptr_mut())
            {
                return Some(paste::paste! {[<shim_ $struct _ $member _user>]}(self.as_ptr_mut()).into());
            }
            None
        }
        }
    };
}

pub(crate) use rust_shim_user_impl;

macro_rules! core_read_kernel {
    ($struc:expr, $field:ident) => {
        $struc
            .$field()
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        $struc
            .$first()
            $(
            .and_then(|r| r.$rest())
            )*
    };
}

pub(crate) use core_read_kernel;
