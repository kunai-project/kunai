use aya_bpf::macros::*;

use kunai_common::{
    alloc,
    bpf_events::*,
    co_re,
    consts::*,
    error, error_msg,
    errors::{self, *},
    inspect_err,
    path::{self, *},
    utils::*,
    warn, warn_msg,
};

#[cfg(feature = "debug")]
mod debug;

mod bpf;
mod bpf_socket;
mod clone;
mod connect;
mod dns;
mod execve;
mod exit;
mod fd_install;
mod fs;
mod init_module;
mod mmap;
mod mount;
mod mprotect;
mod prctl;
mod schedule;
mod send_data;

/// macro to track ignored results
macro_rules! ignore_result {
    ($res:expr) => {{
        let _ = $res;
    }};
}

use ignore_result;

/// kprobe_arg macro retrieves the Nth argument (starting from 0) for a kprobe
/// # Example
///
/// ```
/// let sk = co_re::sock::from_ptr(kprobe_arg!(entry_ctx, 0)?);
/// let prog = co_re::bpf_prog::from_ptr(kprobe_arg!(entry_ctx, 1)?);
/// ```
macro_rules! kprobe_arg {
    ($ctx: expr, $i: literal) => {
        $ctx.arg($i)
            .ok_or(kunai_common::errors::ProbeError::KProbeArgFailure)
    };
}

use kprobe_arg;

/// core_read_kernel macro can be used to access structure fields
/// Rust function field accessors must be defined and must return
/// Option<T>. This macro returns Result<T, ProbeError>
///
/// # Example
///
///```
///let pid = core_read_kernel!(task_struct, pid);
///```
macro_rules! core_read_kernel {
    ($struc:expr, $field:ident) => {
        $struc
            .$field()
            .ok_or(kunai_common::errors::ProbeError::CoReFieldMissing)
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        $struc
            .$first()
            $(
            .and_then(|r| r.$rest())
            )*
            .ok_or(kunai_common::errors::ProbeError::CoReFieldMissing)
    };
}

use core_read_kernel;

/// core_read_user macro can be used to access structure fields
macro_rules! core_read_user {
    ($struc:expr, $field:ident) => {
        paste::item!{
        $struc
            .[<$field _user>]()
            .ok_or(kunai_common::errors::ProbeError::CoReFieldMissing)
        }
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        paste::item!{
        $struc
            .[<$first _user>]()
            $(
            .and_then(|r| r.[<$rest _user>]())
            )*
            .ok_or(kunai_common::errors::ProbeError::CoReFieldMissing)
        }
    };
}

use core_read_user;

/// convenient macro to get Kunai config
macro_rules! get_cfg {
    () => {
        kunai_common::config::config().ok_or(ProbeError::Config)
    };
}

use get_cfg;
