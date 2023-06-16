use crate::alloc;
use crate::error::{self, *};
use crate::util::*;

use aya_bpf::macros::*;
use aya_log_ebpf::*;

use kunai_common::{
    bpf_utils::*,
    co_re, config,
    consts::*,
    events::{self, *},
    inspect_err,
    path::{self, *},
    syscalls::*,
};

#[cfg(debug)]
mod debug;

mod bpf;
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
mod save;
mod schedule;
mod send_data;

macro_rules! ignore_result {
    ($res:expr) => {
        match $res {
            Ok(_) | Err(_) => {}
        }
    };
}

use ignore_result;

macro_rules! kprobe_arg {
    ($ctx: expr, $i: literal) => {
        $ctx.arg($i)
            .ok_or($crate::error::ProbeError::KProbeArgFailure)
    };
}

use kprobe_arg;

macro_rules! core_read_kernel {
    ($struc:expr, $field:ident) => {
        $struc
            .$field()
            .ok_or($crate::error::ProbeError::CoReFieldMissing)
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        $struc
            .$first()
            $(
            .and_then(|r| r.$rest())
            )*
            .ok_or($crate::error::ProbeError::CoReFieldMissing)
    };
}

use core_read_kernel;

macro_rules! core_read_user {
    ($struc:expr, $field:ident) => {
        paste::item!{
        $struc
            .[<$field _user>]()
            .ok_or($crate::error::ProbeError::CoReFieldMissing)
        }
    };

    ($struc:expr, $first:ident, $($rest: ident),*) => {
        paste::item!{
        $struc
            .[<$first _user>]()
            $(
            .and_then(|r| r.[<$rest _user>]())
            )*
            .ok_or($crate::error::ProbeError::CoReFieldMissing)
        }
    };
}

use core_read_user;

macro_rules! get_cfg {
    () => {
        kunai_common::config::config().ok_or(ProbeError::Config)
    };
}

use get_cfg;
