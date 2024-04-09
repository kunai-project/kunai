use aya_ebpf::{
    macros::map,
    maps::{Array, LruPerCpuHashMap},
    EbpfContext,
};

use crate::{
    bpf_events::{error, ErrorEvent},
    string::String,
};

#[allow(unused_imports)]
use super::*;

#[map]
pub static mut ERRORS: LruPerCpuHashMap<u32, ErrorEvent> =
    LruPerCpuHashMap::with_max_entries(16, 0);

#[map]
pub static mut I_ERROR: Array<u32> = Array::with_max_entries(1, 0);

const SIZE: usize = ErrorEvent::size_of();
pub static EMPTY_ERROR: [u8; SIZE] = [0; SIZE];

#[macro_export]
macro_rules! probe_name {
    () => {{
        const fn index(skip: &'static str, st: &'static str) -> usize {
            let mut i = 0;
            let skip = skip.as_bytes();
            let st = st.as_bytes();

            // we cannot skip something larger than string
            if skip.len() > st.len() {
                return i;
            }

            loop {
                if i == skip.len() || i == st.len() || skip[i] != st[i] {
                    break;
                }

                i += 1
            }

            i
        }

        const fn string_loc<const N: usize>(st: &'static str) -> kunai_common::string::String<N> {
            let mut s = kunai_common::string::String { s: [0; N], len: 0 };
            let mut i = 0;
            let i_src = index("src/", st);
            let ext = ".rs";
            let bytes = st.as_bytes();

            loop {
                let i_bytes = i_src + i;

                // we leave a 0 to terminate the string if string
                // larger than capacity
                if i == s.cap() - 1 || i_bytes >= (st.len() - ext.len()) {
                    break;
                }

                if bytes[i_bytes] == b'/' {
                    let mut k = 0;
                    loop {
                        if k == 2 {
                            break;
                        }
                        if s.len < N {
                            s.s[s.len] = b':';
                            s.len += 1;
                        }
                        k += 1;
                    }
                } else {
                    s.s[s.len] = bytes[i_src + i];
                }

                s.len += 1;
                i += 1
            }
            s
        }
        string_loc(file!())
    }};
}

pub struct Args {
    pub line: u32,
    pub location: String<32>,
    pub message: Option<String<64>>,
    pub err: Option<ProbeError>,
    pub level: error::Level,
}

#[inline(always)]
pub unsafe fn error_with_args<C: EbpfContext>(ctx: &C, args: &Args) {
    /*let mut i = match I_ERROR.get(0) {
        Some(&u) => u,
        None => 0,
    };*/
    let _ = ERRORS.insert(&0, &(*(EMPTY_ERROR.as_ptr() as *const ErrorEvent)), 0);
    if let Some(e) = ERRORS.get_ptr_mut(&0) {
        let e = &mut *e;
        e.init_with_level(args.level);
        e.info.etype = bpf_events::Type::Error;
        e.data.location.copy_from(&args.location);
        e.data.line = args.line;
        e.data.error = args.err;
        e.data.message = args.message;

        bpf_events::pipe_error(ctx, e);
        /*i = i.wrapping_add(1);
        I_ERROR.get_ptr_mut(0).map(|old| *old = i);*/
    }
}

#[macro_export]
macro_rules! _error {
    ($ctx:expr, $msg:literal, $err:expr, $level:expr) => {{
        unsafe {
            const _PROBE_NAME: kunai_common::string::String<32> = $crate::probe_name!();
            const _MSG: kunai_common::string::String<64> = kunai_common::string::from_static($msg);

            let args = kunai_common::errors::Args {
                line: core::line!(),
                location: _PROBE_NAME,
                message: {
                    if !$msg.is_empty() {
                        Some(_MSG)
                    } else {
                        None
                    }
                },
                err: $err,
                level: $level,
            };

            kunai_common::errors::error_with_args($ctx, &args);
        };
    }};
}

#[macro_export]
macro_rules! error {
    ($ctx:expr, $err:expr) => {{
        $crate::error!($ctx, "", $err)
    }};

    ($ctx:expr, $msg:literal, $err:expr) => {{
        $crate::_error!(
            $ctx,
            $msg,
            Some($err),
            kunai_common::bpf_events::error::Level::Error
        );
    }};
}

#[macro_export]
macro_rules! error_msg {
    ($ctx:expr, $msg:literal) => {
        $crate::_error!(
            $ctx,
            $msg,
            None,
            kunai_common::bpf_events::error::Level::Error
        )
    };
}

#[macro_export]
macro_rules! warn {
    ($ctx:expr, $err:expr) => {
        $crate::warn!($ctx, "", $err);
    };

    ($ctx:expr, $msg:literal, $err:expr) => {
        $crate::_error!(
            $ctx,
            $msg,
            Some($err),
            kunai_common::bpf_events::error::Level::Warn
        );
    };
}

#[macro_export]
macro_rules! warn_msg {
    ($ctx:expr, $msg:literal) => {
        $crate::_error!(
            $ctx,
            $msg,
            None,
            kunai_common::bpf_events::error::Level::Warn
        )
    };
}
