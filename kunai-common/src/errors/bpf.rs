use aya_ebpf::{macros::map, maps::LruPerCpuHashMap, EbpfContext};

use crate::{
    bpf_events::{log, LogEvent},
    string::String,
};

#[allow(unused_imports)]
use super::*;

#[map]
pub static mut LOGS: LruPerCpuHashMap<u32, LogEvent> = LruPerCpuHashMap::with_max_entries(16, 0);

const SIZE: usize = LogEvent::size_of();
pub static EMPTY_LOG: [u8; SIZE] = [0; SIZE];

#[macro_export]
macro_rules! probe_name {
    () => {{
        const fn index_rev_search(needle: &'static str, haystack: &'static str) -> usize {
            let needle = needle.as_bytes();
            let haystack = haystack.as_bytes();
            let mut i = haystack.len() - needle.len() - 1;

            while i > 0 {
                let mut k = 0;
                while k < needle.len() {
                    if haystack[i + k] != needle[k] {
                        break;
                    }

                    if k == needle.len() - 1 {
                        return i;
                    }
                    k += 1
                }
                i -= 1
            }

            i
        }

        const fn string_loc<const N: usize>(st: &'static str) -> $crate::string::String<N> {
            let src = "src/";
            let ext = ".rs";
            let mut s = $crate::string::String::new();
            let i_src = index_rev_search(src, st) + src.len();

            let bytes = st.as_bytes();

            let mut i = i_src;
            'outer: while i < i_src + s.cap() && i < bytes.len() - ext.len() {
                let b = bytes[i];
                // if it is path separator we replace by ::
                if b == b'/' {
                    let mut k = 0;
                    while k < 2 {
                        if s.push_byte(b':').is_err() {
                            break 'outer;
                        }
                        k += 1
                    }
                } else {
                    // we just copy other characters
                    if s.push_byte(b).is_err() {
                        break;
                    }
                }

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
    pub level: log::Level,
}

#[inline(always)]
pub unsafe fn log_with_args<C: EbpfContext>(ctx: &C, args: &Args) {
    let _ = LOGS.insert(&0, &(*(EMPTY_LOG.as_ptr() as *const LogEvent)), 0);
    if let Some(e) = LOGS.get_ptr_mut(&0) {
        let e = &mut *e;
        e.init_with_level(args.level);
        e.info.etype = bpf_events::Type::Log;
        e.data.location.copy_from(&args.location);
        e.data.line = args.line;
        e.data.error = args.err;
        e.data.message = args.message;

        bpf_events::pipe_log(ctx, e);
    }
}

#[macro_export]
macro_rules! log {
    ($ctx:expr, $msg:literal, $err:expr, $level:expr) => {{
        unsafe {
            const _PROBE_NAME: $crate::string::String<32> = $crate::probe_name!();
            const _MSG: $crate::string::String<64> = $crate::string::from_static($msg);

            let args = $crate::errors::Args {
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

            $crate::errors::log_with_args($ctx, &args);
        };
    }};
}

#[macro_export]
macro_rules! error {
    // literal must be evaluated first
    ($ctx:expr, $msg:literal) => {
        $crate::log!($ctx, $msg, None, $crate::bpf_events::log::Level::Error)
    };

    ($ctx:expr, $err:expr) => {
        $crate::log!($ctx, "", Some($err), $crate::bpf_events::log::Level::Error)
    };

    ($ctx:expr, $msg:literal, $err:expr) => {
        $crate::log!(
            $ctx,
            $msg,
            Some($err),
            $crate::bpf_events::log::Level::Error
        );
    };
}

#[macro_export]
macro_rules! warn {
    // literal must be evaluated first
    ($ctx:expr, $msg:literal) => {
        $crate::log!($ctx, $msg, None, $crate::bpf_events::log::Level::Warn)
    };

    ($ctx:expr, $err:expr) => {
        $crate::log!($ctx, "", Some($err), $crate::bpf_events::log::Level::Warn);
    };

    ($ctx:expr, $msg:literal, $err:expr) => {
        $crate::log!($ctx, $msg, Some($err), $crate::bpf_events::log::Level::Warn);
    };
}
