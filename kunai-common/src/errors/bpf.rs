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

        const fn string_loc<const N: usize>(st: &'static str) -> $crate::string::String<N> {
            let mut s = $crate::string::String { s: [0; N], len: 0 };
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

                // if it is path separator we replace by ::
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
                    // we just copy other characters
                    s.s[s.len] = bytes[i_src + i];
                    s.len += 1;
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
