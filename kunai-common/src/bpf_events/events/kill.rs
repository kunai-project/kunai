use kunai_macros::StrEnum;

use crate::{
    bpf_events::{Event, TaskInfo},
    macros::not_bpf_target_code,
};

pub type KillEvent = Event<KillData>;

#[repr(C)]
pub struct KillData {
    pub signal: u8,
    pub target: TaskInfo,
}

#[allow(non_camel_case_types)]
#[derive(StrEnum, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Values to pass as first argument to prctl()
pub enum Signal {
    SIGHUP = 1,
    SIGINT = 2,
    SIGQUIT = 3,
    SIGILL = 4,
    SIGTRAP = 5,
    SIGABRT = 6,
    //SIGIOT = 6,
    SIGBUS = 7,
    SIGFPE = 8,
    SIGKILL = 9,
    SIGUSR1 = 10,
    SIGSEGV = 11,
    SIGUSR2 = 12,
    SIGPIPE = 13,
    SIGALRM = 14,
    SIGTERM = 15,
    SIGSTKFLT = 16,
    SIGCHLD = 17,
    SIGCONT = 18,
    SIGSTOP = 19,
    SIGTSTP = 20,
    SIGTTIN = 21,
    SIGTTOU = 22,
    SIGURG = 23,
    SIGXCPU = 24,
    SIGXFSZ = 25,
    SIGVTALRM = 26,
    SIGPROF = 27,
    SIGWINCH = 28,
    //SIGIO = 29,
    SIGPOLL = 29,
    //SIGLOST = 29,
    SIGPWR = 30,
    SIGSYS = 31,
    //SIGUNUSED = 31,
    SIGRT0 = 34,
    SIGRT1 = 35,
    SIGRT2 = 36,
    SIGRT3 = 37,
    SIGRT4 = 38,
    SIGRT5 = 39,
    SIGRT6 = 40,
    SIGRT7 = 41,
    SIGRT8 = 42,
    SIGRT9 = 43,
    SIGRT10 = 44,
    SIGRT11 = 45,
    SIGRT12 = 46,
    SIGRT13 = 47,
    SIGRT14 = 48,
    SIGRT15 = 49,
    SIGRT16 = 50,
    SIGRT17 = 51,
    SIGRT18 = 52,
    SIGRT19 = 53,
    SIGRT20 = 54,
    SIGRT21 = 55,
    SIGRT22 = 56,
    SIGRT23 = 57,
    SIGRT24 = 58,
    SIGRT25 = 59,
    SIGRT26 = 60,
    SIGRT27 = 61,
    SIGRT28 = 62,
    SIGRT29 = 63,
    SIGRT30 = 64,
}

not_bpf_target_code! {
    impl Signal{
        pub fn from_uint_to_string<T:Into<u64>>(u: T) -> String{
            let u:u64 = u.into();
            Signal::try_from_uint(u)
            .map(|o| o.as_str().into())
            .unwrap_or(format!("SIG({})", u))
        }
    }
}
