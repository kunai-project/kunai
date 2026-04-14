use crate::{bpf_events::Event, errors::ProbeError, string::String};

pub type LogEvent = Event<LogData>;

#[repr(C)]
#[derive(Clone, Copy)]
pub enum Level {
    Info,
    Warn,
    Error,
}

#[repr(C)]
pub struct LogData {
    pub location: String<32>,
    pub line: u32,
    pub level: Level,
    pub error: Option<ProbeError>,
    pub message: Option<String<64>>,
}

#[cfg(target_arch = "bpf")]
mod bpf {

    use super::*;
    use crate::string;
    use crate::string::String;
    use aya_ebpf::helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid};

    const DEFAULT_COMM: String<16> = string::from_static("?");

    impl LogEvent {
        #[inline(always)]
        pub fn init_with_level(&mut self, level: Level) {
            let pid_tgid = bpf_get_current_pid_tgid();
            self.data.level = level;
            self.info.process.pid = pid_tgid as i32;
            self.info.process.tgid = (pid_tgid >> 32) as i32;
            self.info.process.comm = bpf_get_current_comm().unwrap_or(DEFAULT_COMM.s);
        }
    }
}

#[cfg(feature = "user")]
mod user {
    use super::*;
    
    impl core::fmt::Display for LogEvent {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(
                f,
                "{} line={} pid={} tgid={} comm={}",
                self.data.location.as_str(),
                self.data.line,
                self.info.process.pid,
                self.info.process.tgid,
                self.info.process.comm_str(),
            )?;

            if let Some(msg) = self.data.message.as_ref() {
                write!(f, " {}", msg,)?;
            }

            if let Some(e) = self.data.error.as_ref() {
                write!(f, " {}: {}", e.name(), e.description())?;
            }
            Ok(())
        }
    }
}
