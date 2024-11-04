use super::Type;
use crate::macros::not_bpf_target_code;

// events we want to be accesible
mod connect;
pub use connect::*;
mod execve;
pub use execve::*;
mod clone;
pub use clone::*;
mod mmap;
pub use mmap::*;
mod mprotect;
pub use mprotect::*;
mod dns_query;
pub use dns_query::*;
mod send_entropy;
pub use send_entropy::*;
mod init_module;
pub use init_module::*;
mod exit;
pub use exit::*;
mod fs;
pub use fs::*;
mod bpf;
pub use bpf::*;
mod schedule;
pub use schedule::*;
mod mount;
pub use mount::*;
mod prctl;
pub use prctl::*;
pub mod error;
pub use error::{ErrorData, ErrorEvent};
mod syscore_resume;
pub use syscore_resume::*;
mod kill;
pub use kill::*;
mod ptrace;
pub use ptrace::*;

// prevent using correlation event in bpf code
not_bpf_target_code! {
    mod correlation;
    pub use correlation::*;
}

// used to pipe events to userland
mod perfs;
pub use perfs::*;

pub const MAX_BPF_EVENT_SIZE: usize = max_bpf_event_size();

/// function defined so that it generates an error in case of
/// new Type created and we forgot to take it into account
const fn max_bpf_event_size() -> usize {
    let mut i = 0;
    let variants = Type::variants();
    let mut max = 0;
    loop {
        if i == variants.len() {
            break;
        }
        let size = match variants[i] {
            Type::Execve | Type::ExecveScript => ExecveEvent::size_of(),
            Type::TaskSched => ScheduleEvent::size_of(),
            Type::Exit | Type::ExitGroup => ExitEvent::size_of(),
            Type::Clone => CloneEvent::size_of(),
            Type::Prctl => PrctlEvent::size_of(),
            Type::Kill => KillEvent::size_of(),
            Type::Ptrace => PtraceEvent::size_of(),
            Type::InitModule => InitModuleEvent::size_of(),
            Type::BpfProgLoad => BpfProgLoadEvent::size_of(),
            Type::BpfSocketFilter => BpfSocketFilterEvent::size_of(),
            Type::MprotectExec => MprotectEvent::size_of(),
            Type::MmapExec => MmapExecEvent::size_of(),
            Type::Connect => ConnectEvent::size_of(),
            Type::DnsQuery => DnsQueryEvent::size_of(),
            Type::SendData => SendEntropyEvent::size_of(),
            Type::Read
            | Type::ReadConfig
            | Type::Write
            | Type::WriteConfig
            | Type::WriteAndClose => FileEvent::size_of(),
            Type::FileRename => FileRenameEvent::size_of(),
            Type::FileUnlink => UnlinkEvent::size_of(),
            Type::Error => ErrorEvent::size_of(),
            Type::SyscoreResume => SysCoreResumeEvent::size_of(),
            // these are event types only used in user land
            Type::Unknown
            | Type::EndConfigurable
            | Type::Correlation
            | Type::CacheHash
            | Type::Max
            | Type::FileScan => 0,
            // never handle _ pattern otherwise this function loses all interest
        };
        if size > max {
            max = size;
        }
        i += 1;
    }
    max
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::bpf_events::ExecveEvent;

    #[test]
    fn test_max_bpf_event_size() {
        // for the time being ExecveEvent is known to be the biggest
        // event. This is subject to change and it might be normal
        // this test fails in the future
        assert_eq!(max_bpf_event_size(), ExecveEvent::size_of())
    }
}
