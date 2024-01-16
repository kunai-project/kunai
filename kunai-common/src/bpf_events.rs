use crate::macros::test_flag;
use crate::uuid::{TaskUuid, Uuid};
use crate::{bpf_target_code, not_bpf_target_code};

not_bpf_target_code! {
    use std::vec::Vec;
    use thiserror::Error;
}

bpf_target_code! {
    use crate::co_re::core_read_kernel;
    use crate::co_re::task_struct;
    use crate::helpers::{bpf_get_current_task, bpf_ktime_get_ns};
    use kunai_macros::BpfError;
}

pub const COMM_SIZE: usize = 16;
pub const COMM_DEFAULT: [i8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// events we want to be accesible
mod connect;
pub use connect::*;
mod execve;
pub use execve::*;
mod clone;
pub use clone::*;
mod mmap;
use kunai_macros::StrEnum;
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

// prevent using correlation event in bpf code
not_bpf_target_code! {
    mod correlation;
    pub use correlation::*;
}

// used to pipe events to userland
mod perfs;
pub use perfs::*;

#[repr(u32)]
#[derive(StrEnum, Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Type {
    #[str("unknown")]
    Unknown = 0,

    // process events
    #[str("execve")]
    Execve,
    #[str("execve_script")]
    ExecveScript,
    #[str("task_sched")]
    TaskSched,
    #[str("exit")]
    Exit,
    #[str("exit_group")]
    ExitGroup,
    #[str("clone")]
    Clone,
    #[str("prctl")]
    Prctl,

    // stuff loaded in kernel
    #[str("init_module")]
    InitModule = 20,
    #[str("bpf_prog_load")]
    BpfProgLoad,
    #[str("bpf_socket_filter")]
    BpfSocketFilter,
    //#[str("bpf_socket_prog")]
    //BpfSocketProg,

    // memory stuffs
    #[str("mprotect_exec")]
    MprotectExec = 40,
    #[str("mmap_exec")]
    MmapExec,

    // networking events
    #[str("connect")]
    Connect = 60,
    #[str("dns_query")]
    DnsQuery,
    #[str("send_data")]
    SendData,

    // filesystem events
    #[str("mount")]
    Mount = 80,
    #[str("read")]
    Read,
    #[str("read_config")]
    ReadConfig,
    #[str("write")]
    Write,
    #[str("write_config")]
    WriteConfig,
    #[str("file_rename")]
    FileRename,
    #[str("file_unlink")]
    FileUnlink,

    // Materialize end of possible events
    #[str("end_event")]
    EndEvents = 1000,

    // specific events
    #[str("correlation")]
    Correlation,
    #[str("cache_hash")]
    CacheHash,

    // !!! all new event types must be put before max
    #[str("max")]
    Max,
}

impl Default for Type {
    fn default() -> Self {
        Self::Unknown
    }
}

impl Type {
    pub fn is_configurable(&self) -> bool {
        *self > Self::Unknown && *self < Self::EndEvents
    }
}

impl Type {
    pub fn id(&self) -> u32 {
        *self as u32
    }
}

not_bpf_target_code! {
    use std::fmt::Display;
    use aya::Pod;

    unsafe impl Pod for Type {}

    impl Display for Type {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}", self.as_str())
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct Namespaces {
    pub mnt: u32,
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskInfo {
    pub flags: u32,
    pub comm: [u8; COMM_SIZE],
    pub uid: u32,
    pub gid: u32,
    // task group id
    // when program is single threaded tgid == pid
    pub tgid: i32,
    // task pid -> pid of the thread
    pub pid: i32,
    // task group uuid -> used to group tasks
    pub tg_uuid: TaskUuid,
    pub namespaces: Namespaces,
    pub start_time: u64,
}

impl TaskInfo {
    pub fn comm_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.comm[..]) }
    }

    pub fn is_kernel_thread(&self) -> bool {
        test_flag!(self.flags, 0x00200000)
    }

    not_bpf_target_code! {
        pub fn comm_string(&self) -> std::string::String {
            crate::utils::cstr_to_string(self.comm)
        }
    }
}

bpf_target_code! {

    #[derive(BpfError)]
    pub enum Error {
        #[error("flags field is missing")]
        FlagFieldMissing,
        #[error("pid field is missing")]
        PidFieldMissing,
        #[error("tgid field is missing")]
        TgidFieldMissing,
        #[error("cred field is missing")]
        CredFieldMissing,
        #[error("real_parent field is missing")]
        RealParentFieldMissing,
        #[error("boot time field is missing")]
        BootTimeMissing,
        #[error("group_leader field is missing")]
        GroupLeaderMissing,
        #[error("comm field is missing")]
        CommMissing,
        #[error("mnt_namespace")]
        MntNamespaceFailure,
    }

}

bpf_target_code! {
    impl TaskInfo {
        /// # Safety
        /// * task must be a pointer to a valid task_struct
        #[inline(always)]
        pub unsafe fn from_task(&mut self, task: task_struct) -> Result<(), Error> {
            // flags
            self.flags = task.flags().ok_or(Error::FlagFieldMissing)?;

            // process start time
            self.start_time = task.start_boottime().ok_or(Error::BootTimeMissing)?;
            self.tgid = task.tgid().ok_or(Error::TgidFieldMissing)?;
            self.pid = task.pid().ok_or(Error::PidFieldMissing)?;

            // the leader structure member points to the task leader of the thread group
            let leader = task.group_leader().ok_or(Error::GroupLeaderMissing)?;

            // start_time is the time in jiffies and is contained in /proc/$pid/stat
            // file -> this way we can also compute unique ID from procfs
            self.tg_uuid.init(
                leader.start_boottime().ok_or(Error::BootTimeMissing)?,
                self.tgid as u32,
            );

            // copy comm
            self.comm = task.comm_array().ok_or(Error::CommMissing)?;

            // if task_struct is valid cannot be null
            self.uid = task.cred().ok_or(Error::CredFieldMissing)?.uid();
            self.gid = task.cred().ok_or(Error::CredFieldMissing)?.gid();

            self.namespaces.mnt = core_read_kernel!(task, nsproxy, mnt_ns, ns, inum).ok_or(Error::MntNamespaceFailure)?;

            Ok(())
        }
    }
}

#[repr(C)]
#[derive(Default, Debug, Clone, Copy)]
pub struct EventInfo {
    pub etype: Type,
    // source process relate information
    pub process: TaskInfo,
    // parent process related information
    pub parent: TaskInfo,
    // event uuid
    pub uuid: Uuid,
    // identify batch number (set in userland)
    pub batch: usize,
    // time elapsed since system boot in nanoseconds.
    // The time during the system was suspended is included.
    // set by using bpf_ktime_get_boot_ns()
    pub timestamp: u64,
}

impl EventInfo {
    pub fn set_uuid_random(&mut self, rand: u32) {
        // this is used for final Uuid calculation
        self.process.tg_uuid.random = rand;
        self.parent.tg_uuid.random = rand;
    }

    pub fn switch_type(&mut self, new: Type) {
        self.etype = new
    }
}

#[cfg(target_arch = "bpf")]
impl EventInfo {
    #[inline(always)]
    pub(crate) unsafe fn init(&mut self, t: Type, task: task_struct) -> Result<(), Error> {
        self.etype = t;

        // create a new Uuid for event
        self.uuid = Uuid::new_random();

        if !task.is_null() {
            self.process.from_task(task)?;
            self.parent
                .from_task(task.real_parent().ok_or(Error::RealParentFieldMissing)?)?;
        }

        self.timestamp = bpf_ktime_get_ns();

        Ok(())
    }
}

#[repr(C)]
pub struct Event<T> {
    // don't move info elsewhere than in the beginning of the struct
    // the decoder relies on that offset to read EventInfo
    pub info: EventInfo,
    pub data: T,
}

impl<T> Event<T> {
    #[inline]
    pub const fn size_of() -> usize {
        core::mem::size_of::<Event<T>>()
    }

    #[inline]
    pub fn ty(&self) -> Type {
        self.info.etype
    }

    #[inline]
    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    #[inline]
    pub fn as_ptr(&self) -> *const Event<T> {
        self as *const Event<T>
    }

    #[inline]
    pub fn as_mut_ptr(&mut self) -> *mut Event<T> {
        self as *mut Event<T>
    }

    #[inline]
    pub fn encode(&self) -> &[u8] {
        unsafe { self.as_byte_slice() }
    }

    #[inline]
    unsafe fn as_byte_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(
            (self as *const Self) as *const u8,
            core::mem::size_of::<Event<T>>(),
        )
    }

    #[inline]
    pub fn switch_type(mut self, new: Type) -> Self {
        // we record original event type
        self.info.switch_type(new);
        self
    }
}

bpf_target_code! {
    impl<T> Event<T> {
        #[inline(always)]
        pub unsafe fn init_from_current_task(&mut self, ty: Type) -> Result<(), Error> {
            self.init_from_task(ty, task_struct::from_ptr(bpf_get_current_task() as *const _))
        }

        #[inline(always)]
        pub unsafe fn init_from_task(&mut self, ty: Type, ts: task_struct) -> Result<(), Error> {
            self.info.init(ty, ts)?;
            Ok(())
        }
    }
}

not_bpf_target_code! {

    #[repr(C)]
    #[derive(Clone)]
    pub struct EncodedEvent {
        event: Vec<u8>,
    }

    #[derive(Error, Debug)]
    pub enum DecoderError {
        #[error("not enough bytes to decode")]
        NotEnoughBytes,
        #[error("size of buffer does not match with size of event")]
        SizeDontMatch,
    }

    impl EncodedEvent {
        pub fn from_bytes(bytes: &[u8]) -> Self {
            Self {
                event: Vec::from(bytes),
            }

        }

        pub fn from_event<T>(event: Event<T>) -> Self {
            Self::from_bytes(event.encode())
        }

        /// # Safety
        /// * the bytes decoded must be a valid Event<T>
        pub unsafe fn info(&self) -> Result<&EventInfo, DecoderError> {
            // event content must be at least the size of EventInfo
            if self.event.len() < core::mem::size_of::<EventInfo>() {
                return Err(DecoderError::NotEnoughBytes);
            }

            Ok(&(*(self.event.as_ptr() as *const EventInfo)))
        }

        /// # Safety
        /// * the bytes decoded must be a valid Event<T>
        pub unsafe fn info_mut(&mut self) -> Result<&mut EventInfo, DecoderError> {
            // event content must be at least the size of EventInfo
            if self.event.len() < core::mem::size_of::<EventInfo>() {
                return Err(DecoderError::NotEnoughBytes);
            }

            Ok(&mut (*(self.event.as_ptr() as *mut EventInfo)))
        }

        /// # Safety
        /// * the bytes decoded must be a valid Event<T>
        pub unsafe fn as_event_with_data<D>(&self) -> Result<&Event<D>, DecoderError> {
            // must be at least the size of Event<T>
            if self.event.len() < core::mem::size_of::<Event<D>>() {
                return Err(DecoderError::SizeDontMatch);
            }

            Ok(&(*(self.event.as_ptr() as *const Event<D>)))
        }


        /// # Safety
        /// * the bytes decoded must be a valid Event<T>
        pub unsafe fn as_mut_event_with_data<D>(&mut self) -> Result<&mut Event<D>, DecoderError> {
            // must be at least the size of Event<T>
            if self.event.len() < core::mem::size_of::<Event<D>>() {
                return Err(DecoderError::SizeDontMatch);
            }

            Ok(&mut (*(self.event.as_mut_ptr() as *mut Event<D>)))
        }
    }

    #[macro_export]
    macro_rules! mut_event {
        ($enc: expr) => {unsafe { $enc.as_mut_event_with_data() }};
        ($enc:expr, $event:ty) => {{
            let event: Result<&mut $event, $crate::bpf_events::DecoderError> =
            unsafe { $enc.as_mut_event_with_data() };
            event
        }};
    }

    pub use mut_event;

    #[macro_export]
    macro_rules! event {
        ($enc: expr) => {unsafe { $enc.as_event_with_data() }};
        ($enc:expr, $event:ty) => {{
            let event: Result<&$event, $crate::bpf_events::DecoderError> =
            unsafe { $enc.as_event_with_data() };
            event
        }};
    }

    pub use event;

}

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
            Type::InitModule => InitModuleEvent::size_of(),
            Type::BpfProgLoad => BpfProgLoadEvent::size_of(),
            Type::BpfSocketFilter => BpfSocketFilterEvent::size_of(),
            Type::MprotectExec => MprotectEvent::size_of(),
            Type::MmapExec => MmapExecEvent::size_of(),
            Type::Connect => ConnectEvent::size_of(),
            Type::DnsQuery => DnsQueryEvent::size_of(),
            Type::SendData => SendEntropyEvent::size_of(),
            Type::Mount => MountEvent::size_of(),
            Type::Read | Type::ReadConfig | Type::Write | Type::WriteConfig => {
                ConfigEvent::size_of()
            }
            Type::FileRename => FileRenameEvent::size_of(),
            Type::FileUnlink => UnlinkEvent::size_of(),
            Type::Unknown | Type::EndEvents | Type::Correlation | Type::CacheHash | Type::Max => 0,
            // never handle _ pattern otherwise this function loses all interest
        };
        if size > max {
            max = size;
        }
        i += 1;
    }
    max
}

not_bpf_target_code! {

    #[cfg(test)]
    mod test {
        use bpf_events::*;

        #[repr(C)]
        pub struct ExecveData {
            pub foo: u32,
            pub bar: u32,
        }

        pub type ExecveEvent = Event<ExecveData>;

        #[test]
        fn test_encode_decode() {
            let mut execve = unsafe { std::mem::zeroed::<ExecveEvent>() };
            execve.data.foo = 42;
            execve.data.bar = 4242;
            execve.info.etype = Type::Execve;
            let b = execve.encode();
            println!("b.len()={}", b.len());

            let mut d = EncodedEvent::from_bytes(b);
            let info = unsafe { d.info() }.unwrap();
            assert!(matches!(info.etype, Type::Execve));

            let dec_execve = unsafe { d.as_mut_event_with_data::<ExecveData>() }.unwrap();

            assert_eq!(dec_execve.data.foo, 42);
            assert_eq!(dec_execve.data.bar, 4242);
            dec_execve.data.foo = 342;
            // we check that modifying the event also modified the bytes in the vector
            let mod_execve = unsafe { d.as_event_with_data::<ExecveData>() }.unwrap();
            assert_eq!(mod_execve.data.foo, 342);
        }
    }

    #[test]
    fn test_max_bpf_event_size() {
        // for the time being ExecveEvent is known to be the biggest
        // event. This is subject to change and it might be normal
        // this test fails in the future
        assert_eq!(max_bpf_event_size(), ExecveEvent::size_of())
    }

}
