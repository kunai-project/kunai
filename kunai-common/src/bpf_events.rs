use crate::errors::ProbeError;
use crate::macros::test_flag;
use crate::macros::{bpf_target_code, not_bpf_target_code};
use crate::uuid::{TaskUuid, Uuid};
use kunai_macros::{BpfError, StrEnum};

not_bpf_target_code! {
    mod user;
    pub use user::*;
}

bpf_target_code! {
    mod bpf;
    pub use bpf::*;
}

mod events;
pub use events::*;

pub const COMM_SIZE: usize = 16;
pub const COMM_DEFAULT: [i8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

#[derive(BpfError, Clone, Copy)]
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
    #[error("failed to get mnt_namespace")]
    MntNamespaceFailure,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::EventError(value)
    }
}

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
    #[str("error")]
    Error,

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

    pub fn id(&self) -> u32 {
        *self as u32
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
    pub namespaces: Option<Namespaces>,
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

#[cfg(test)]
mod test {
    use super::*;

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
