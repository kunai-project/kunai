use crate::uuid::{TaskUuid, Uuid};
use crate::{bpf_target_code, not_bpf_target_code};

not_bpf_target_code! {
    use std::vec::Vec;
    use thiserror::Error;
}

bpf_target_code! {
    use crate::co_re::task_struct;
    use aya_bpf::helpers::{bpf_get_current_task, bpf_ktime_get_ns};
    use aya_bpf::cty::c_void;
    use kunai_macros::BpfError;
}

pub const COMM_SIZE: usize = 16;
pub const COMM_DEFAULT: [i8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

// events we want to be accesible
mod connect;
pub use connect::*;
mod execve;
pub use execve::*;
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
mod perfs;
pub use perfs::*;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum Type {
    Unknown = 0,
    Execve,
    ExecveScript,
    TaskSched,
    BpfProgLoad,
    MprotectExec,
    MmapExec,
    Connect,
    DnsQuery,
    SendData,
    InitModule,
    ReadConfig,
    WriteConfig,
    FileRename,
    Exit,
    ExitGroup,
}

impl Type {
    pub fn as_str(&self) -> &str {
        match self {
            Type::Unknown => "unknown",
            Type::Execve => "execve",
            Type::ExecveScript => "execve_script",
            Type::TaskSched => "task_sched",
            Type::BpfProgLoad => "bpf_prog_load",
            Type::MprotectExec => "mprotect_exec",
            Type::MmapExec => "mmap_exec",
            Type::Connect => "connect",
            Type::DnsQuery => "dns_query",
            Type::SendData => "send_data",
            Type::InitModule => "init_module",
            Type::ReadConfig => "read_config",
            Type::WriteConfig => "write_config",
            Type::FileRename => "file_rename",
            Type::Exit => "exit",
            Type::ExitGroup => "exit_group",
        }
    }
}

impl Default for Type {
    fn default() -> Self {
        Self::Unknown
    }
}

not_bpf_target_code! {
    use std::fmt::Display;

    impl Display for Type {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{}", self.as_str())
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct TaskInfo {
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
    pub start_time: u64,
}

impl TaskInfo {
    pub fn comm_str(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(&self.comm[..]) }
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
}

}

#[cfg(target_arch = "bpf")]
impl TaskInfo {
    /// # Safety
    /// * task must be a pointer to a valid task_struct
    #[inline(always)]
    pub(crate) unsafe fn from_task(&mut self, task: &task_struct) -> Result<(), Error> {
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
        //self.comm.copy_from_slice(&task.comm()[..]);
        self.comm = task.comm();

        // if task_struct is valid cannot be null
        self.uid = task.cred().ok_or(Error::CredFieldMissing)?.uid();
        self.gid = task.cred().ok_or(Error::CredFieldMissing)?.gid();

        Ok(())
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
}

#[cfg(target_arch = "bpf")]
impl EventInfo {
    #[inline(always)]
    pub(crate) unsafe fn init(&mut self, t: Type, task: *const c_void) -> Result<(), Error> {
        self.etype = t;

        // create a new Uuid for event
        self.uuid = Uuid::new_random();

        if !task.is_null() {
            let task = task_struct::from_ptr(task as *const _);
            self.process.from_task(&task)?;
            self.parent
                .from_task(&task.real_parent().ok_or(Error::RealParentFieldMissing)?)?;
        }

        //self.timestamp = bpf_ktime_get_boot_ns();
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
    pub fn ty(&self) -> Type {
        self.info.etype
    }

    pub fn data_mut(&mut self) -> &mut T {
        &mut self.data
    }

    pub fn as_ptr(&self) -> *const Event<T> {
        self as *const Event<T>
    }

    pub fn as_mut_ptr(&mut self) -> *mut Event<T> {
        self as *mut Event<T>
    }

    pub fn encode(&self) -> &[u8] {
        unsafe { self.as_byte_slice() }
    }

    unsafe fn as_byte_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(
            (self as *const Self) as *const u8,
            core::mem::size_of::<Event<T>>(),
        )
    }
}

bpf_target_code! {
    impl<T> Event<T> {
        #[inline(always)]
        pub unsafe fn init_from_btf_task(&mut self, ty: Type) -> Result<(), Error> {
            let t = bpf_get_current_task() as *const c_void;
            self.info.init(ty, t)?;
            Ok(())
        }
    }
}

not_bpf_target_code! {

    #[repr(C)]
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
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, DecoderError> {
            Ok(EncodedEvent {
                event: Vec::from(bytes),
            })
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
        pub unsafe fn info_mut(&self) -> Result<&mut EventInfo, DecoderError> {
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

}

not_bpf_target_code! {

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

            let mut d = EncodedEvent::from_bytes(b).unwrap();
            let info = unsafe { d.info() }.unwrap();
            assert!(matches!(info.etype, Type::Execve));

            let mut dec_execve = unsafe { d.as_mut_event_with_data::<ExecveData>() }.unwrap();

            assert_eq!(dec_execve.data.foo, 42);
            assert_eq!(dec_execve.data.bar, 4242);
            dec_execve.data.foo = 342;
            // we check that modifying the event also modified the bytes in the vector
            let mod_execve = unsafe { d.as_event_with_data::<ExecveData>() }.unwrap();
            assert_eq!(mod_execve.data.foo, 342);
        }
    }

}
