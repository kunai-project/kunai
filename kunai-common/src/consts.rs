use kunai_macros::StrEnum;

#[cfg(feature = "user")]
mod user;
#[cfg(feature = "user")]
pub use user::*;

pub const AF_INET: u32 = 2;
pub const AF_INET6: u32 = 10;

// prot constants from mman.h
pub const PROT_READ: u32 = 1;
pub const PROT_WRITE: u32 = 2;
pub const PROT_EXEC: u32 = 4;
pub const PROT_NONE: u32 = 0;

/// Linux capability values as defined in include/uapi/linux/capability.h
///
/// These constants represent the capabilities that can be used to control
/// the permissions of processes beyond the traditional root uid=0 model.
///
/// See: <https://man7.org/linux/man-pages/man7/capabilities.7.html>
#[repr(u32)]
#[derive(StrEnum, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Capability {
    #[str("CAP_CHOWN")]
    /// Change file ownership and group ownership
    Chown = 0,
    #[str("CAP_DAC_OVERRIDE")]
    /// Override all DAC access controls
    DACOverride = 1,
    #[str("CAP_DAC_READ_SEARCH")]
    /// Override DAC access controls on read operations
    DACReadSearch = 2,
    #[str("CAP_FOWNER")]
    /// Override DAC access controls on write operations (chmod, chown, etc.)
    FOwner = 3,
    #[str("CAP_FSETID")]
    /// Don't clear setuid/setgid bits on file write
    FSetID = 4,
    #[str("CAP_KILL")]
    /// Allow sending signals to arbitrary processes
    Kill = 5,
    #[str("CAP_SETGID")]
    /// Allow setting the process GID
    SetGID = 6,
    #[str("CAP_SETUID")]
    /// Allow setting the process UID
    SetUID = 7,
    #[str("CAP_SETPCAP")]
    /// Allow transferring capabilities to other processes
    SetPCAP = 8,
    #[str("CAP_LINUX_IMMUTABLE")]
    /// Allow modifying immutable and append-only file attributes
    LinuxImmutable = 9,
    #[str("CAP_NET_BIND_SERVICE")]
    /// Allow binding to privileged ports (< 1024)
    NetBindService = 10,
    #[str("CAP_NET_BROADCAST")]
    /// Allow broadcasting and listening on multicast
    NetBroadcast = 11,
    #[str("CAP_NET_ADMIN")]
    /// Allow network administration operations
    NetAdmin = 12,
    #[str("CAP_NET_RAW")]
    /// Allow use of raw sockets
    NetRaw = 13,
    #[str("CAP_IPC_LOCK")]
    /// Allow locking memory (mlock, mlockall, etc.)
    IpcLock = 14,
    #[str("CAP_IPC_OWNER")]
    /// Override all IPC ownership and permission checks
    IpcOwner = 15,
    #[str("CAP_SYS_MODULE")]
    /// Allow loading and unloading of kernel modules
    SysModule = 16,
    #[str("CAP_SYS_RAWIO")]
    /// Allow raw I/O port access
    SysRawIO = 17,
    #[str("CAP_SYS_CHROOT")]
    /// Allow use of chroot()
    SysChroot = 18,
    #[str("CAP_SYS_PTRACE")]
    /// Allow tracing of arbitrary processes
    SysPtrace = 19,
    #[str("CAP_SYS_PACCT")]
    /// Allow process accounting
    SysPACCT = 20,
    #[str("CAP_SYS_ADMIN")]
    /// Allow a range of system administration operations
    SysAdmin = 21,
    #[str("CAP_SYS_BOOT")]
    /// Allow rebooting the system
    SysBoot = 22,
    #[str("CAP_SYS_NICE")]
    /// Allow raising nice values and setting real-time scheduling
    SysNice = 23,
    #[str("CAP_SYS_RESOURCE")]
    /// Override resource limits
    SysResource = 24,
    #[str("CAP_SYS_TIME")]
    /// Allow manipulation of the system clock
    SysTime = 25,
    #[str("CAP_SYS_TTY_CONFIG")]
    /// Allow configuration of TTY devices
    SysTTYConfig = 26,
    #[str("CAP_MKNOD")]
    /// Allow creation of special files using mknod()
    Mknod = 27,
    #[str("CAP_LEASE")]
    /// Allow taking of leases on files (fcntl, lease)
    Lease = 28,
    #[str("CAP_AUDIT_WRITE")]
    /// Allow writing to the audit log
    AuditWrite = 29,
    #[str("CAP_AUDIT_CONTROL")]
    /// Allow configuration of the audit subsystem
    AuditControl = 30,
    #[str("CAP_SETFCAP")]
    /// Allow setting file capabilities
    SetFCAP = 31,
    #[str("CAP_MAC_OVERRIDE")]
    /// Override Mandatory Access Control
    MACOverride = 32,
    #[str("CAP_MAC_ADMIN")]
    /// Allow administration of the MAC subsystem
    MACAdmin = 33,
    #[str("CAP_SYSLOG")]
    /// Allow viewing kernel logs (dmesg, etc.)
    Syslog = 34,
    #[str("CAP_WAKE_ALARM")]
    /// Allow triggering wake alarms (timer_create, etc.)
    WakeAlarm = 35,
    #[str("CAP_BLOCK_SUSPEND")]
    /// Allow blocking system suspend
    BlockSuspend = 36,
    #[str("CAP_AUDIT_READ")]
    /// Allow reading the audit log
    AuditRead = 37,
    #[str("CAP_PERFMON")]
    /// Allow use of performance monitoring (perf_event_open, etc.)
    Perfmon = 38,
    #[str("CAP_BPF")]
    /// Allow use of BPF
    Bpf = 39,
    #[str("CAP_CHECKPOINT_RESTORE")]
    /// Allow checkpoint and restore of processes
    CheckpointRestore = 40,
}
