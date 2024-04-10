use super::Error;
use aya_ebpf::{helpers::bpf_probe_read, EbpfContext};

/// To read the input parameters for a tracepoint conveniently, define a struct
/// to hold the input arguments. Refer to to
/// `/sys/kernel/debug/tracing/events/<category>/<tracepoint>/format`
/// for information about a specific tracepoint.
#[repr(C, packed(1))]
pub struct TracepointCommonArgs {
    pub ctype: u16,
    pub flags: u8,
    pub preempt_count: u8,
    pub pid: i32,
}

#[repr(C, packed(1))]
pub struct Syscall {
    pub sys_nr: i32,
    pad: u32,
}

#[repr(C, packed(1))]
pub struct SysExitArgs {
    pub common: TracepointCommonArgs,
    pub syscall: Syscall,
    pub ret: i64,
}

impl SysExitArgs {
    pub fn from_context<C: EbpfContext>(c: &C) -> Result<Self, Error> {
        unsafe { bpf_probe_read(c.as_ptr() as *const SysExitArgs) }
            .map_err(|_| Error::FailedToReadExitArgs)
    }
}

#[repr(C, packed(1))]
pub struct SysEnterArgs<A> {
    pub common: TracepointCommonArgs,
    pub syscall: Syscall,
    pub args: A,
}

impl<A> SysEnterArgs<A> {
    pub fn from_context<C: EbpfContext>(c: &C) -> Result<Self, Error> {
        unsafe { bpf_probe_read(c.as_ptr() as *const SysEnterArgs<A>) }
            .map_err(|_| Error::FailedToReadEnterArgs)
    }
}
