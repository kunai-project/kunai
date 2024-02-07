use super::*;
use aya_bpf::programs::TracePointContext;
use kunai_common::{maps::FdMap, syscalls::SysEnterArgs};

// print fmt: "unshare_flags: 0x%08lx", ((unsigned long)(REC->unshare_flags))
// name: sys_enter_mmap
// ID: 101
// format:
// field:unsigned short common_type; offset:0; size:2; signed:0;
// field:unsigned char common_flags; offset:2; size:1; signed:0;
// field:unsigned char common_preempt_count; offset:3; size:1; signed:0;
// field:int common_pid; offset:4; size:4; signed:1;
//
// field:int __syscall_nr; offset:8; size:4; signed:1;
// field:unsigned long addr; offset:16; size:8; signed:0;
// field:unsigned long len; offset:24; size:8; signed:0;
// field:unsigned long prot; offset:32; size:8; signed:0;
// field:unsigned long flags; offset:40; size:8; signed:0;
// field:unsigned long fd; offset:48; size:8; signed:0;
// field:unsigned long off; offset:56; size:8; signed:0;

#[repr(C)]
pub struct MmapArgs {
    pub addr: u64,
    pub len: u64,
    pub prot: u64,
    pub flag: u64,
    pub fd: u64,
    pub off: u64,
}

#[tracepoint(name = "syscalls.sys_enter_mmap")]
pub fn mmap(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_mmap(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_mmap(ctx: &TracePointContext) -> ProbeResult<()> {
    let mmap_args = SysEnterArgs::<MmapArgs>::from_context(ctx)?.args;
    let fd = mmap_args.fd as i32;

    if fd >= 0 && mmap_args.prot & PROT_EXEC as u64 == PROT_EXEC as u64 {
        //if fd >= 0 {
        let mut fds = FdMap::attach();

        let opt_p = fds.get(fd as i64);

        match opt_p {
            Some(f) => {
                alloc::init()?;
                let event = alloc::alloc_zero::<MmapExecEvent>()?;

                event.init_from_current_task(Type::MmapExec)?;

                event
                    .data
                    .filename
                    .core_resolve(&core_read_kernel!(f, f_path)?, path::MAX_PATH_DEPTH)?;

                pipe_event(ctx, event);
            }
            None => {
                error_msg!(ctx, "failed to retrieve path for mmapped");
            }
        }
    }

    Ok(())
}
