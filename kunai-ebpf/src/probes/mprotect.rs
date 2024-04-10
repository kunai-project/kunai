use super::*;
use aya_ebpf::programs::TracePointContext;
use kunai_common::syscalls::SysEnterArgs;

// print fmt: "0x%lx", REC->ret
// name: sys_enter_mprotect
// ID: 594
// format:
// field:unsigned short common_type;	offset:0;	size:2;	signed:0;
// field:unsigned char common_flags;	offset:2;	size:1;	signed:0;
// field:unsigned char common_preempt_count;	offset:3;	size:1;	signed:0;
// field:int common_pid;	offset:4;	size:4;	signed:1;

// field:int __syscall_nr;	offset:8;	size:4;	signed:1;
// field:unsigned long start;	offset:16;	size:8;	signed:0;
// field:size_t len;	offset:24;	size:8;	signed:0;
// field:unsigned long prot;	offset:32;	size:8;	signed:0;

#[repr(C)]
pub struct MprotectArgs {
    pub start: u64,
    pub len: u64,
    pub prot: u64,
}

#[tracepoint(name = "sys_enter_mprotect", category = "syscalls")]
pub fn syscalls_sys_enter_mprotect(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_mprotect(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_mprotect(ctx: &TracePointContext) -> ProbeResult<()> {
    let args = SysEnterArgs::<MprotectArgs>::from_context(ctx)?.args;
    if args.prot & PROT_EXEC as u64 == PROT_EXEC as u64 {
        alloc::init()?;
        let event = alloc::alloc_zero::<MprotectEvent>()?;

        event.init_from_current_task(Type::MprotectExec)?;

        // setting event data
        event.data.start = args.start;
        event.data.prot = args.prot;
        event.data.len = args.len;

        // todo: work on section identification
        //copy_ascii_str(event.data.section, "?");

        pipe_event(ctx, event);
    }

    Ok(())
}
