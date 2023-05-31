use super::*;

use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::{ProbeContext, TracePointContext};

#[map]
static mut INIT_MODULE_TRACKING: LruHashMap<u64, InitModuleEvent> =
    LruHashMap::with_max_entries(1024, 0);

#[kprobe(name = "lkm.mod_sysfs_setup")]
pub fn mod_sysfs_setup(ctx: ProbeContext) -> u32 {
    match unsafe { try_mod_sysfs_setup(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_mod_sysfs_setup(ctx: &ProbeContext) -> ProbeResult<()> {
    let load_info = co_re::load_info::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);

    let key = bpf_task_tracking_id();

    if let Some(event) = INIT_MODULE_TRACKING.get_ptr_mut(&key) {
        let event = &mut (*event);
        if let Some(pname) = load_info.name() {
            event.data.name.read_kernel_str_bytes(pname)?;
        }
    } else {
        return Err(MapError::GetFailure.into());
    }

    Ok(())
}

#[repr(C)]
pub struct InitModuleArgs {
    pub umod: u64,
    pub len: u64,
    pub uargs: u64,
}

#[tracepoint(name = "lkm.syscalls.sys_enter_init_module")]
pub fn sys_enter_init_module(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_init_module(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_init_module(ctx: &TracePointContext) -> ProbeResult<()> {
    // initialize allocator
    alloc::init()?;
    let key = bpf_task_tracking_id();
    let args = SysEnterArgs::<InitModuleArgs>::from_context(ctx)?.args;
    let event = alloc::alloc_zero::<InitModuleEvent>()?;

    event.init_from_btf_task(Type::InitModule)?;

    // setting event data
    event.data.umod = args.umod;
    event.data.len = args.len;
    event
        .data
        .uargs
        .read_user_str_bytes(args.uargs as *const u8)?;

    INIT_MODULE_TRACKING
        .insert(&key, event, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

#[tracepoint(name = "lkm.syscalls.sys_exit_init_module")]
pub fn sys_exit_init_module(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_init_module(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_exit_init_module(ctx: &TracePointContext) -> ProbeResult<()> {
    let key = bpf_task_tracking_id();
    let args = SysExitArgs::from_context(ctx)?;

    if let Some(event) = INIT_MODULE_TRACKING.get_ptr_mut(&key) {
        let event = &mut (*event);
        // we set a default value for driver name
        if event.data.name.is_empty() {
            event.data.name.push_byte(b'?');
        }
        event.data.loaded = args.ret == 0;
        pipe_event(ctx, event);
    }

    // we remove item from map
    ignore_result!(INIT_MODULE_TRACKING.remove(&key));

    Ok(())
}
