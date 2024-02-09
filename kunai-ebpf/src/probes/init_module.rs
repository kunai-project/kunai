use super::*;

use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::{ProbeContext, TracePointContext};
use kunai_common::syscalls::{SysEnterArgs, SysExitArgs};

#[map]
static mut INIT_MODULE_TRACKING: LruHashMap<u64, InitModuleEvent> =
    LruHashMap::with_max_entries(1024, 0);

#[kprobe(name = "lkm.mod_sysfs_setup")]
pub fn mod_sysfs_setup(ctx: ProbeContext) -> u32 {
    match unsafe { try_mod_sysfs_setup(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
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

#[tracepoint(name = "lkm.syscalls.sys_enter_init_module")]
pub fn sys_enter_init_module(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_init_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_init_module(ctx: &TracePointContext) -> ProbeResult<()> {
    let args = SysEnterArgs::<Init>::from_context(ctx)?.args;
    handle_init_module(ctx, args.into())
}

#[tracepoint(name = "lkm.syscalls.sys_enter_finit_module")]
pub fn sys_enter_finit_module(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_enter_finit_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_finit_module(ctx: &TracePointContext) -> ProbeResult<()> {
    let args = SysEnterArgs::<FInit>::from_context(ctx)?.args;
    handle_init_module(ctx, args.into())
}

unsafe fn handle_init_module(ctx: &TracePointContext, args: InitModuleArgs) -> ProbeResult<()> {
    // initialize allocator
    alloc::init()?;
    let key = bpf_task_tracking_id();

    let event = alloc::alloc_zero::<InitModuleEvent>()?;

    event.init_from_current_task(Type::InitModule)?;

    // Aya currently reports an error on empty string being read
    // so until Aya is upgraded some errors might pop up while there
    // is none.
    ignore_result!(inspect_err!(
        event
            .data
            .uargs
            .read_user_str_bytes(args.uargs() as *const u8),
        |_| warn_msg!(ctx, "failed to read uargs")
    ));

    // setting event data
    event.data.args = args;

    INIT_MODULE_TRACKING
        .insert(&key, event, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

#[tracepoint(name = "lkm.syscalls.sys_exit_init_module")]
pub fn sys_exit_init_module(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_init_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[tracepoint(name = "lkm.syscalls.sys_exit_finit_module")]
pub fn sys_exit_finit_module(ctx: TracePointContext) -> u32 {
    match unsafe { try_sys_exit_init_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
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
            event.data.name.push_bytes_unchecked("?");
        }
        event.data.loaded = args.ret == 0;
        pipe_event(ctx, event);
    }

    // we remove item from map
    ignore_result!(INIT_MODULE_TRACKING.remove(&key));

    Ok(())
}
