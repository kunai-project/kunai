use super::*;

use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::{ProbeContext, RawTracePointContext};
use kunai_common::syscalls::{RawSysEnterContext, RawSysExitContext};

#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_INIT_MODULE: i64 = 175;
#[cfg(bpf_target_arch = "x86_64")]
pub const SYS_FINIT_MODULE: i64 = 313;

#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_INIT_MODULE: i64 = 105;
#[cfg(bpf_target_arch = "aarch64")]
pub const SYS_FINIT_MODULE: i64 = 273;

#[map]
static mut INIT_MODULE_TRACKING: LruHashMap<u64, InitModuleEvent> =
    LruHashMap::with_max_entries(1024, 0);

/// match-proto:v5.0:kernel/module.c:static int mod_sysfs_setup(struct module *mod, const struct load_info *info, struct kernel_param *kparam, unsigned int num_params)
/// match-proto:v5.19:kernel/module/sysfs.c:int mod_sysfs_setup(struct module *mod, const struct load_info *info, struct kernel_param *kparam, unsigned int num_params)
/// match-proto:latest:kernel/module/sysfs.c:int mod_sysfs_setup(struct module *mod, const struct load_info *info, struct kernel_param *kparam, unsigned int num_params)
#[kprobe(function = "mod_sysfs_setup")]
pub fn lkm_mod_sysfs_setup(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

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

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn lkm_syscalls_sys_enter_init_module(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysEnterContext::from(ctx);

    if ctx.sys_nr() != SYS_INIT_MODULE {
        return errors::BPF_PROG_SUCCESS;
    }

    match unsafe { try_sys_enter_init_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_init_module(ctx: &RawSysEnterContext) -> ProbeResult<()> {
    let args = Init {
        umod: ctx.arg(0).unwrap_or_default(),
        len: ctx.arg(1).unwrap_or_default(),
        uargs: ctx.arg(2).unwrap_or_default(),
    };

    handle_init_module(ctx, args.into())
}

#[raw_tracepoint(tracepoint = "sys_enter")]
pub fn lkm_syscalls_sys_enter_finit_module(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysEnterContext::from(ctx);
    if ctx.sys_nr() != SYS_FINIT_MODULE {
        return errors::BPF_PROG_SUCCESS;
    }

    match unsafe { try_sys_enter_finit_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_enter_finit_module(ctx: &RawSysEnterContext) -> ProbeResult<()> {
    let args = FInit {
        fd: ctx.arg(0).unwrap_or_default(),
        uargs: ctx.arg(1).unwrap_or_default(),
        flags: ctx.arg(2).unwrap_or_default(),
    };
    handle_init_module(ctx, args.into())
}

unsafe fn handle_init_module(ctx: &RawSysEnterContext, args: InitModuleArgs) -> ProbeResult<()> {
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
        |_| warn!(ctx, "failed to read uargs")
    ));

    // setting event data
    event.data.args = args;

    INIT_MODULE_TRACKING
        .insert(&key, event, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

#[raw_tracepoint(tracepoint = "sys_exit")]
pub fn lkm_syscalls_sys_exit_init_module(ctx: RawTracePointContext) -> u32 {
    if is_current_loader_task() {
        return errors::BPF_PROG_SUCCESS;
    }

    let ctx = RawSysExitContext::from(ctx);
    unsafe {
        if !matches!(ctx.sys_nr(), Some(SYS_FINIT_MODULE) | Some(SYS_INIT_MODULE)) {
            return errors::BPF_PROG_SUCCESS;
        }
    }

    match unsafe { try_sys_exit_init_module(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_sys_exit_init_module(ctx: &RawSysExitContext) -> ProbeResult<()> {
    let key = bpf_task_tracking_id();

    if let Some(event) = INIT_MODULE_TRACKING.get_ptr_mut(&key) {
        let event = &mut (*event);
        // we set a default value for driver name
        if event.data.name.is_empty() {
            ignore_result!(event.data.name.push_char('?'));
        }
        event.data.loaded = ctx.ret() == 0;
        pipe_event(ctx, event);
    }

    // we remove item from map
    ignore_result!(INIT_MODULE_TRACKING.remove(&key));

    Ok(())
}
