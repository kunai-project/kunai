use super::*;

use aya_bpf::cty::c_int;
use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::ProbeContext;

#[map]
static mut MOUNT_EVENTS: LruHashMap<u128, MountEvent> = LruHashMap::with_max_entries(1024, 0);

#[kretprobe(name = "fs.exit.security_sb_mount")]
pub fn exit_security_sb_mount(ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::security_sb_mount)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|ent_ctx| try_exit_security_sb_mount(ent_ctx, &ctx))
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_exit_security_sb_mount(
    entry: &mut KProbeEntryContext,
    exit: &ProbeContext,
) -> ProbeResult<()> {
    let key = entry.uuid();
    let entry = entry.restore();

    let dev_name: *const u8 = kprobe_arg!(entry, 0)?;
    let path = co_re::path::from_ptr(kprobe_arg!(entry, 1)?);
    let typ: *const u8 = kprobe_arg!(entry, 2)?;
    let rc: c_int = exit.ret().unwrap_or_default();

    alloc::init()?;
    let event = alloc::alloc_zero::<MountEvent>()?;

    // failing at retrieving path make the probe failing
    event.data.path.core_resolve(&path, MAX_PATH_DEPTH)?;

    if let Err(e) = event.data.dev_name.read_kernel_str_bytes(dev_name) {
        error!(exit, "failed to read dev_name: {} ", e.description());
    }

    if let Err(e) = event.data.ty.read_kernel_str_bytes(typ) {
        error!(exit, "failed to read dev type: {}", e.description())
    }

    event.data.rc = rc;

    event.init_from_current_task(Type::Mount)?;

    ignore_result!(MOUNT_EVENTS.insert(&key, event, 0));

    Ok(())
}

// path_mount is available only since 5.9 before that do_mount must be hooked
#[kretprobe(name = "fs.exit.path_mount")]
pub fn exit_path_mount(ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::security_sb_mount)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|ent_ctx| try_exit_path_mount(ent_ctx, &ctx))
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_exit_path_mount(
    entry_ctx: &mut KProbeEntryContext,
    exit_ctx: &ProbeContext,
) -> ProbeResult<()> {
    let key = entry_ctx.uuid();

    // we restore entry context
    let event = MOUNT_EVENTS.get(&key).ok_or(MapError::GetFailure)?;

    pipe_event(exit_ctx, event);

    // eventually cleanup event
    ignore_result!(MOUNT_EVENTS.remove(&key));

    Ok(())
}
