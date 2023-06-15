#[allow(unused_imports)]
use super::*;
#[allow(unused_imports)]
use aya_bpf::programs::ProbeContext;

/*#[kretprobe(name = "debug.exit.security_sb_mount")]
pub fn debug_exit_security_sb_mount(ctx: ProbeContext) -> u32 {
    match unsafe {
        restore_entry_ctx(ProbeFn::security_sb_mount)
            .ok_or(ProbeError::KProbeCtxRestoreFailure)
            .and_then(|ent_ctx| try_exit_debug_security_sb_mount(ent_ctx, &ctx))
    } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_exit_debug_security_sb_mount(
    entry: &mut KProbeEntryContext,
    exit: &ProbeContext,
) -> ProbeResult<()> {
    let entry = entry.restore();

    let dev_name: *const u8 = kprobe_arg!(entry, 0)?;
    let path = co_re::path::from_ptr(kprobe_arg!(entry, 1)?);
    let typ: *const u8 = kprobe_arg!(entry, 2)?;

    alloc::init()?;

    let p = alloc::alloc_zero::<Path>()?;
    p.core_resolve(&path, 15)?;
    info!(
        exit,
        "path:0x{:x} path={}",
        path.as_ptr() as usize,
        p.to_aya_debug_str()
    );

    Ok(())
}*/
