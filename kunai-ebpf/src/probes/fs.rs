use super::*;

use aya_bpf::cty::c_int;
use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::ProbeContext;
use kunai_common::inspect_err;

#[map]
static mut FILE_TRACKING: LruHashMap<u128, bool> = LruHashMap::with_max_entries(4096, 0);

#[inline(always)]
unsafe fn track(file: &co_re::file) -> ProbeResult<()> {
    FILE_TRACKING
        .insert(&file_id(file)?, &true, 0)
        .map_err(|_| MapError::InsertFailure)?;
    Ok(())
}

#[inline(always)]
unsafe fn already_tracked(file: &co_re::file) -> ProbeResult<bool> {
    Ok(*(FILE_TRACKING.get(&file_id(file)?).unwrap_or(&false)))
}

#[inline(always)]
unsafe fn file_id(file: &co_re::file) -> ProbeResult<u128> {
    let ino = core_read_kernel!(file, f_inode, i_ino)?;
    let task_id = bpf_task_tracking_id();
    Ok((task_id as u128) << 64 | ino as u128)
}

#[kprobe(name = "fs.vfs_read")]
pub fn vfs_read(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_read(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[kprobe(name = "fs.vfs_readv")]
pub fn vfs_readv(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_read(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_vfs_read(ctx: &ProbeContext) -> ProbeResult<()> {
    let file = co_re::file::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    if !file.is_file().unwrap_or(false) {
        // if not file we do nothing
        return Ok(());
    }

    // if file has already been tracked
    if already_tracked(&file)? {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ConfigEvent>()?;

    inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: path::Error| error!(ctx, "failed to resolve filename: {}", e.description())
    );

    if event.data.path.starts_with("/etc/") {
        event.init_from_btf_task(Type::ReadConfig)?;
        pipe_event(ctx, event);
    }

    // we mark file as being tracked
    inspect_err!(track(&file), |_| error!(ctx, "failed to track file"));
    Ok(())
}

#[kprobe(name = "fs.vfs_write")]
pub fn vfs_write(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_write(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[kprobe(name = "fs.vfs_writev")]
pub fn vfs_writev(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_write(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_vfs_write(ctx: &ProbeContext) -> ProbeResult<()> {
    let file = co_re::file::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    if !core_read_kernel!(file, is_file)? {
        // if not a regular file we do nothing
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ConfigEvent>()?;

    inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: path::Error| error!(ctx, "failed to resolve filename: {}", e.description())
    );

    if event.data.path.starts_with("/etc/") {
        event.init_from_btf_task(Type::WriteConfig)?;
        pipe_event(ctx, event);
    }

    Ok(())
}

#[kprobe(name = "fs.security_path_rename")]
pub fn security_path_rename(ctx: ProbeContext) -> u32 {
    match unsafe { try_security_path_rename(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_path_rename(ctx: &ProbeContext) -> ProbeResult<()> {
    let old_dir = co_re::path::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);
    let old_dentry = co_re::dentry::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);
    let new_dir = co_re::path::from_ptr(ctx.arg(2).ok_or(ProbeError::KProbeArgFailure)?);
    let new_dentry = co_re::dentry::from_ptr(ctx.arg(3).ok_or(ProbeError::KProbeArgFailure)?);

    // we handle only file renaming for the moment
    if !core_read_kernel!(old_dentry, is_file)? {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<FileRenameEvent>()?;

    event.init_from_btf_task(Type::FileRename)?;

    let name = core_read_kernel!(old_dentry, d_name, name)?;
    let len = core_read_kernel!(old_dentry, d_name, len)?;

    // parsing old_name
    inspect_err!(
        event.data.old_name.prepend_qstr_name(name, len),
        |e: path::Error| error!(ctx, "failed to parse old_name dentry: {}", e.description())
    );

    inspect_err!(
        event.data.old_name.core_resolve(&old_dir, MAX_PATH_DEPTH),
        |e: path::Error| error!(ctx, "failed to old_dir: {}", e.description())
    );

    // parsing new_name
    inspect_err!(
        event.data.new_name.prepend_qstr_name(
            core_read_kernel!(new_dentry, d_name, name)?,
            core_read_kernel!(new_dentry, d_name, len)?,
        ),
        |e: path::Error| error!(ctx, "failed to parse new_name dentry: {}", e.description())
    );

    inspect_err!(
        event.data.new_name.core_resolve(&new_dir, MAX_PATH_DEPTH),
        |e: path::Error| error!(ctx, "failed to resolve new_dir: {}", e.description())
    );

    pipe_event(ctx, event);

    Ok(())
}

//#[kprobe(name = "debug.do_mount")] // older kernels
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
    // we restore entry context
    let entry_ctx = entry_ctx.restore();

    let dev_name: *const u8 = kprobe_arg!(entry_ctx, 0)?;
    let path = co_re::path::from_ptr(kprobe_arg!(entry_ctx, 1)?);
    let typ: *const u8 = kprobe_arg!(entry_ctx, 2)?;
    let rc: c_int = exit_ctx.ret().unwrap_or_default();

    alloc::init()?;
    let event = alloc::alloc_zero::<MountEvent>()?;

    // failing at retrieving path make the probe failing
    event.data.path.core_resolve(&path, MAX_PATH_DEPTH)?;

    // todo handle those two errors properly
    event.data.dev_name.read_kernel_str_bytes(dev_name);
    event.data.ty.read_kernel_str_bytes(typ);

    event.data.rc = rc;

    event.init_from_btf_task(Type::Mount)?;

    pipe_event(exit_ctx, event);

    /*warn!(
        exit_ctx,
        "dev_name={} (path={} i_ino={}) type={} rc={}",
        event.data.dev_name.as_str(),
        event.data.path.to_aya_debug_str(),
        event.data.path.ino.unwrap_or_default(),
        event.data.ty.as_str(),
        rc
    );*/

    Ok(())
}
