use super::*;

use aya_ebpf::cty::c_int;
use aya_ebpf::maps::LruHashMap;
use aya_ebpf::programs::ProbeContext;
use kunai_common::inspect_err;
use kunai_common::kprobe::ProbeFn;

#[repr(C)]
struct RW(bool, bool);

#[repr(C)]
struct FileKey(u64, u64);

#[map]
static mut FILE_TRACKING: LruHashMap<FileKey, RW> = LruHashMap::with_max_entries(0x1ffff, 0);

#[inline(always)]
unsafe fn track_read(file: &co_re::file) -> ProbeResult<()> {
    let key = &file_key(file)?;
    match FILE_TRACKING.get_ptr_mut(&key) {
        Some(rw) => (*rw).0 = true,
        None => {
            FILE_TRACKING
                .insert(&key, &RW(true, false), 0)
                .map_err(|_| MapError::InsertFailure)?;
        }
    }
    Ok(())
}

#[inline(always)]
unsafe fn track_write(file: &co_re::file) -> ProbeResult<()> {
    let key = &file_key(file)?;
    match FILE_TRACKING.get_ptr_mut(&key) {
        Some(rw) => (*rw).1 = true,
        None => {
            FILE_TRACKING
                .insert(&key, &RW(false, true), 0)
                .map_err(|_| MapError::InsertFailure)?;
        }
    }
    Ok(())
}

#[inline(always)]
unsafe fn already_read(file: &co_re::file) -> ProbeResult<bool> {
    Ok(FILE_TRACKING
        .get(&file_key(file)?)
        .unwrap_or(&RW(false, false))
        .0)
}

#[inline(always)]
unsafe fn already_written(file: &co_re::file) -> ProbeResult<bool> {
    Ok(FILE_TRACKING
        .get(&file_key(file)?)
        .unwrap_or(&RW(false, false))
        .1)
}

#[inline(always)]
unsafe fn file_key(file: &co_re::file) -> ProbeResult<FileKey> {
    let ino = core_read_kernel!(file, f_inode, i_ino)?;
    let task_id = bpf_task_tracking_id();
    Ok(FileKey(task_id, ino))
}

#[kprobe(function = "vfs_read")]
pub fn fs_0x2e_vfs_read(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_read(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[kprobe(function = "vfs_readv")]
pub fn fs_0x2e_vfs_readv(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_read(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_vfs_read(ctx: &ProbeContext) -> ProbeResult<()> {
    let config = get_cfg!()?;
    let file = co_re::file::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    if !file.is_file().unwrap_or(false) {
        // if not file we do nothing
        return Ok(());
    }

    // if file has already been tracked
    if already_read(&file)? {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ConfigEvent>()?;

    ignore_result!(inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve filename", (*e).into())
    ));

    if event.data.path.starts_with("/etc/") {
        event.init_from_current_task(Type::ReadConfig)?;
        pipe_event(ctx, event);
    } else if config.is_event_enabled(Type::Read) && !event.data.path.starts_with("/proc/") {
        // we filter out procfs because it generates too much events
        // maybe let the choice through a configuration option
        event.init_from_current_task(Type::Read)?;
        pipe_event(ctx, event);
    }

    // we mark file as being tracked
    ignore_result!(inspect_err!(track_read(&file), |_| warn_msg!(
        ctx,
        "failed to track file read"
    )));

    Ok(())
}

#[kprobe(function = "vfs_write")]
pub fn fs_0x2e_vfs_write(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_write(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[kprobe(function = "vfs_writev")]
pub fn fs_0x2e_vfs_writev(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_write(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_vfs_write(ctx: &ProbeContext) -> ProbeResult<()> {
    let config = get_cfg!()?;
    let file = co_re::file::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    if !core_read_kernel!(file, is_file)? {
        // if not a regular file we do nothing
        return Ok(());
    }

    // if file has already been tracked
    if already_written(&file)? {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ConfigEvent>()?;

    ignore_result!(inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve filename", (*e).into())
    ));

    if event.data.path.starts_with("/etc/") {
        event.init_from_current_task(Type::WriteConfig)?;
        pipe_event(ctx, event);
    } else if config.is_event_enabled(Type::Write) {
        event.init_from_current_task(Type::Write)?;
        pipe_event(ctx, event);
    }

    // we mark file as being tracked
    ignore_result!(inspect_err!(track_write(&file), |_| warn_msg!(
        ctx,
        "failed to track file write"
    )));

    Ok(())
}

#[kprobe(function = "security_path_rename")]
pub fn fs_0x2e_security_path_rename(ctx: ProbeContext) -> u32 {
    match unsafe { try_security_path_rename(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
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

    event.init_from_current_task(Type::FileRename)?;

    // parsing old_name
    ignore_result!(inspect_err!(
        event.data.old_name.prepend_dentry(&old_dentry),
        |e: &path::Error| warn!(ctx, "failed to parse old_name dentry", (*e).into())
    ));

    ignore_result!(inspect_err!(
        event.data.old_name.core_resolve(&old_dir, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to old_dir", (*e).into())
    ));

    // parsing new_name
    ignore_result!(inspect_err!(
        event.data.new_name.prepend_dentry(&new_dentry),
        |e: &path::Error| warn!(ctx, "failed to parse new_name dentry", (*e).into())
    ));

    ignore_result!(inspect_err!(
        event.data.new_name.core_resolve(&new_dir, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve new_dir", (*e).into())
    ));

    pipe_event(ctx, event);

    Ok(())
}

#[map]
static mut PATHS: LruHashMap<u128, Path> = LruHashMap::with_max_entries(4096, 0);

#[kprobe(function = "security_path_unlink")]
pub fn fs_0x2e_security_path_unlink(ctx: ProbeContext) -> u32 {
    match unsafe { try_security_path_unlink(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_path_unlink(ctx: &ProbeContext) -> ProbeResult<()> {
    let dir = co_re::path::from_ptr(kprobe_arg!(ctx, 0)?);
    let entry = co_re::dentry::from_ptr(kprobe_arg!(ctx, 1)?);

    alloc::init()?;
    let p = alloc::alloc_zero::<Path>()?;

    p.prepend_dentry(&entry)?;
    p.core_resolve(&dir, MAX_PATH_DEPTH)?;

    // as vfs_unlink can be reached without security_path_unlink being called
    // we report error when insertion is failing
    PATHS
        .insert(&ProbeFn::security_path_unlink.depth_key(), &p, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

// we have to hook into vfs_unlink (called by do_unlinkat) and recovering
// path argument from the security_path_unlink call happening before.
// do_unlinkat cannot be hooked at ret as path/dentry we wanna parse
// seems to be cleaned up and cannot be parsed correctly.
#[kretprobe(function = "vfs_unlink")]
pub fn fs_0x2e_exit_0x2e_vfs_unlink(ctx: ProbeContext) -> u32 {
    match unsafe { try_vfs_unlink(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_vfs_unlink(ctx: &ProbeContext) -> ProbeResult<()> {
    let rc: c_int = ctx.ret().unwrap_or(-1);

    alloc::init()?;
    let e = alloc::alloc_zero::<UnlinkEvent>()?;

    e.init_from_current_task(Type::FileUnlink)?;

    let path_key = ProbeFn::security_path_unlink.depth_key();
    if let Some(p) = PATHS.get(&path_key) {
        e.data.path.copy_from(&p);
        // make some room in the cache
        ignore_result!(PATHS.remove(&path_key));
    } else {
        // it seems there are very few code paths where vfs_unlink
        // can be called without a prior call to security_path_unlink
        // in this case we return so that we don't end up with an event
        // with an empty path
        return Ok(());
    }

    e.data.success = rc == 0;

    pipe_event(ctx, e);

    Ok(())
}
