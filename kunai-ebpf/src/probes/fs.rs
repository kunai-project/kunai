use super::*;
use aya_bpf::cty::c_long;
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
        event.init_from_btf_task(Type::ReadConfig);
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
        event.init_from_btf_task(Type::WriteConfig);
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

    event.init_from_btf_task(Type::FileRename);

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
