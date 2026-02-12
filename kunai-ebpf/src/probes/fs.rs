use core::ops::Div;

use super::*;

use aya_ebpf::cty::c_int;
use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::maps::{LruHashMap, LruPerCpuHashMap};
use aya_ebpf::programs::{ProbeContext, RetProbeContext};
use aya_ebpf::EbpfContext;
use kunai_common::kprobe::ProbeFn;
use kunai_common::{bpf_events, inspect_err};

const READ: Flag = Flag(0b00000001);
const WRITE: Flag = Flag(0b00000010);
const CLOSE_AFTER_WRITE: Flag = Flag(0b10000000);

#[repr(C)]
struct Flag(u8);

impl Flag {
    #[inline(always)]
    fn set(&mut self, flag: Flag) -> &mut Self {
        self.0 |= flag.0;
        self
    }

    #[inline(always)]
    fn unset(&mut self, flag: Flag) -> &mut Self {
        self.0 &= !flag.0;
        self
    }

    #[inline(always)]
    fn matches(&self, flag: Flag) -> bool {
        self.0 & flag.0 == flag.0
    }
}

#[repr(C)]
struct FileKey(u64, u64);

#[map]
static mut FILE_TRACKING: LruHashMap<FileKey, Flag> = LruHashMap::with_max_entries(0x1ffff, 0);

#[inline(always)]
unsafe fn file_set_flag(file: &co_re::file, flag: Flag) -> ProbeResult<()> {
    let key = &file_key(file)?;
    match FILE_TRACKING.get_ptr_mut(key) {
        Some(rw) => {
            (*rw).set(flag);
        }
        None => {
            FILE_TRACKING
                .insert(key, &flag, 0)
                .map_err(|_| MapError::InsertFailure)?;
        }
    }
    Ok(())
}

#[inline(always)]
unsafe fn file_match_flag(file: &co_re::file, flag: Flag) -> ProbeResult<bool> {
    Ok(FILE_TRACKING
        .get_ptr_mut(&file_key(file)?)
        .map(|f| (*f).matches(flag))
        .unwrap_or(false))
}

#[inline(always)]
unsafe fn file_unset_flag(file: &co_re::file, flag: Flag) -> ProbeResult<()> {
    FILE_TRACKING
        .get_ptr_mut(&file_key(file)?)
        .map(|f| (*f).unset(flag));
    Ok(())
}

#[inline(always)]
unsafe fn file_key(file: &co_re::file) -> ProbeResult<FileKey> {
    let ino = core_read_kernel!(file, f_inode, i_ino)?;
    let task_id = bpf_task_tracking_id();
    Ok(FileKey(task_id, ino))
}

// (task_id, sampling_ts): counter
#[map]
static mut THROTTLE: LruPerCpuHashMap<(u64, u64), u64> =
    LruPerCpuHashMap::with_max_entries(8192, 0);

const SAMPLING_NS: u64 = 1_000_000_000;
const SAMPLES_IN_1S: u64 = 1;

#[inline(always)]
unsafe fn events_per_sampling(task_id: u64) -> u64 {
    let sampling_ts = bpf_ktime_get_ns().div(SAMPLING_NS);

    let key = (task_id, sampling_ts);

    if let Some(c) = THROTTLE.get_ptr_mut(&key) {
        *c += 1;
        *c
    } else {
        ignore_result!(THROTTLE.insert(&key, &1, 0));
        1
    }
}

#[inline(always)]
unsafe fn is_task_fs_limit_reach(limit: u64) -> (bool, bool) {
    let eps = events_per_sampling(bpf_task_tracking_id());
    if eps >= limit {
        return (true, eps == limit);
    }
    (false, false)
}

#[inline(always)]
unsafe fn is_global_fs_limit_reach(limit: u64) -> (bool, bool) {
    let eps = events_per_sampling(0);
    if eps >= limit {
        return (true, eps == limit);
    }
    (false, false)
}

#[inline(always)]
unsafe fn limit_eps_with_context<C: EbpfContext>(ctx: &C) -> ProbeResult<bool> {
    let cfg = get_cfg!()?;

    // we convert event/s to event/sampling
    let (Some(glob_limit), Some(task_limit)) = (
        cfg.glob_max_eps_fs.map(|m| m.div(SAMPLES_IN_1S)),
        cfg.task_max_eps_fs.map(|m| m.div(SAMPLES_IN_1S)),
    ) else {
        // if there is no limit we do not throttle
        return Ok(false);
    };

    // we allow a process to take alone half of this otherwise we report it
    if let (true, limit) = is_task_fs_limit_reach(task_limit) {
        if limit {
            let event = alloc::alloc_zero::<ErrorEvent>()?;
            event.init_from_current_task(Type::Error)?;
            event.data.error = bpf_events::error::Error::TaskThrottleFs;
            pipe_event(ctx, event);
        }
        return Ok(true);
    }

    // if there are too many I/O globally a random task can see its I/O ignored
    if let (true, limit) = is_global_fs_limit_reach(glob_limit) {
        if limit {
            let event = alloc::alloc_zero::<ErrorEvent>()?;
            event.init_from_current_task(Type::Error)?;
            event.data.error = bpf_events::error::Error::GlobalThrottleFs;
            pipe_event(ctx, event);
        }
        return Ok(true);
    }

    Ok(false)
}

/// match-proto:v5.0:fs/read_write.c:ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
/// match-proto:latest:fs/read_write.c:ssize_t vfs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
#[kprobe(function = "vfs_read")]
pub fn fs_vfs_read(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_vfs_read(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

/// match-proto:v5.0:fs/read_write.c:ssize_t vfs_readv(struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
/// match-proto:v5.10:fs/read_write.c:static ssize_t vfs_readv(struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
/// match-proto:latest:fs/read_write.c:static ssize_t vfs_readv(struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
#[kprobe(function = "vfs_readv")]
pub fn fs_vfs_readv(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

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
    if file_match_flag(&file, READ)? {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<FileEvent>()?;

    ignore_result!(inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve filename", (*e).into())
    ));

    if event.data.path.starts_with("/etc/") {
        event.init_from_current_task(Type::ReadConfig)?;
        pipe_event(ctx, event);
    } else if config.is_event_enabled(Type::Read) && !event.data.path.starts_with("/proc/") {
        // we rate limit this event
        if limit_eps_with_context(ctx)? {
            return Ok(());
        }
        // we filter out procfs because it generates too much events
        // maybe let the choice through a configuration option
        event.init_from_current_task(Type::Read)?;
        pipe_event(ctx, event);
    }

    // we mark file as being tracked
    ignore_result!(inspect_err!(file_set_flag(&file, READ), |_| warn!(
        ctx,
        "failed to track file read"
    )));

    Ok(())
}

/// match-proto:v5.0:fs/read_write.c:ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
/// match-proto:latest:fs/read_write.c:ssize_t vfs_write(struct file *file, const char __user *buf, size_t count, loff_t *pos)
#[kprobe(function = "vfs_write")]
pub fn fs_vfs_write(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_vfs_write(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

/// match-proto:v5.0:fs/read_write.c:static ssize_t vfs_writev(struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
/// match-proto:latest:fs/read_write.c:static ssize_t vfs_writev(struct file *file, const struct iovec __user *vec, unsigned long vlen, loff_t *pos, rwf_t flags)
#[kprobe(function = "vfs_writev")]
pub fn fs_vfs_writev(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

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

    // we track write on close anyway
    file_set_flag(&file, CLOSE_AFTER_WRITE)?;

    // if file has already been tracked
    if file_match_flag(&file, WRITE)? {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<FileEvent>()?;

    ignore_result!(inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve filename", (*e).into())
    ));

    if event.data.path.starts_with("/etc/") {
        event.init_from_current_task(Type::WriteConfig)?;
        pipe_event(ctx, event);
    } else if config.is_event_enabled(Type::Write) {
        // we rate limit this event
        if limit_eps_with_context(ctx)? {
            return Ok(());
        }
        event.init_from_current_task(Type::Write)?;
        pipe_event(ctx, event);
    }

    // we mark file as being tracked
    ignore_result!(inspect_err!(file_set_flag(&file, WRITE), |_| warn!(
        ctx,
        "failed to track file write"
    )));

    Ok(())
}

/// match-proto:v5.0:security/security.c:int security_path_rename(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
/// match-proto:latest:security/security.c:int security_path_rename(const struct path *old_dir, struct dentry *old_dentry, const struct path *new_dir, struct dentry *new_dentry, unsigned int flags)
#[kprobe(function = "security_path_rename")]
pub fn fs_security_path_rename(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_path_rename(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_path_rename(ctx: &ProbeContext) -> ProbeResult<()> {
    // if event is disabled we return
    if_disabled_return!(Type::FileRename, ());

    let old_dir = co_re::path::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);
    let old_dentry = co_re::dentry::from_ptr(ctx.arg(1).ok_or(ProbeError::KProbeArgFailure)?);
    let new_dir = co_re::path::from_ptr(ctx.arg(2).ok_or(ProbeError::KProbeArgFailure)?);
    let new_dentry = co_re::dentry::from_ptr(ctx.arg(3).ok_or(ProbeError::KProbeArgFailure)?);

    // we handle only file renaming for the moment
    if !core_read_kernel!(old_dentry, is_file)? {
        return Ok(());
    }

    // we rate limit this event
    if limit_eps_with_context(ctx)? {
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

/// match-proto:v5.0:security/security.c:int security_path_unlink(const struct path *dir, struct dentry *dentry)
/// match-proto:latest:security/security.c:int security_path_unlink(const struct path *dir, struct dentry *dentry)
#[kprobe(function = "security_path_unlink")]
pub fn fs_security_path_unlink(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_path_unlink(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_path_unlink(ctx: &ProbeContext) -> ProbeResult<()> {
    // if event is disabled we return
    if_disabled_return!(Type::FileUnlink, ());

    let dir = co_re::path::from_ptr(kprobe_arg!(ctx, 0)?);
    let entry = co_re::dentry::from_ptr(kprobe_arg!(ctx, 1)?);

    alloc::init()?;
    let p = alloc::alloc_zero::<Path>()?;

    p.prepend_dentry(&entry)?;
    p.core_resolve(&dir, MAX_PATH_DEPTH)?;

    // as vfs_unlink can be reached without security_path_unlink being called
    // we report error when insertion is failing
    PATHS
        .insert(&ProbeFn::security_path_unlink.depth_key(), p, 0)
        .map_err(|_| MapError::InsertFailure)?;

    Ok(())
}

/// we have to hook into vfs_unlink (called by do_unlinkat) and recovering
/// path argument from the security_path_unlink call happening before.
/// do_unlinkat cannot be hooked at ret as path/dentry we wanna parse
/// seems to be cleaned up and cannot be parsed correctly.
///
/// match-proto:v5.0:fs/namei.c:int vfs_unlink(struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
/// match-proto:v5.12:fs/namei.c:int vfs_unlink(struct user_namespace *mnt_userns, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
/// match-proto:v6.3:fs/namei.c:int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct inode **delegated_inode)
/// match-proto:v6.19:fs/namei.c:int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct delegated_inode *delegated_inode)
/// match-proto:latest:fs/namei.c:int vfs_unlink(struct mnt_idmap *idmap, struct inode *dir, struct dentry *dentry, struct delegated_inode *delegated_inode)
#[kretprobe(function = "vfs_unlink")]
pub fn fs_exit_vfs_unlink(ctx: RetProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_vfs_unlink(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_vfs_unlink(ctx: &RetProbeContext) -> ProbeResult<()> {
    // if event is disabled we return
    if_disabled_return!(Type::FileUnlink, ());

    // we rate limit this event
    if limit_eps_with_context(ctx)? {
        return Ok(());
    }

    let rc: c_int = ctx.ret().unwrap_or(-1);

    alloc::init()?;
    let e = alloc::alloc_zero::<UnlinkEvent>()?;

    e.init_from_current_task(Type::FileUnlink)?;

    let path_key = ProbeFn::security_path_unlink.depth_key();
    if let Some(p) = PATHS.get(&path_key) {
        e.data.path.copy_from(p);
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

/// catching calls to close_range syscall
/// fput is an async function, meaning file might not be
/// closed immediately. This is the function called when
/// a task terminates and its fds are closed. In such
/// a case it is probable events generated appear after
/// task has terminated. If that is the case there is
/// not much we can do for event re-ordering.
///
/// match-proto:v5.0:fs/file_table.c:void fput(struct file *file)
/// match-proto:latest:fs/file_table.c:void fput(struct file *file)
#[kprobe(function = "fput")]
pub fn fs_enter_fput(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_enter_fput(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

/// this is the synchronous version of fput. This
/// function gets called by the close syscall
///
/// match-proto:v5.0:fs/file_table.c:void __fput_sync(struct file *file)
/// match-proto:latest:fs/file_table.c:void __fput_sync(struct file *file)
#[kprobe(function = "__fput_sync")]
pub fn fs_enter_fput_sync(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_enter_fput(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

#[map]
static mut WRITE_CLOSE_CACHE: LruHashMap<(u64, u64, path::MapKey), bool> =
    LruHashMap::with_max_entries(4096, 0);

#[inline(always)]
unsafe fn try_enter_fput(ctx: &ProbeContext) -> ProbeResult<()> {
    // if event is disabled we return early
    if get_cfg!().map(|c| c.is_event_disabled(Type::WriteClose))? {
        return Ok(());
    }

    let file = co_re::file::from_ptr(kprobe_arg!(&ctx, 0)?);

    // if not a regular file we do nothing
    if !core_read_kernel!(file, is_file).unwrap_or(false) {
        return Ok(());
    }

    // if file has not been written we return
    if !file_match_flag(&file, CLOSE_AFTER_WRITE)? {
        return Ok(());
    }

    alloc::init()?;

    let event = alloc::alloc_zero::<FileEvent>()?;

    event.init_from_current_task(Type::WriteClose)?;

    ignore_result!(inspect_err!(
        event.data.path.core_resolve_file(&file, MAX_PATH_DEPTH),
        |e: &path::Error| warn!(ctx, "failed to resolve filename", (*e).into())
    ));

    // we create a unique key for path
    let k = (
        bpf_ktime_get_ns().div(100_000_000),
        bpf_task_tracking_id(),
        event.data.path.map_key(),
    );

    // we already generated an event for this path less than 100ms ago
    // so we ignore it
    if WRITE_CLOSE_CACHE.get(&k).is_some() {
        return Ok(());
    }

    ignore_result!(WRITE_CLOSE_CACHE.insert(&k, &true, 0));

    // make this check only here as we want to filter out
    // already known paths first
    if limit_eps_with_context(ctx)? {
        return Ok(());
    }

    // we send event
    pipe_event(ctx, event);

    // we untrack write on close as we want to catch
    // other instances in case the process closes, re-open
    // and re-write the file
    file_unset_flag(&file, CLOSE_AFTER_WRITE)
}

const FMODE_CREATED: u32 = 0x100000;

/// this probe aims at catching file creation event
///
/// match-proto:v5.0:security/security.c:int security_file_open(struct file *file)
/// match-proto:latest:security/security.c:int security_file_open(struct file *file)
#[kprobe(function = "security_file_open")]
pub fn fs_security_file_open(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_file_open(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_file_open(ctx: &ProbeContext) -> ProbeResult<()> {
    // if event is disabled we return
    if_disabled_return!(Type::FileCreate, ());

    let file = co_re::file::from_ptr(kprobe_arg!(ctx, 0)?);

    // if not FMODE_CREATED we return
    if !file.f_mode().unwrap_or_default() & FMODE_CREATED == FMODE_CREATED {
        return Ok(());
    }

    // we rate limit this event
    if limit_eps_with_context(ctx)? {
        return Ok(());
    }

    alloc::init()?;
    let e = alloc::alloc_zero::<FileEvent>()?;

    e.init_from_current_task(Type::FileCreate)?;

    e.data.path.core_resolve_file(&file, MAX_PATH_DEPTH)?;

    // we send event
    pipe_event(ctx, e);

    Ok(())
}
