use super::*;
use aya_bpf::maps::LruHashMap;
use aya_bpf::programs::ProbeContext;
use co_re::task_struct;
use kunai_common::inspect_err;

#[map]
static mut MARKED: LruHashMap<u128, bool> = LruHashMap::with_max_entries(0x8000, 0);

/*
The idea behind this probe is being able to reconstruct the list of ancestors
of a process even if we missed its creation via execve. To do so, the first thing
comming to my mind was to hook the scheduling routine and collect information such
as the command line and the executable path. However, it seems impossible to reliably
know the script executed (if any). Exception made to scripts executed from an absolute path,
which will be contained in argv. For relative scripts we cannot know whether they
got executed from current directory or from another directory via execveat syscall.
 */

/*
The second use of this probe is to track forked tasks, which is useful to get a
consistent ancestor/parent tracking.
*/

// It should be enough to get scheduling of all userland tasks
#[kprobe(name = "sched.schedule")]
pub fn schedule(ctx: ProbeContext) -> u32 {
    match unsafe { try_schedule(&ctx) } {
        Ok(_) => error::BPF_PROG_SUCCESS,
        Err(s) => {
            log_err!(&ctx, s);
            error::BPF_PROG_FAILURE
        }
    }
}

#[inline(always)]
unsafe fn try_schedule(ctx: &ProbeContext) -> ProbeResult<()> {
    let ts = task_struct::current();
    let task_uuid = ts.uuid();

    // we don't need to process the task again this way we don't handle in
    // userland tasks we already know
    if MARKED.get(&task_uuid).is_some() {
        return Ok(());
    }

    alloc::init()?;
    let event = alloc::alloc_zero::<ScheduleEvent>()?;

    let mm = core_read_kernel!(ts, mm)?;

    if mm.is_null() {
        return Ok(());
    }

    let arg_start = core_read_kernel!(mm, arg_start)?;
    let arg_len = core_read_kernel!(mm, arg_len)?;

    // we check that arg_start is not a null pointer
    if arg_start != 0 && arg_len != 0 {
        ignore_result!(inspect_err!(
            event
                .data
                .argv
                .read_user_at(arg_start as *const u8, arg_len as u32),
            |_| error!(
                ctx,
                "failed to read argv: arg_start=0x{:x} arg_len={}", arg_start, arg_len
            )
        ));
    }

    let exe_file = core_read_kernel!(mm, exe_file)?;
    ignore_result!(inspect_err!(
        event.data.exe.core_resolve_file(&exe_file, MAX_PATH_DEPTH),
        |e: &path::Error| error!(ctx, "failed to resolve exe: {}", e.description())
    ));

    if event.data.exe.is_empty() && event.data.argv.is_empty() {
        return Ok(());
    }

    let cgroup = core_read_kernel!(ts, sched_task_group, css, cgroup)?;

    event.data.cgroup.resolve(cgroup)?;

    event.init_from_current_task(Type::TaskSched)?;

    // we do not really care if that is failing
    ignore_result!(inspect_err!(MARKED.insert(&task_uuid, &true, 0), |_| {
        error!(ctx, "failed to track task")
    }));

    // we send event to userland
    pipe_event(ctx, event);

    Ok(())
}
