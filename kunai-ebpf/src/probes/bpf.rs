use super::*;
use aya_ebpf::{
    maps::LruHashMap,
    programs::{ProbeContext, RetProbeContext},
};

#[map]
static mut BPF_PROG_TRACK: LruHashMap<u64, co_re::bpf_prog> = LruHashMap::with_max_entries(1024, 0);

// this function gets called at the end of bpf_prog_load
// and contains all useful information about program
// being loaded
#[kprobe(function = "security_bpf_prog")]
pub fn entry_security_bpf_prog(ctx: ProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_security_bpf_prog(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_security_bpf_prog(ctx: &ProbeContext) -> ProbeResult<()> {
    let bpf_prog = co_re::bpf_prog::from_ptr(ctx.arg(0).ok_or(ProbeError::KProbeArgFailure)?);

    ignore_result!(BPF_PROG_TRACK.insert(&bpf_task_tracking_id(), &bpf_prog, 0));

    Ok(())
}

// this probe gets executed after security_bpf_prog because of fexit
#[kretprobe(function = "bpf_prog_load")]
pub fn exit_bpf_prog_load(ctx: RetProbeContext) -> u32 {
    if is_current_loader_task() {
        return 0;
    }

    match unsafe { try_bpf_prog_load(&ctx) } {
        Ok(_) => errors::BPF_PROG_SUCCESS,
        Err(s) => {
            error!(&ctx, s);
            errors::BPF_PROG_FAILURE
        }
    }
}

unsafe fn try_bpf_prog_load(ctx: &RetProbeContext) -> ProbeResult<()> {
    let rc = ctx.ret().unwrap_or(-1);
    let key = bpf_task_tracking_id();

    if let Some(bpf_prog) = BPF_PROG_TRACK.get(&key) {
        alloc::init()?;

        let bpf_prog_aux = core_read_kernel!(bpf_prog, aux)?;

        let event = alloc::alloc_zero::<BpfProgLoadEvent>()?;

        if let Some(ksym) = bpf_prog_aux.ksym() {
            if let Some(p_name) = ksym.name() {
                ignore_result!(event.data.ksym.read_kernel_str_bytes(p_name));
            }
        }

        event.data.id = core_read_kernel!(bpf_prog_aux, id)?;
        event.data.tag = core_read_kernel!(bpf_prog, tag_array)?;

        if let Some(p_name) = bpf_prog_aux.name() {
            ignore_result!(inspect_err!(
                event.data.name.read_kernel_str_bytes(p_name),
                |_| warn_msg!(ctx, "failed to read program name")
            ));
        }

        event.data.prog_type = bpf_prog.ty().unwrap_or_default();
        event.data.attach_type = bpf_prog.expected_attach_type().unwrap_or_default();

        // problematic on ubuntu 22.04 (kernel 5.15.0-70-generic)
        // needs to be implemented like that not to cause a read_ok! verifier error
        // on some kernels
        if let Some(vi) = bpf_prog_aux.verified_insns() {
            event.data.verified_insns = Some(vi)
        }

        // get attached_func_name
        if let Some(afn) = bpf_prog_aux.attach_func_name() {
            ignore_result!(inspect_err!(
                event.data.attached_func_name.read_kernel_str_bytes(afn),
                |_| warn_msg!(ctx, "failed to read attach_func_name")
            ));
        }

        // initializing event from task
        event.init_from_current_task(Type::BpfProgLoad)?;

        // successful loading if rc > 0
        event.data.loaded = rc > 0;

        pipe_event(ctx, event);
    } else {
        error_msg!(ctx, "failed to retrieve BPF program load event")
    }

    // we use a LruHashmap so we can safely ignore result
    ignore_result!(BPF_PROG_TRACK.remove(&key));

    Ok(())
}
