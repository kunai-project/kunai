use aya_ebpf::helpers::bpf_get_current_pid_tgid;

#[inline(always)]
pub fn bpf_task_tracking_id() -> u64 {
    bpf_get_current_pid_tgid()
}
