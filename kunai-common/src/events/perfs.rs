use crate::bpf_target_code;

pub const EVENTS_MAP_NAME: &str = "KUNAI_EVENTS";

bpf_target_code! {
    use super::Event;
    use aya_bpf::{macros::map, maps::PerfEventByteArray, BpfContext};

    #[map(name = "KUNAI_EVENTS")]
    static mut EVENTS: PerfEventByteArray = PerfEventByteArray::with_max_entries(4096, 0);

    pub unsafe fn pipe_event<C: BpfContext, T>(ctx: &C, e: &Event<T>) {
        EVENTS.output(ctx, e.encode(), 0);
    }
}
