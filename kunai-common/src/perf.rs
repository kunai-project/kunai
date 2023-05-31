use crate::not_bpf_target_code;

not_bpf_target_code! {
    use bytes::BytesMut;
    use core::cmp::min;

    pub fn optimal_page_count(page_size: usize, max_event_size: usize, n_events: usize) -> usize {
        let c = (max_event_size * n_events) / page_size;
        2usize.pow(c.ilog2() + 1)
    }

    pub fn event_buffers(max_event_size: usize, count: usize, max_count: usize) -> Vec<BytesMut> {
        (0..count)
        .map(|_| BytesMut::with_capacity(min(max_event_size, max_count)))
        .collect::<Vec<_>>()
    }

}
