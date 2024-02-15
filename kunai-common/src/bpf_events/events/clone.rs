use crate::{
    bpf_events::{Event, Nodename},
    buffer::Buffer,
    cgroup::Cgroup,
    path::Path,
};

use super::MAX_ARGV_SIZE;

pub type CloneEvent = Event<CloneData>;

#[repr(C)]
pub struct CloneData {
    pub flags: u64,
    pub executable: Path,
    pub argv: Buffer<MAX_ARGV_SIZE>,
    pub cgroup: Cgroup,
    pub nodename: Nodename,
}

#[cfg(test)]
mod test {
    use core::mem::MaybeUninit;

    use super::CloneData;

    #[test]
    fn test_zeroed_nodename() {
        let d = unsafe { MaybeUninit::<CloneData>::zeroed().assume_init() };
        assert!(d.nodename.is_none());
    }
}
