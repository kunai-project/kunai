use crate::{bpf_events::Event, creds::Creds};

pub type CommitCredsEvent = Event<CommitCredsData>;

#[repr(C)]
pub struct CommitCredsData {
    pub old: Creds,
    pub new: Creds,
}
