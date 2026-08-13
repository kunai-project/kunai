use crate::{bpf_events::Event, creds::CredSnapshot};

pub type CommitCredsEvent = Event<CommitCredsData>;

#[repr(C)]
pub struct CommitCredsData {
    pub old: CredSnapshot,
    pub new: CredSnapshot,
}
