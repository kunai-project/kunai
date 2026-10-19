use crate::{bpf_events::Event, user_ns::UserNs};

pub type UserNsMapEvent = Event<UserNsMapData>;

/// Emitted after a successful write to a user namespace's uid_map or gid_map.
#[repr(C)]
pub struct UserNsMapData {
    pub user_ns: UserNs,
}
