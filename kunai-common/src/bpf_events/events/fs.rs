use crate::bpf_events::Event;
use crate::path::Path;

pub type FileEvent = Event<FileData>;

#[repr(C)]
pub struct FileData {
    pub path: Path,
}

pub type FileRenameEvent = Event<FileRenameData>;

#[repr(C)]
pub struct FileRenameData {
    pub old_name: Path,
    pub new_name: Path,
}

pub type UnlinkEvent = Event<UnlinkData>;

#[repr(C)]
pub struct UnlinkData {
    pub path: Path,
    pub success: bool,
}
