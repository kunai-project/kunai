use super::Event;
use crate::path::Path;

pub type ConfigEvent = Event<ConfigData>;

#[repr(C)]
pub struct ConfigData {
    pub path: Path,
}

pub type FileRenameEvent = Event<FileRenameData>;

#[repr(C)]
pub struct FileRenameData {
    pub old_name: Path,
    pub new_name: Path,
}
