use super::Event;
use crate::path::Path;
use crate::string::String;

pub type MountEvent = Event<MountData>;

#[repr(C)]
pub struct MountData {
    pub dev_name: String<1024>,
    pub path: Path,
    pub ty: String<64>,
    pub rc: i32,
}
