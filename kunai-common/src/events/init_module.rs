use super::Event;
use crate::string::String;

pub type InitModuleEvent = Event<InitModuleData>;

#[repr(C)]
pub struct InitModuleData {
    pub name: String<256>,
    pub umod: u64,
    pub len: u64,
    pub uargs: String<256>,
    pub loaded: bool,
}
