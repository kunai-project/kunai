use crate::bpf_events::Event;
use crate::string::String;

pub type InitModuleEvent = Event<InitModuleData>;

#[repr(C)]
pub struct Init {
    pub umod: u64,
    pub len: u64,
    pub uargs: u64,
}

#[repr(C)]
pub struct FInit {
    pub fd: u64,
    pub uargs: u64,
    pub flags: u64,
}

#[repr(C)]
pub enum InitModuleArgs {
    Init(Init),
    FInit(FInit),
}

impl InitModuleArgs {
    pub fn uargs(&self) -> u64 {
        match self {
            Self::Init(a) => a.uargs,
            Self::FInit(a) => a.uargs,
        }
    }
}

impl From<Init> for InitModuleArgs {
    fn from(value: Init) -> Self {
        Self::Init(value)
    }
}

impl From<FInit> for InitModuleArgs {
    fn from(value: FInit) -> Self {
        Self::FInit(value)
    }
}

#[repr(C)]
pub struct InitModuleData {
    pub name: String<256>,
    pub args: InitModuleArgs,
    pub uargs: String<256>,
    pub loaded: bool,
}
