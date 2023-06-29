use crate::{bpf_target_code, events, not_bpf_target_code};

// analyzer does not see both target so we can allow dead code
// to prevent warnings to happen
#[allow(dead_code)]
const CONFIG_MAP_NAME: &str = "KUNAI_CONFIG_ARRAY";

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Loader {
    pub tgid: u32,
}

not_bpf_target_code! {
    impl Loader {
        pub fn from_own_pid() -> Self {
            // std::process::id returns the process ID which
            // turns to be the equivalent of the tgid
            Loader{
                tgid: std::process::id(),
            }
        }
    }
}

const FILTER_SIZE: usize = events::Type::Max as usize;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Filter {
    enabled: [bool; FILTER_SIZE],
}

impl Filter {
    pub fn all_enabled() -> Self {
        Self {
            enabled: [true; FILTER_SIZE],
        }
    }

    pub fn all_disabled() -> Self {
        Self {
            enabled: [false; FILTER_SIZE],
        }
    }

    pub fn disable(&mut self, ty: events::Type) {
        self.enabled[ty as usize] = false;
    }

    pub fn enable(&mut self, ty: events::Type) {
        self.enabled[ty as usize] = true;
    }

    pub fn is_enabled(&self, ty: events::Type) -> bool {
        self.enabled[ty as usize]
    }
}

not_bpf_target_code! {}

/// Structure holding configuration to use in eBPF programs
//#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfConfig {
    pub loader: Loader,
    pub filter: Filter,
}

// specific structure implementation to be used in eBPF
bpf_target_code! {
    use aya_bpf::maps::Array;
    use aya_bpf::macros::map;
    use aya_bpf::helpers::bpf_get_current_pid_tgid;

    #[map]
    static mut KUNAI_CONFIG_ARRAY: Array<BpfConfig> = Array::with_max_entries(1, 0);

    /// Function to retrieve configuration into eBPF code
    pub unsafe fn config() -> Option<&'static BpfConfig> {
        KUNAI_CONFIG_ARRAY.get(0)
    }

    impl BpfConfig {
        pub unsafe fn current_is_loader(&self) -> bool {
            bpf_get_current_pid_tgid() as u32 == self.loader.tgid
        }

        pub fn is_event_enabled(&self, ty: events::Type) -> bool {
            self.filter.is_enabled(ty)
        }
    }
}

not_bpf_target_code! {
    use aya::{
        Bpf,
        maps::{MapError,Array},
        Pod,
    };

    unsafe impl Pod for BpfConfig{}

    impl BpfConfig {
        pub fn init_config_in_bpf(bpf: &mut Bpf, conf: Self) -> Result<(), MapError> {
            let mut bpf_config = Array::try_from(bpf.map_mut(CONFIG_MAP_NAME).expect(
                &(CONFIG_MAP_NAME.to_owned() + "map should not be missing, maybe you forgot using it your eBPF code"),
            ))
            .expect(&(CONFIG_MAP_NAME.to_owned() + "should be a valid Array"));
            bpf_config.set(0, conf, 0)
        }
    }

}
