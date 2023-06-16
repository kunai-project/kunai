use crate::{bpf_target_code, not_bpf_target_code};

const CONFIG_MAP_NAME: &str = "KUNAI_CONFIG_ARRAY";

#[derive(Debug, Clone, Copy)]
pub struct Loader {
    pub tgid: u32,
}

not_bpf_target_code! {
    impl Loader {
        pub fn from_own_pid() -> Self {
            Loader{
                tgid: std::process::id(),
            }
        }
    }
}

not_bpf_target_code! {
    /// Kunai configuration structure to be used in userland
    pub struct Config {}

}

/// Structure holding configuration to use in eBPF programs
#[derive(Debug, Clone, Copy)]
pub struct BpfConfig {
    pub loader: Loader,
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
    }
}

not_bpf_target_code! {
    use aya::{
        Bpf,
        maps::Array,
        Pod,
    };

    unsafe impl Pod for BpfConfig{}

    impl From<Config> for BpfConfig{
        fn from(value: Config) -> Self {
            Self{
                loader: Loader::from_own_pid(),
            }
        }
    }

    impl BpfConfig {
        pub fn init_config_in_bpf(bpf: &mut Bpf, config: Self) {
            let mut bpf_config = Array::try_from(bpf.map_mut(CONFIG_MAP_NAME).expect(
                &(CONFIG_MAP_NAME.to_owned() + "map should not be missing, maybe you forgot using it your eBPF code"),
            ))
            .expect(&(CONFIG_MAP_NAME.to_owned() + "should be a valid Array"));
            bpf_config.set(0, config, 0).unwrap();
        }
    }

}
