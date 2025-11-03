use super::{BpfConfig, Loader, CONFIG_MAP_NAME};
use aya::{
    maps::{Array, MapError},
    Ebpf, Pod,
};

impl Loader {
    pub fn from_own_pid() -> Self {
        // std::process::id returns the process ID which
        // turns to be the equivalent of the tgid
        Loader {
            tgid: std::process::id(),
        }
    }
}

unsafe impl Pod for BpfConfig {}

impl BpfConfig {
    pub fn init_config_in_bpf(bpf: &mut Ebpf, conf: Self) -> Result<(), MapError> {
        let mut bpf_config = Array::try_from(bpf.map_mut(CONFIG_MAP_NAME).unwrap_or_else(|| {
            panic!(
                "{}",
                (CONFIG_MAP_NAME.to_owned()
                    + "map should not be missing, maybe you forgot using it your eBPF code")
            )
        }))
        .unwrap_or_else(|_| {
            panic!(
                "{}",
                (CONFIG_MAP_NAME.to_owned() + "should be a valid Array")
            )
        });
        bpf_config.set(0, conf, 0)
    }
}
