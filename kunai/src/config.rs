use core::str::FromStr;
use huby::ByteSize;
use kunai_common::{
    bpf_events,
    config::{BpfConfig, Filter, Loader},
};
use serde::{Deserialize, Serialize};
use std::fs;
use thiserror::Error;

pub const DEFAULT_SEND_DATA_MIN_LEN: u64 = 256;
pub const DEFAULT_MAX_BUFFERED_EVENTS: u16 = 1024;

#[derive(Error, Debug)]
pub enum Error {
    #[error("invalid output {0}")]
    InvalidOutput(String),
    #[error("invalid event {0}")]
    InvalidEvent(String),
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Event {
    name: String,
    enable: bool,
}

impl Event {
    #[inline(always)]
    pub fn name(&self) -> &str {
        &self.name
    }

    #[inline(always)]
    pub fn disable(&mut self) {
        self.enable = false
    }

    #[inline(always)]
    pub fn enable(&mut self) {
        self.enable = true
    }

    #[inline(always)]
    pub fn is_enabled(&self) -> bool {
        self.enable
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FileSettings {
    pub rotate_size: ByteSize,
    pub max_size: ByteSize,
}

/// Kunai configuration structure to be used in userland
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    host_uuid: Option<uuid::Uuid>,
    pub output: String,
    pub output_settings: Option<FileSettings>,
    pub max_buffered_events: u16,
    pub workers: Option<usize>,
    pub send_data_min_len: Option<u64>,
    pub rules: Vec<String>,
    pub iocs: Vec<String>,
    pub yara: Vec<String>,
    pub always_show_positive_scans: bool,
    pub harden: bool,
    pub events: Vec<Event>,
}

impl Default for Config {
    fn default() -> Self {
        let mut events = vec![];
        for v in bpf_events::Type::variants() {
            // some events get disabled by default because there are too many
            let en = !matches!(v, bpf_events::Type::Read | bpf_events::Type::Write);

            if v.is_configurable() {
                events.push(Event {
                    name: v.as_str().into(),
                    enable: en,
                })
            }
        }

        Self {
            host_uuid: None,
            output: "/dev/stdout".into(),
            output_settings: None,
            max_buffered_events: DEFAULT_MAX_BUFFERED_EVENTS,
            workers: None,
            send_data_min_len: None,
            rules: vec![],
            iocs: vec![],
            yara: vec![],
            always_show_positive_scans: true,
            harden: false,
            events,
        }
    }
}

fn host_uuid() -> Option<uuid::Uuid> {
    if let Ok(machine_id) = fs::read_to_string("/etc/machine-id") {
        let machine_id = machine_id.trim_end();
        // we do not generate uuid if machine_id is empty string
        if machine_id.is_empty() {
            return None;
        }
        return Some(uuid::Uuid::new_v5(
            &uuid::Uuid::NAMESPACE_OID,
            machine_id.as_bytes(),
        ));
    }
    None
}

impl Config {
    pub fn default_hardened() -> Self {
        Self {
            harden: true,
            ..Default::default()
        }
    }

    pub fn host_uuid(&self) -> Option<uuid::Uuid> {
        // host_uuid in config supersedes system host_uuid
        self.host_uuid.or(host_uuid())
    }

    pub fn stdout_output(mut self) -> Self {
        self.output = "stdout".into();
        self
    }

    pub fn generate_host_uuid(&mut self) {
        self.host_uuid = host_uuid().or(Some(uuid::Uuid::new_v4()));
    }

    pub fn to_toml(&self) -> Result<String, toml::ser::Error> {
        toml::to_string(self)
    }

    pub fn from_toml<S: AsRef<str>>(toml: S) -> Result<Self, toml::de::Error> {
        toml::from_str(toml.as_ref())
    }

    pub fn validate(&self) -> Result<(), Error> {
        for e in self.events.iter() {
            let Ok(ty) = bpf_events::Type::from_str(&e.name) else {
                return Err(Error::InvalidEvent(e.name.clone()));
            };

            if !ty.is_configurable() {
                return Err(Error::InvalidEvent(e.name.clone()));
            }
        }
        Ok(())
    }

    pub fn enable_all(&mut self) {
        self.events.iter_mut().for_each(|e| e.enable())
    }

    pub fn disable_all(&mut self) {
        self.events.iter_mut().for_each(|e| e.disable())
    }
}

impl TryFrom<Config> for Filter {
    type Error = Error;

    fn try_from(value: Config) -> Result<Self, Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Config> for Filter {
    type Error = Error;

    fn try_from(value: &Config) -> Result<Self, Error> {
        let mut filter = Filter::all_disabled();

        for e in value.events.iter() {
            // config should have been verified so it should not fail
            let ty = bpf_events::Type::from_str(&e.name)
                .map_err(|_| Error::InvalidEvent(e.name.clone()))?;
            // we enable event in BpfConfig only if it has been configured
            if e.enable {
                filter.enable(ty);
            }
        }

        Ok(filter)
    }
}

impl TryFrom<Config> for BpfConfig {
    type Error = Error;

    fn try_from(value: Config) -> Result<Self, Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Config> for BpfConfig {
    type Error = Error;

    fn try_from(value: &Config) -> Result<Self, Error> {
        Ok(Self {
            loader: Loader::from_own_pid(),
            filter: value.try_into()?,
            send_data_min_len: value.send_data_min_len.unwrap_or(DEFAULT_SEND_DATA_MIN_LEN),
        })
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_serialize() {
        let config = Config {
            ..Default::default()
        };

        config.validate().unwrap();

        println!("{}", toml::to_string_pretty(&config).unwrap());
    }

    #[test]
    fn test_machine_uuid() {
        let uuid = host_uuid();
        assert!(uuid.is_some());
        println!("machine uuid: {}", uuid.unwrap())
    }
}
