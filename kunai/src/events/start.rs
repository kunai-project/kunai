use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::cache::Hashes;

/// System related information
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct SystemData {
    /// Uptime in seconds (read from /proc/uptime)
    pub uptime: Option<f64>,
    /// Boot time computed from uptime
    pub boot_time: Option<DateTime<Utc>>,
    /// Utsname information, except nodename
    /// which duplicates information in
    /// .info.host.name
    pub sysname: String,
    pub release: String,
    pub version: String,
    pub machine: String,
    pub domainname: String,
}

/// System related information
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct ConfigData {
    pub sha256: String,
}

/// Encodes Kunai related data
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct KunaiData {
    /// Version
    pub version: String,
    /// Information about executable
    pub exe: Hashes,
    /// Configuration related data
    pub config: ConfigData,
}

/// Structure holding information we want
/// to display in start events
#[derive(Default, Debug, Serialize, Deserialize)]
pub struct StartData {
    pub system: SystemData,
    pub kunai: KunaiData,
}

impl StartData {
    pub fn new() -> Self {
        Default::default()
    }
}
