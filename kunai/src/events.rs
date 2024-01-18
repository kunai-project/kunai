use std::{
    borrow::Cow,
    collections::HashSet,
    fmt::LowerHex,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use event_derive::{Event, FieldGetter};
use gene::{Event, FieldGetter, FieldValue};

use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};

use crate::{
    cache::Hashes,
    info::{ContainerInfo, StdEventInfo},
};

#[derive(FieldGetter, Serialize, Deserialize)]
pub struct ContainerSection {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: Option<String>,
}

impl From<ContainerInfo> for ContainerSection {
    fn from(value: ContainerInfo) -> Self {
        Self {
            name: value.name,
            ty: value.ty,
        }
    }
}

#[derive(FieldGetter, Serialize, Deserialize)]
pub struct HostSection {
    #[getter(skip)]
    uuid: uuid::Uuid,
    name: String,
    container: Option<ContainerSection>,
}

#[derive(FieldGetter, Serialize, Deserialize)]
pub struct EventSection {
    source: String,
    id: u32,
    name: String,
    uuid: String,
    batch: usize,
}

impl From<&StdEventInfo> for EventSection {
    fn from(value: &StdEventInfo) -> Self {
        Self {
            source: "kunai".into(),
            id: value.info.etype.id(),
            name: value.info.etype.to_string(),
            uuid: value.info.uuid.into_uuid().hyphenated().to_string(),
            batch: value.info.batch,
        }
    }
}

#[derive(FieldGetter, Serialize, Deserialize)]
pub struct NamespaceInfo {
    mnt: u32,
}

impl From<kunai_common::bpf_events::Namespaces> for NamespaceInfo {
    fn from(value: kunai_common::bpf_events::Namespaces) -> Self {
        Self { mnt: value.mnt }
    }
}

#[derive(FieldGetter, Serialize, Deserialize)]
pub struct TaskSection {
    name: String,
    pid: i32,
    tgid: i32,
    guuid: String,
    uid: u32,
    gid: u32,
    namespaces: NamespaceInfo,
    #[serde(serialize_with = "serialize_to_hex")]
    flags: u32,
}

impl From<kunai_common::bpf_events::TaskInfo> for TaskSection {
    fn from(value: kunai_common::bpf_events::TaskInfo) -> Self {
        Self {
            name: value.comm_string(),
            pid: value.pid,
            tgid: value.tgid,
            guuid: value.tg_uuid.into_uuid().hyphenated().to_string(),
            uid: value.uid,
            gid: value.gid,
            namespaces: value.namespaces.into(),
            flags: value.flags,
        }
    }
}

pub struct UtcDateTime(DateTime<Utc>);

impl From<DateTime<Utc>> for UtcDateTime {
    fn from(value: DateTime<Utc>) -> Self {
        Self(value)
    }
}

impl From<DateTime<FixedOffset>> for UtcDateTime {
    fn from(value: DateTime<FixedOffset>) -> Self {
        Self(value.naive_utc().and_utc())
    }
}

#[inline(always)]
fn serialize_utc_ts<S>(ts: &UtcDateTime, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&ts.0.to_rfc3339_opts(SecondsFormat::Nanos, true))
}

struct UtcDateTimeVisitor;

impl<'de> Visitor<'de> for UtcDateTimeVisitor {
    type Value = UtcDateTime;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting a rfc3339 formatted timestamp")
    }

    fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
    where
        E: serde::de::Error,
    {
        DateTime::parse_from_rfc3339(&v)
            .map_err(|e| E::custom(e.to_string()))
            .map(UtcDateTime::from)
    }
}

impl<'de> Deserialize<'de> for UtcDateTime {
    fn deserialize<D>(deserializer: D) -> Result<UtcDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_string(UtcDateTimeVisitor)
    }
}

impl FieldGetter for UtcDateTime {
    fn get_from_iter(&self, i: core::slice::Iter<'_, std::string::String>) -> Option<FieldValue> {
        if i.len() > 0 {
            return None;
        }
        // currently return timestamp as millisecond, it might not be optimal
        Some(self.0.timestamp_millis().into())
    }
}

#[derive(FieldGetter, Serialize, Deserialize)]
pub struct EventInfo {
    pub host: HostSection,
    pub event: EventSection,
    pub task: TaskSection,
    pub parent_task: TaskSection,
    #[serde(serialize_with = "serialize_utc_ts")]
    pub utc_time: UtcDateTime,
}

impl From<StdEventInfo> for EventInfo {
    fn from(value: StdEventInfo) -> Self {
        Self {
            host: HostSection {
                name: value.additional.host.name,
                uuid: value.additional.host.uuid,
                container: value.additional.container.map(ContainerSection::from),
            },
            event: EventSection {
                source: "kunai".into(),
                id: value.info.etype.id(),
                name: value.info.etype.to_string(),
                uuid: value.info.uuid.into_uuid().hyphenated().to_string(),
                batch: value.info.batch,
            },
            task: value.info.process.into(),
            parent_task: value.info.parent.into(),
            utc_time: value.utc_timestamp.into(),
        }
    }
}

pub trait IocGetter {
    fn iocs(&mut self) -> Vec<Cow<'_, str>>;
}

macro_rules! impl_std_iocs {
    ($ty:ty) => {
        impl IocGetter for $ty {
            fn iocs(&mut self) -> Vec<Cow<'_, str>> {
                vec![self.exe.to_string_lossy()]
            }
        }
    };
}

#[derive(Debug, Default, Serialize, Deserialize, FieldGetter)]
pub struct ScanResult {
    /// union of the rule names matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub iocs: HashSet<String>,
    /// union of the rule names matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub rules: HashSet<String>,
    /// union of tags defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub tags: HashSet<String>,
    /// union of attack ids defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub attack: HashSet<String>,
    /// union of actions defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub actions: HashSet<String>,
    /// flag indicating whether a filter rule matched
    #[serde(skip)]
    pub filtered: bool,
    /// total severity score (bounded to [MAX_SEVERITY](rules::MAX_SEVERITY))
    pub severity: u8,
}

impl From<gene::ScanResult> for ScanResult {
    fn from(value: gene::ScanResult) -> Self {
        ScanResult {
            iocs: HashSet::new(),
            rules: value.rules,
            tags: value.tags,
            attack: value.attack,
            actions: value.actions,
            filtered: value.filtered,
            severity: value.severity,
        }
    }
}

impl ScanResult {
    #[inline(always)]
    pub fn is_detection(&self) -> bool {
        !(self.rules.is_empty() && self.iocs.is_empty())
    }

    #[inline(always)]
    pub fn is_only_filter(&self) -> bool {
        !self.is_detection() && self.is_filtered()
    }

    #[inline(always)]
    pub fn is_filtered(&self) -> bool {
        self.filtered
    }
}

pub trait KunaiEvent: ::gene::Event + ::gene::FieldGetter + IocGetter {
    fn set_detection(&mut self, sr: ScanResult);
}

#[derive(Event, FieldGetter, Serialize, Deserialize)]
#[event(id = self.info.event.id as i64, source = "kunai".into())]
pub struct UserEvent<T> {
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<ScanResult>,
    pub info: EventInfo,
}

impl<T> IocGetter for UserEvent<T>
where
    T: IocGetter,
{
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        self.data.iocs()
    }
}

impl<T> KunaiEvent for UserEvent<T>
where
    T: FieldGetter + IocGetter,
{
    fn set_detection(&mut self, sr: ScanResult) {
        self.detection = Some(sr)
    }
}

impl<T> UserEvent<T> {
    pub fn new(data: T, info: StdEventInfo) -> Self {
        Self {
            data: data,
            detection: None,
            info: info.into(),
        }
    }
}

#[inline(always)]
fn serialize_to_hex<S, T: LowerHex>(value: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{:x}", value))
}

/// helper macro helping de define standardized user data.
/// it typically create a structure with some fields all data
/// sections must have (exe, command_line ...)
///
/// # Example
///
/// ```rust,ignore
/// def_user_data!(
///    pub struct CloneData {
///        #[serde(serialize_with = "serialize_to_hex")]
///        pub flags: u64,
///    }
/// );
/// ```
macro_rules! def_user_data {
            // Match for a struct with fields and field attributes
            ($(#[$derive:meta])* $struct_vis:vis struct $struct_name:ident { $($(#[$struct_meta:meta])* $vis:vis $field_name:ident : $field_type:ty),* $(,)? }) => {
                $(#[$derive])*
                #[derive(Debug, Serialize, Deserialize, FieldGetter)]
                $struct_vis struct $struct_name {
                    pub command_line: String,
                    pub exe: PathBuf,
                    $(
                        $(#[$struct_meta])*
                        $vis $field_name: $field_type
                    ),*
                }
            };
        }

#[derive(Debug, Serialize, Deserialize, FieldGetter)]
pub struct ExecveData {
    pub ancestors: String,
    pub parent_exe: String,
    pub command_line: String,
    pub exe: Hashes,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<Hashes>,
}

impl IocGetter for ExecveData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        // parent_exe path
        let mut v = vec![self.parent_exe.as_str().into()];

        // exe path + hashes
        v.extend(self.exe.iocs().into_iter());

        // exe path + hashes of interpreter if any
        self.interpreter
            .as_ref()
            .map(|h| v.extend(h.iocs().into_iter()));

        v
    }
}

def_user_data!(
    pub struct CloneData {
        #[serde(serialize_with = "serialize_to_hex")]
        pub flags: u64,
    }
);

impl_std_iocs!(CloneData);

def_user_data!(
    pub struct PrctlData {
        pub option: String,
        #[serde(serialize_with = "serialize_to_hex")]
        pub arg2: u64,
        #[serde(serialize_with = "serialize_to_hex")]
        pub arg3: u64,
        #[serde(serialize_with = "serialize_to_hex")]
        pub arg4: u64,
        #[serde(serialize_with = "serialize_to_hex")]
        pub arg5: u64,
        pub success: bool,
    }
);

impl_std_iocs!(PrctlData);

def_user_data!(
    pub struct MmapExecData {
        pub mapped: Hashes,
    }
);

impl IocGetter for MmapExecData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.exe.to_string_lossy()];
        v.extend(self.mapped.iocs());
        v
    }
}

def_user_data!(
    pub struct MprotectData {
        #[serde(serialize_with = "serialize_to_hex")]
        pub addr: u64,
        #[serde(serialize_with = "serialize_to_hex")]
        pub prot: u64,
    }
);

impl_std_iocs!(MprotectData);

#[derive(Debug, Serialize, Deserialize, FieldGetter)]
pub struct NetworkInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    pub ip: IpAddr,
    pub port: u16,
    pub public: bool,
    pub is_v6: bool,
}

impl Default for NetworkInfo {
    fn default() -> Self {
        Self {
            hostname: None,
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
            public: false,
            is_v6: false,
        }
    }
}

impl IocGetter for NetworkInfo {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.ip.to_string().into()];

        self.hostname.as_ref().map(|hn| v.push(hn.into()));

        v
    }
}

def_user_data!(
    pub struct ConnectData {
        pub dst: NetworkInfo,
        pub connected: bool,
    }
);

impl IocGetter for ConnectData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        self.dst.iocs()
    }
}

def_user_data!(
    #[derive(Default)]
    pub struct DnsQueryData {
        pub query: String,
        pub proto: String,
        pub response: String,
        pub dns_server: NetworkInfo,
        #[serde(skip)]
        #[getter(skip)]
        responses: Vec<String>,
    }
);

impl DnsQueryData {
    const SEP: &'static str = ";";

    pub fn new() -> Self {
        Default::default()
    }

    #[inline]
    pub fn with_responses(mut self, responses: Vec<String>) -> Self {
        self.response = responses.join(Self::SEP);
        self.responses = responses;
        self
    }

    #[inline]
    fn cache_responses(&mut self) {
        if !self.response.is_empty() && self.responses.is_empty() {
            self.responses = self.response.split(Self::SEP).map(|s| s.into()).collect();
        }
    }

    #[inline]
    pub fn responses(&mut self) -> &Vec<String> {
        self.cache_responses();
        &self.responses
    }
}

impl IocGetter for DnsQueryData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        // we build up responses if needed
        self.cache_responses();

        // set executable
        let mut v = vec![self.exe.to_string_lossy()];
        // the ip addresses in the response
        v.extend(
            self.responses
                .iter()
                .map(|ioc| ioc.into())
                .collect::<Vec<Cow<'_, str>>>(),
        );
        // the domain queried
        v.push((&self.query).into());
        // dns server iocs
        v.extend(self.dns_server.iocs().into_iter());
        v
    }
}

def_user_data!(
    pub struct SendDataData {
        pub dst: NetworkInfo,
        pub data_entropy: f32,
        pub data_size: u64,
    }
);

impl IocGetter for SendDataData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.exe.to_string_lossy()];
        v.extend(self.dst.iocs());
        v
    }
}

#[derive(Debug, Serialize, Deserialize, FieldGetter)]
pub struct InitModuleData {
    pub ancestors: String,
    pub command_line: String,
    pub exe: PathBuf,
    pub module_name: String,
    pub args: String,
    #[serde(serialize_with = "serialize_to_hex")]
    pub userspace_addr: u64,
    pub loaded: bool,
}

impl IocGetter for InitModuleData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.to_string_lossy()]
    }
}

def_user_data!(
    pub struct RWData {
        pub path: PathBuf,
    }
);

impl IocGetter for RWData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.to_string_lossy(), self.path.to_string_lossy()]
    }
}

def_user_data!(
    pub struct UnlinkData {
        pub path: PathBuf,
        pub success: bool,
    }
);

impl IocGetter for UnlinkData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.to_string_lossy(), self.path.to_string_lossy()]
    }
}

def_user_data!(
    pub struct MountData {
        pub dev_name: String,
        pub path: PathBuf,
        #[serde(rename = "type")]
        pub ty: String,
        pub success: bool,
    }
);

impl IocGetter for MountData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.to_string_lossy(), self.path.to_string_lossy()]
    }
}

def_user_data!(
    pub struct FileRenameData {
        pub old: PathBuf,
        pub new: PathBuf,
    }
);

impl IocGetter for FileRenameData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![
            self.exe.to_string_lossy(),
            self.old.to_string_lossy(),
            self.new.to_string_lossy(),
        ]
    }
}

#[derive(Debug, FieldGetter, Serialize, Deserialize)]
pub struct BpfProgTypeInfo {
    pub id: u32,
    pub name: String,
}

#[derive(Debug, FieldGetter, Serialize, Deserialize)]
pub struct BpfProgInfo {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub size: usize,
}

def_user_data!(
    pub struct BpfProgLoadData {
        pub id: u32,
        pub prog_type: BpfProgTypeInfo,
        pub tag: String,
        pub attached_func: String,
        pub name: String,
        pub ksym: String,
        pub bpf_prog: BpfProgInfo,
        pub verified_insns: Option<u32>,
        pub loaded: bool,
    }
);

impl IocGetter for BpfProgLoadData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![
            self.exe.to_string_lossy(),
            self.bpf_prog.md5.as_str().into(),
            self.bpf_prog.sha1.as_str().into(),
            self.bpf_prog.sha256.as_str().into(),
            self.bpf_prog.sha512.as_str().into(),
        ]
    }
}

#[derive(Debug, FieldGetter, Serialize, Deserialize)]
pub struct SocketInfo {
    pub domain: String,
    #[serde(rename = "type")]
    pub ty: String,
}

#[derive(Debug, FieldGetter, Serialize, Deserialize)]
pub struct FilterInfo {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub len: u16,    // size in filter sock_filter blocks
    pub size: usize, // size in bytes
}

def_user_data!(
    pub struct BpfSocketFilterData {
        pub socket: SocketInfo,
        pub filter: FilterInfo,
        pub attached: bool,
    }
);

impl IocGetter for BpfSocketFilterData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![
            self.exe.to_string_lossy(),
            self.filter.md5.as_str().into(),
            self.filter.sha1.as_str().into(),
            self.filter.sha256.as_str().into(),
            self.filter.sha512.as_str().into(),
        ]
    }
}

def_user_data!(
    pub struct ExitData {
        pub error_code: u64,
    }
);

impl_std_iocs!(ExitData);
