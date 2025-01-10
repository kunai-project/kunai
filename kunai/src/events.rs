use std::{
    borrow::Cow,
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
};

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use gene::{Event, FieldGetter, FieldValue};
use gene_derive::{Event, FieldGetter};

use kunai_common::{bpf_events, net};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::{
    cache::{FileMeta, Hashes},
    containers::Container,
    info::{ContainerInfo, StdEventInfo, TaskAdditionalInfo},
};

#[derive(Debug, Default, Serialize, Deserialize, FieldGetter)]
pub struct File {
    pub path: PathBuf,
}

impl From<PathBuf> for File {
    fn from(value: PathBuf) -> Self {
        Self { path: value }
    }
}

#[derive(FieldGetter, Serialize, Deserialize, Clone)]
#[getter(use_serde_rename)]
pub struct ContainerSection {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: Option<Container>,
}

impl From<ContainerInfo> for ContainerSection {
    fn from(value: ContainerInfo) -> Self {
        Self {
            name: value.name,
            ty: value.ty,
        }
    }
}

#[derive(FieldGetter, Serialize, Deserialize, Clone)]
pub struct HostSection {
    #[getter(skip)]
    pub uuid: uuid::Uuid,
    pub name: String,
    pub container: Option<ContainerSection>,
}

#[derive(FieldGetter, Serialize, Deserialize, Clone)]
pub struct EventSection {
    pub source: String,
    pub id: u32,
    pub name: String,
    pub uuid: String,
    pub batch: usize,
}

impl From<&StdEventInfo> for EventSection {
    fn from(value: &StdEventInfo) -> Self {
        Self {
            source: "kunai".into(),
            id: value.bpf.etype.id(),
            name: value.bpf.etype.to_string(),
            uuid: value.bpf.uuid.into_uuid().hyphenated().to_string(),
            batch: value.bpf.batch,
        }
    }
}

#[derive(Debug, FieldGetter, Serialize, Deserialize, Clone)]
pub struct NamespaceInfo {
    pub mnt: u32,
}

impl From<kunai_common::bpf_events::Namespaces> for NamespaceInfo {
    fn from(value: kunai_common::bpf_events::Namespaces) -> Self {
        Self { mnt: value.mnt }
    }
}

#[derive(Debug, FieldGetter, Serialize, Deserialize, Clone)]
pub struct TaskSection {
    pub name: String,
    pub pid: i32,
    pub tgid: i32,
    pub guuid: String,
    pub uid: u32,
    pub user: String,
    pub gid: u32,
    pub group: String,
    pub namespaces: Option<NamespaceInfo>,
    #[serde(with = "u32_hex")]
    pub flags: u32,
    pub zombie: bool,
}

impl TaskSection {
    pub fn from_task_info_with_addition(
        ti: kunai_common::bpf_events::TaskInfo,
        add: TaskAdditionalInfo,
    ) -> Self {
        Self {
            name: ti.comm_string(),
            pid: ti.pid,
            tgid: ti.tgid,
            guuid: ti.tg_uuid.into_uuid().hyphenated().to_string(),
            uid: ti.uid,
            user: add.user.map(|u| u.name).unwrap_or("?".into()),
            gid: ti.gid,
            group: add.group.map(|g| g.name).unwrap_or("?".into()),
            namespaces: ti.namespaces.map(|ns| ns.into()),
            flags: ti.flags,
            zombie: ti.zombie,
        }
    }
}

#[derive(Clone)]
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

impl<'de> Deserialize<'de> for UtcDateTime {
    fn deserialize<D>(deserializer: D) -> Result<UtcDateTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UtcDateTimeVisitor;

        impl Visitor<'_> for UtcDateTimeVisitor {
            type Value = UtcDateTime;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("expecting a rfc3339 formatted timestamp")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                DateTime::parse_from_rfc3339(v)
                    .map_err(|e| E::custom(e))
                    .map(UtcDateTime::from)
            }
        }

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

#[derive(FieldGetter, Serialize, Deserialize, Clone)]
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
        let task =
            TaskSection::from_task_info_with_addition(value.bpf.process, value.additional.task);

        let parent_task =
            TaskSection::from_task_info_with_addition(value.bpf.parent, value.additional.parent);

        Self {
            host: HostSection {
                name: value.additional.host.name,
                uuid: value.additional.host.uuid,
                container: value.additional.container.map(ContainerSection::from),
            },
            event: EventSection {
                source: "kunai".into(),
                id: value.bpf.etype.id(),
                name: value.bpf.etype.to_string(),
                uuid: value.bpf.uuid.into_uuid().hyphenated().to_string(),
                batch: value.bpf.batch,
            },
            task,
            parent_task,
            utc_time: value.utc_timestamp.into(),
        }
    }
}

impl EventInfo {
    pub fn from_other_with_type(mut other: EventInfo, ty: bpf_events::Type) -> Self {
        other.event.name = ty.to_string();
        other.event.id = ty.id();
        other.event.uuid = Uuid::new_v4().to_string();
        other
    }
}

/// Trait providing a function returning all the IoCs
/// the implementer can provide for IoC checking purposes.
pub trait IocGetter {
    fn iocs(&mut self) -> Vec<Cow<'_, str>>;
}

/// Trait to represent the fact that an event may be
/// scanned by a file scanner.
pub trait Scannable {
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>>;
}

macro_rules! impl_std_iocs {
    ($ty:ty) => {
        impl IocGetter for $ty {
            fn iocs(&mut self) -> Vec<Cow<'_, str>> {
                self._iocs()
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

pub trait KunaiEvent: ::gene::Event + ::gene::FieldGetter + IocGetter + Scannable {
    fn set_detection(&mut self, sr: ScanResult);
    fn get_detection(&self) -> &Option<ScanResult>;
    fn info(&self) -> &EventInfo;
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
    #[inline(always)]
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        self.data.iocs()
    }
}

impl<T> Scannable for UserEvent<T>
where
    T: Scannable,
{
    #[inline(always)]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        self.data.scannable_files()
    }
}

impl<T> KunaiEvent for UserEvent<T>
where
    T: FieldGetter + IocGetter + Scannable,
{
    #[inline(always)]
    fn set_detection(&mut self, sr: ScanResult) {
        self.detection = Some(sr)
    }

    #[inline(always)]
    fn get_detection(&self) -> &Option<ScanResult> {
        &self.detection
    }

    #[inline(always)]
    fn info(&self) -> &EventInfo {
        &self.info
    }
}

impl<T> UserEvent<T> {
    pub fn new(data: T, info: StdEventInfo) -> Self {
        Self {
            data,
            detection: None,
            info: info.into(),
        }
    }

    pub fn with_data_and_info(data: T, info: EventInfo) -> Self {
        Self {
            data,
            detection: None,
            info,
        }
    }
}

mod u32_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    #[inline(always)]
    pub fn serialize<S>(value: &u32, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", value))
    }

    #[inline(always)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: Deserializer<'de>,
    {
        u32::from_str_radix(
            String::deserialize(deserializer)?.trim_start_matches("0x"),
            16,
        )
        .map_err(serde::de::Error::custom)
    }
}

mod u64_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    #[inline(always)]
    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", value))
    }

    #[inline(always)]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        u64::from_str_radix(
            String::deserialize(deserializer)?.trim_start_matches("0x"),
            16,
        )
        .map_err(serde::de::Error::custom)
    }
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
///        #[serde(serialize_with = "u64_hex")]
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
                    pub ancestors: String,
                    pub command_line: String,
                    pub exe: File,
                    $(
                        $(#[$struct_meta])*
                        $vis $field_name: $field_type
                    ),*
                }

                impl $struct_name {
                    #[inline(always)]
                    fn _iocs(&self) -> Vec<Cow<'_,str>>{
                        vec![self.exe.path.to_string_lossy()]
                    }
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

impl Scannable for ExecveData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        let mut v = vec![Cow::Borrowed(&self.exe.path)];
        if let Some(interp) = self.interpreter.as_ref() {
            v.push(Cow::Borrowed(&interp.path));
        }
        v
    }
}

impl IocGetter for ExecveData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        // parent_exe path
        let mut v = vec![self.parent_exe.as_str().into()];

        // exe path + hashes
        v.extend(self.exe.iocs());

        // exe path + hashes of interpreter if any
        if let Some(h) = self.interpreter.as_ref() {
            v.extend(h.iocs())
        }

        v
    }
}

def_user_data!(
    pub struct CloneData {
        #[serde(with = "u64_hex")]
        pub flags: u64,
    }
);

impl Scannable for CloneData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(CloneData);

def_user_data!(
    pub struct PrctlData {
        pub option: String,
        #[serde(with = "u64_hex")]
        pub arg2: u64,
        #[serde(with = "u64_hex")]
        pub arg3: u64,
        #[serde(with = "u64_hex")]
        pub arg4: u64,
        #[serde(with = "u64_hex")]
        pub arg5: u64,
        pub success: bool,
    }
);

impl_std_iocs!(PrctlData);

impl Scannable for PrctlData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

#[derive(Debug, FieldGetter, Serialize, Deserialize)]
pub struct TargetTask {
    pub command_line: String,
    pub exe: File,
    pub task: TaskSection,
}

def_user_data!(
    pub struct KillData {
        pub signal: String,
        pub target: TargetTask,
    }
);

impl Scannable for KillData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(KillData);

def_user_data!(
    pub struct PtraceData {
        #[serde(with = "u32_hex")]
        pub mode: u32,
        pub target: TargetTask,
    }
);

impl Scannable for PtraceData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(PtraceData);

def_user_data!(
    pub struct MmapExecData {
        pub mapped: Hashes,
    }
);

impl Scannable for MmapExecData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![
            Cow::Borrowed(&self.exe.path),
            Cow::Borrowed(&self.mapped.path),
        ]
    }
}

impl IocGetter for MmapExecData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.exe.path.to_string_lossy()];
        v.extend(self.mapped.iocs());
        v
    }
}

def_user_data!(
    pub struct MprotectData {
        #[serde(with = "u64_hex")]
        pub addr: u64,
        #[serde(with = "u64_hex")]
        pub prot: u64,
    }
);

impl Scannable for MprotectData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(MprotectData);

#[derive(Debug, Serialize, Deserialize, FieldGetter, Clone, Copy)]
pub struct SockAddr {
    pub ip: IpAddr,
    pub port: u16,
}

impl Default for SockAddr {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        }
    }
}

impl From<kunai_common::net::SockAddr> for SockAddr {
    fn from(value: kunai_common::net::SockAddr) -> Self {
        Self {
            ip: IpAddr::from(value),
            port: value.port(),
        }
    }
}

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

        if let Some(hn) = self.hostname.as_ref() {
            v.push(hn.into())
        }

        v
    }
}

def_user_data!(
    pub struct ConnectData {
        pub socket: SocketInfo,
        pub src: SockAddr,
        pub dst: NetworkInfo,
        pub community_id: String,
        pub connected: bool,
    }
);

impl Scannable for ConnectData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for ConnectData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        self.dst.iocs()
    }
}

def_user_data!(
    #[derive(Default)]
    pub struct DnsQueryData {
        pub socket: SocketInfo,
        pub src: SockAddr,
        pub query: String,
        pub response: String,
        pub dns_server: NetworkInfo,
        pub community_id: String,
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

impl Scannable for DnsQueryData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for DnsQueryData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        // we build up responses if needed
        self.cache_responses();

        // set executable
        let mut v = vec![self.exe.path.to_string_lossy()];
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
        v.extend(self.dns_server.iocs());
        v
    }
}

def_user_data!(
    pub struct SendDataData {
        pub socket: SocketInfo,
        pub src: SockAddr,
        pub dst: NetworkInfo,
        pub community_id: String,
        pub data_entropy: f32,
        pub data_size: u64,
    }
);

impl Scannable for SendDataData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for SendDataData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.exe.path.to_string_lossy()];
        v.extend(self.dst.iocs());
        v
    }
}

#[derive(Debug, Serialize, Deserialize, FieldGetter)]
pub struct InitModuleData {
    pub ancestors: String,
    pub command_line: String,
    pub exe: File,
    pub syscall: String,
    pub module_name: String,
    pub args: String,
    pub loaded: bool,
}

impl IocGetter for InitModuleData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.path.to_string_lossy()]
    }
}

impl Scannable for InitModuleData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

def_user_data!(
    pub struct FileData {
        pub path: PathBuf,
    }
);

impl IocGetter for FileData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.path.to_string_lossy(), self.path.to_string_lossy()]
    }
}

impl Scannable for FileData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path), Cow::Borrowed(&self.path)]
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
        vec![self.exe.path.to_string_lossy(), self.path.to_string_lossy()]
    }
}

impl Scannable for UnlinkData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
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
            self.exe.path.to_string_lossy(),
            self.old.to_string_lossy(),
            self.new.to_string_lossy(),
        ]
    }
}

impl Scannable for FileRenameData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path), Cow::Borrowed(&self.new)]
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
            self.exe.path.to_string_lossy(),
            self.bpf_prog.md5.as_str().into(),
            self.bpf_prog.sha1.as_str().into(),
            self.bpf_prog.sha256.as_str().into(),
            self.bpf_prog.sha512.as_str().into(),
        ]
    }
}

impl Scannable for BpfProgLoadData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

#[derive(Default, Debug, FieldGetter, Serialize, Deserialize, Clone)]
pub struct SocketInfo {
    pub domain: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub proto: String,
}

impl From<net::SocketInfo> for SocketInfo {
    fn from(value: net::SocketInfo) -> Self {
        Self {
            domain: value.domain_to_string(),
            ty: value.type_to_string(),
            proto: value.proto_to_string(),
        }
    }
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

impl Scannable for BpfSocketFilterData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for BpfSocketFilterData {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![
            self.exe.path.to_string_lossy(),
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

impl Scannable for ExitData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(ExitData);

def_user_data!(
    pub struct ErrorData {
        pub code: u64,
        pub message: String,
    }
);

impl Scannable for ErrorData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(ErrorData);

#[derive(Default, Debug, Serialize, Deserialize, FieldGetter)]
pub struct FileScanData {
    pub path: PathBuf,
    pub meta: FileMeta,
    #[getter(skip)]
    pub signatures: Vec<String>,
    pub positives: usize,
    pub source_event: String,
    pub scan_error: Option<String>,
}

impl FileScanData {
    pub fn from_hashes(h: Hashes) -> Self {
        let p = h.path.clone();
        Self {
            path: p,
            meta: h.into(),
            ..Default::default()
        }
    }
}

impl Scannable for FileScanData {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![]
    }
}

impl IocGetter for FileScanData {
    // we might want to scan hashes against IoCs later than execve
    #[inline(always)]
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.path.to_string_lossy()];
        v.extend(self.meta.iocs());
        v
    }
}
