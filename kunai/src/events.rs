use std::{
    borrow::Cow,
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    path::PathBuf,
    sync::Arc,
};

use chrono::{DateTime, FixedOffset, SecondsFormat, Utc};
use gene::{rules::MAX_SEVERITY, Event, FieldGetter, FieldNameIterator, FieldValue};
use gene_derive::{Event, FieldGetter};

use kunai_common::{
    bpf_events::{self, TaskInfo, Type},
    consts::caps_to_str_vec,
    creds, net,
};
use serde::{de::Visitor, Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::{
    cache::{FileMeta, Hashes},
    containers::Container,
    info::{ContainerInfo, StdEventInfo, TaskAdditionalInfo},
};

pub mod agent;
mod start;
pub use start::*;

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
    pub batch: u64,
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
pub struct TaskSection<'src> {
    pub name: String,
    pub pid: i32,
    pub tgid: i32,
    pub guuid: String,
    pub creds: Creds<'src>,
    pub namespaces: Option<NamespaceInfo>,
    #[serde(with = "u32_hex")]
    pub flags: u32,
    pub zombie: bool,
}

impl<'src> TaskSection<'src> {
    pub fn from_task_info_with_addition(ti: TaskInfo, add: &'src TaskAdditionalInfo) -> Self {
        Self {
            name: ti.comm_string(),
            pid: ti.pid,
            tgid: ti.tgid,
            guuid: ti.tg_uuid.into_uuid().hyphenated().to_string(),
            creds: Creds::from_bpf_and_additions(ti.creds, add, true),
            namespaces: ti.namespaces.map(|ns| ns.into()).into(),
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

impl<'f> FieldGetter<'f> for UtcDateTime {
    fn get_from_iter(&'f self, i: FieldNameIterator) -> Option<FieldValue<'f>> {
        if !i.is_terminal() {
            return None;
        }
        // currently return timestamp as millisecond, it might not be optimal
        Some(self.0.timestamp_millis().into())
    }
}

#[derive(FieldGetter, Serialize, Deserialize, Clone)]
pub struct EventInfo<'i> {
    pub host: HostSection,
    pub event: EventSection,
    pub task: TaskSection<'i>,
    pub parent_task: TaskSection<'i>,
    #[serde(serialize_with = "serialize_utc_ts")]
    pub utc_time: UtcDateTime,
}

impl<'a> From<&'a StdEventInfo> for EventInfo<'a> {
    fn from(value: &'a StdEventInfo) -> Self {
        let task =
            TaskSection::from_task_info_with_addition(value.bpf.process, &value.additional.task);

        let parent_task =
            TaskSection::from_task_info_with_addition(value.bpf.parent, &value.additional.parent);

        Self {
            host: HostSection {
                name: value.additional.host.name.clone(),
                uuid: value.additional.host.uuid,
                container: value
                    .additional
                    .container
                    .clone()
                    .map(ContainerSection::from),
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

impl EventInfo<'_> {
    pub fn from_other_with_type(mut other: Self, ty: bpf_events::Type) -> Self {
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

#[derive(Debug, Default, FieldGetter, Serialize, Deserialize, Clone, PartialEq)]
pub struct Detection {
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
    /// total severity score (bounded to [`MAX_SEVERITY`])
    pub severity: u8,
}

impl From<gene::Detection<'_>> for Detection {
    fn from(mut value: gene::Detection) -> Self {
        Self {
            iocs: HashSet::new(),
            rules: value.rules.drain().map(|s| s.into_owned()).collect(),
            tags: value.tags.drain().map(|s| s.into_owned()).collect(),
            attack: value.attack.drain().map(|s| s.into_owned()).collect(),
            actions: value.actions.drain().map(|s| s.into_owned()).collect(),
            severity: value.severity,
        }
    }
}

#[derive(Debug, Default, FieldGetter, Serialize, Deserialize, Clone, PartialEq)]
pub struct Filter {
    /// union of the rule names matching the event
    #[getter(skip)]
    pub rules: HashSet<String>,
    /// union of tags defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub tags: HashSet<String>,
    /// union of actions defined in the rules matching the event
    #[getter(skip)]
    #[serde(skip_serializing_if = "HashSet::is_empty")]
    pub actions: HashSet<String>,
}

impl From<gene::Filter<'_>> for Filter {
    fn from(mut value: gene::Filter) -> Self {
        Self {
            rules: value.rules.drain().map(|s| s.into_owned()).collect(),
            tags: value.tags.drain().map(|s| s.into_owned()).collect(),
            actions: value.actions.drain().map(|s| s.into_owned()).collect(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize, FieldGetter)]
pub struct ScanResult {
    pub detection: Option<Detection>,
    pub filter: Option<Filter>,
}

impl From<gene::ScanResult<'_>> for ScanResult {
    fn from(value: gene::ScanResult) -> Self {
        Self {
            detection: value.detection.take_include().map(Detection::from),
            filter: value.filter.take_include().map(Filter::from),
        }
    }
}

impl ScanResult {
    #[inline(always)]
    pub fn contains_detection<S: AsRef<str>>(&self, rule: S) -> bool {
        self.detection
            .as_ref()
            .map(|d| d.rules.contains(rule.as_ref()))
            .unwrap_or_default()
    }

    #[inline(always)]
    pub fn contains_filter<S: AsRef<str>>(&self, rule: S) -> bool {
        self.filter
            .as_ref()
            .map(|f| f.rules.contains(rule.as_ref()))
            .unwrap_or_default()
    }

    #[inline(always)]
    pub fn is_detection(&self) -> bool {
        self.detection.is_some()
    }

    #[inline(always)]
    pub fn is_only_filter(&self) -> bool {
        !self.is_detection() && self.is_filtered()
    }

    #[inline(always)]
    pub fn is_filtered(&self) -> bool {
        self.filter.is_some()
    }

    #[inline(always)]
    pub fn severity(&self) -> u8 {
        self.detection
            .as_ref()
            .map(|d| d.severity)
            .unwrap_or_default()
    }

    #[inline]
    pub fn update_iocs<S: AsRef<str>>(&mut self, iocs: impl Iterator<Item = (S, u8)>) {
        let detections = self.detection.get_or_insert_default();

        iocs.for_each(|(ioc, sev)| {
            detections.iocs.insert(ioc.as_ref().to_string());
            detections.severity =
                (sev.clamp(0, MAX_SEVERITY) + detections.severity).clamp(0, MAX_SEVERITY);
        });
    }
}

pub trait KunaiEvent<'e>:
    ::gene::Event<'e> + ::gene::FieldGetter<'e> + IocGetter + Scannable
{
    fn set_detection(&mut self, d: Detection) -> &Detection;
    fn get_detection(&self) -> &Option<Detection>;
    fn set_filter(&mut self, f: Filter) -> &Filter;
    fn get_filter(&self) -> &Option<Filter>;
    fn info(&self) -> &EventInfo<'_>;
}

#[derive(Event, FieldGetter, Serialize, Deserialize)]
#[event(id = self.info.event.id as i64, source = "kunai".into())]
pub struct UserEvent<'i, T> {
    pub data: T,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detection: Option<Detection>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub filter: Option<Filter>,
    pub info: EventInfo<'i>,
}

impl<T> IocGetter for UserEvent<'_, T>
where
    T: IocGetter,
{
    #[inline(always)]
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        self.data.iocs()
    }
}

impl<T> Scannable for UserEvent<'_, T>
where
    T: Scannable,
{
    #[inline(always)]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        self.data.scannable_files()
    }
}

impl<'e, T> KunaiEvent<'e> for UserEvent<'_, T>
where
    T: FieldGetter<'e> + IocGetter + Scannable,
{
    #[inline(always)]
    fn set_detection(&mut self, d: Detection) -> &Detection {
        self.detection = Some(d);
        self.detection.as_ref().unwrap()
    }

    #[inline(always)]
    fn get_detection(&self) -> &Option<Detection> {
        &self.detection
    }

    #[inline(always)]
    fn set_filter(&mut self, f: Filter) -> &Filter {
        self.filter = Some(f);
        self.filter.as_ref().unwrap()
    }

    #[inline(always)]
    fn get_filter(&self) -> &Option<Filter> {
        &self.filter
    }

    #[inline(always)]
    fn info(&self) -> &EventInfo<'_> {
        &self.info
    }
}

impl<'i, T> UserEvent<'i, T> {
    pub fn new(data: T, info: &'i StdEventInfo) -> Self {
        Self {
            data,
            detection: None,
            filter: None,
            info: info.into(),
        }
    }

    pub fn with_data_and_info(data: T, info: EventInfo<'i>) -> Self {
        Self {
            data,
            detection: None,
            filter: None,
            info,
        }
    }

    pub fn with_type(mut self, ty: Type) -> Self {
        self.info.event.id = ty.id();
        self.info.event.name = ty.to_string();
        self
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
/// The struct must declare exactly one lifetime parameter, which
/// generated fields borrow from.
///
/// # Example
///
/// ```rust,ignore
/// def_user_data!(
///    pub struct CloneData<'src> {
///        #[serde(serialize_with = "u64_hex")]
///        pub flags: u64,
///    }
/// );
/// ```
macro_rules! def_user_data {
            // Match for a struct with fields and field attributes
            ($(#[$derive:meta])* $struct_vis:vis struct $struct_name:ident <$lt:lifetime> { $($(#[$struct_meta:meta])* $vis:vis $field_name:ident : $field_type:ty),* $(,)? }) => {
                $(#[$derive])*
                #[derive(Debug, Serialize, Deserialize, FieldGetter)]
                $struct_vis struct $struct_name <$lt> {
                    pub ancestors: Vec<Cow<$lt, str>>,
                    pub command_line: String,
                    pub exe: File,
                    $(
                        $(#[$struct_meta])*
                        $vis $field_name: $field_type
                    ),*
                }

                impl <$lt> $struct_name <$lt> {
                    #[inline(always)]
                    fn _iocs(&self) -> Vec<Cow<'_,str>>{
                        vec![self.exe.path.to_string_lossy()]
                    }
                }
            };
        }

#[derive(Debug, Serialize, Deserialize, FieldGetter)]
pub struct ExecveData<'src> {
    pub ancestors: Vec<Cow<'src, str>>,
    pub parent_command_line: String,
    pub parent_exe: String,
    pub command_line: String,
    pub exe: Arc<Hashes>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interpreter: Option<Arc<Hashes>>,
}

impl Scannable for ExecveData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        let mut v = vec![Cow::Borrowed(&self.exe.path)];
        if let Some(interp) = self.interpreter.as_ref() {
            v.push(Cow::Borrowed(&interp.path));
        }
        v
    }
}

impl IocGetter for ExecveData<'_> {
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
    pub struct CloneData<'src> {
        #[serde(with = "u64_hex")]
        pub flags: u64,
    }
);

impl Scannable for CloneData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(CloneData<'_>);

def_user_data!(
    pub struct PrctlData<'src> {
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

impl_std_iocs!(PrctlData<'_>);

impl Scannable for PrctlData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

#[derive(Debug, FieldGetter, Serialize, Deserialize)]
pub struct TargetTask<'src> {
    pub command_line: String,
    pub exe: File,
    pub task: TaskSection<'src>,
}

def_user_data!(
    pub struct KillData<'src> {
        pub signal: String,
        pub target: TargetTask<'src>,
    }
);

impl Scannable for KillData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(KillData<'_>);

def_user_data!(
    pub struct PtraceData<'src> {
        #[serde(with = "u32_hex")]
        pub mode: u32,
        pub target: TargetTask<'src>,
    }
);

impl Scannable for PtraceData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(PtraceData<'_>);

#[derive(Debug, FieldGetter, Serialize, Deserialize, Clone)]
pub struct Caps {
    pub effective: Vec<Cow<'static, str>>,
    pub permitted: Vec<Cow<'static, str>>,
    pub inheritable: Vec<Cow<'static, str>>,
}

#[derive(Default, Debug, FieldGetter, Serialize, Deserialize, Clone)]
pub struct Identity<'src> {
    pub uid: u32,
    pub user: Cow<'src, str>,
    pub gid: u32,
    pub group: Cow<'src, str>,
}

#[derive(Debug, FieldGetter, Serialize, Deserialize, Clone)]
pub struct Creds<'src> {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub real: Option<Identity<'src>>,
    pub effective: Identity<'src>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved: Option<Identity<'src>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fs: Option<Identity<'src>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caps: Option<Caps>,
}

impl<'src> Creds<'src> {
    pub fn from_bpf_and_additions(
        s: creds::Creds,
        ai: &'src TaskAdditionalInfo,
        light: bool,
    ) -> Self {
        macro_rules! identity {
            ($uid:expr, $gid:expr) => {
                Identity {
                    uid: $uid,
                    user: ai
                        .users
                        .as_ref()
                        .and_then(|users| users.get_by_uid($uid))
                        .map(|u| Cow::Borrowed(u.name.as_str()))
                        .unwrap_or("?".into()),
                    gid: $gid,
                    group: ai
                        .groups
                        .as_ref()
                        .and_then(|groups| groups.get_by_gid($gid))
                        .map(|g| Cow::Borrowed(g.name.as_str()))
                        .unwrap_or("?".into()),
                }
            };
        }

        Self {
            real: {
                if light {
                    None
                } else {
                    Some(identity!(s.uid, s.gid))
                }
            },
            effective: identity!(s.euid, s.egid),
            saved: if light {
                None
            } else {
                Some(identity!(s.suid, s.sgid))
            },
            fs: if light {
                None
            } else {
                Some(identity!(s.fsuid, s.fsgid))
            },
            caps: if light {
                None
            } else {
                Some(Caps {
                    effective: caps_to_str_vec(s.cap_effective),
                    permitted: caps_to_str_vec(s.cap_permitted),
                    inheritable: caps_to_str_vec(s.cap_inheritable),
                })
            },
        }
    }
}

def_user_data!(
    pub struct CommitCredsData<'src> {
        pub old: Creds<'src>,
        pub new: Creds<'src>,
    }
);

impl Scannable for CommitCredsData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(CommitCredsData<'_>);

def_user_data!(
    pub struct CredsTamperedData<'src> {
        pub actual: Creds<'src>,
        pub expected: Creds<'src>,
    }
);

impl Scannable for CredsTamperedData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(CredsTamperedData<'_>);

def_user_data!(
    pub struct MmapExecData<'src> {
        pub mapped: Arc<Hashes>,
    }
);

impl Scannable for MmapExecData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![
            Cow::Borrowed(&self.exe.path),
            Cow::Borrowed(&self.mapped.path),
        ]
    }
}

impl IocGetter for MmapExecData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.exe.path.to_string_lossy()];
        v.extend(self.mapped.iocs());
        v
    }
}

def_user_data!(
    pub struct MprotectData<'src> {
        #[serde(with = "u64_hex")]
        pub addr: u64,
        #[serde(with = "u64_hex")]
        pub prot: u64,
    }
);

impl Scannable for MprotectData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(MprotectData<'_>);

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
    pub struct ConnectData<'src> {
        pub socket: SocketInfo,
        pub src: SockAddr,
        pub dst: NetworkInfo,
        pub community_id: String,
        pub connected: bool,
    }
);

impl Scannable for ConnectData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for ConnectData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        self.dst.iocs()
    }
}

def_user_data!(
    #[derive(Default)]
    pub struct DnsQueryData<'src> {
        pub socket: SocketInfo,
        pub src: SockAddr,
        pub query: String,
        pub query_type: Cow<'static, str>,
        pub response: Vec<String>,
        pub dns_server: NetworkInfo,
        pub community_id: String,
    }
);

impl DnsQueryData<'_> {
    pub fn new() -> Self {
        Default::default()
    }
}

impl Scannable for DnsQueryData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for DnsQueryData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        // set executable
        let mut v = vec![self.exe.path.to_string_lossy()];
        // the ip addresses in the response
        v.extend(
            self.response
                .iter()
                .map(|ioc| Cow::Borrowed(ioc.as_str()))
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
    pub struct SendDataData<'src> {
        pub socket: SocketInfo,
        pub src: SockAddr,
        pub dst: NetworkInfo,
        pub community_id: String,
        pub data_entropy: f32,
        pub data_size: u64,
    }
);

impl Scannable for SendDataData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for SendDataData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.exe.path.to_string_lossy()];
        v.extend(self.dst.iocs());
        v
    }
}

#[derive(Debug, Serialize, Deserialize, FieldGetter)]
pub struct InitModuleData<'src> {
    pub ancestors: Vec<Cow<'src, str>>,
    pub command_line: String,
    pub exe: File,
    pub syscall: String,
    pub module_name: String,
    pub args: String,
    pub loaded: bool,
}

impl IocGetter for InitModuleData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.path.to_string_lossy()]
    }
}

impl Scannable for InitModuleData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

def_user_data!(
    pub struct FileData<'src> {
        pub path: PathBuf,
    }
);

impl IocGetter for FileData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.path.to_string_lossy(), self.path.to_string_lossy()]
    }
}

impl Scannable for FileData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path), Cow::Borrowed(&self.path)]
    }
}

def_user_data!(
    pub struct UnlinkData<'src> {
        pub path: PathBuf,
        pub success: bool,
    }
);

impl IocGetter for UnlinkData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![self.exe.path.to_string_lossy(), self.path.to_string_lossy()]
    }
}

impl Scannable for UnlinkData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

def_user_data!(
    pub struct FileRenameData<'src> {
        pub old: PathBuf,
        pub new: PathBuf,
    }
);

impl IocGetter for FileRenameData<'_> {
    fn iocs(&mut self) -> Vec<Cow<'_, str>> {
        vec![
            self.exe.path.to_string_lossy(),
            self.old.to_string_lossy(),
            self.new.to_string_lossy(),
        ]
    }
}

impl Scannable for FileRenameData<'_> {
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
    pub struct BpfProgLoadData<'src> {
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

impl IocGetter for BpfProgLoadData<'_> {
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

impl Scannable for BpfProgLoadData<'_> {
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
    pub struct BpfSocketFilterData<'src> {
        pub socket: SocketInfo,
        pub filter: FilterInfo,
        pub attached: bool,
    }
);

impl Scannable for BpfSocketFilterData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl IocGetter for BpfSocketFilterData<'_> {
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
    pub struct ExitData<'src> {
        pub error_code: u64,
    }
);

impl Scannable for ExitData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(ExitData<'_>);

#[derive(Debug, Default, FieldGetter, Serialize, Deserialize)]
pub struct IoUringOp {
    pub code: u8,
    pub name: String,
}

def_user_data!(
    pub struct IoUringSqeData<'src> {
        pub op: IoUringOp,
    }
);

impl Scannable for IoUringSqeData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(IoUringSqeData<'_>);

def_user_data!(
    pub struct ErrorData<'src> {
        pub code: u64,
        pub message: String,
    }
);

impl Scannable for ErrorData<'_> {
    #[inline]
    fn scannable_files(&self) -> Vec<Cow<'_, PathBuf>> {
        vec![Cow::Borrowed(&self.exe.path)]
    }
}

impl_std_iocs!(ErrorData<'_>);

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
    pub fn from_hashes(h: Arc<Hashes>) -> Self {
        let p = h.path.clone();
        Self {
            path: p,
            meta: h.as_ref().into(),
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

#[derive(Default, Debug, Serialize, Deserialize, FieldGetter)]
pub struct LossData {
    pub read: u64,
    pub lost: u64,
    pub eps: f64,
}

impl From<&bpf_events::LossData> for LossData {
    fn from(value: &bpf_events::LossData) -> Self {
        Self {
            read: value.read,
            lost: value.lost,
            eps: value.eps,
        }
    }
}
