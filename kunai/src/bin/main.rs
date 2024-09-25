#![deny(unused_imports)]

use anyhow::anyhow;
use aya::maps::perf::Events;
use aya::maps::MapData;
use bytes::BytesMut;

use clap::builder::styling;
use clap::{CommandFactory, FromArgMatches, Parser, Subcommand};
use env_logger::Builder;
use fs_walk::WalkOptions;
use gene::rules::MAX_SEVERITY;
use gene::Engine;
use kunai::containers::Container;
use kunai::events::{
    BpfProgLoadData, BpfProgTypeInfo, BpfSocketFilterData, CloneData, ConnectData, DnsQueryData,
    EventInfo, ExecveData, ExitData, FileData, FileRenameData, FileScanData, FilterInfo,
    InitModuleData, KillData, KunaiEvent, MmapExecData, MprotectData, NetworkInfo, PrctlData,
    ScanResult, SendDataData, SockAddr, SocketInfo, TargetTask, UnlinkData, UserEvent,
};
use kunai::info::{AdditionalInfo, StdEventInfo, TaskKey};
use kunai::ioc::IoC;
use kunai::util::uname::Utsname;

use kunai::yara::{Scanner, SourceCode};
use kunai::{cache, util};
use kunai_common::bpf_events::{
    self, error, event, mut_event, EncodedEvent, Event, PrctlOption, Signal, Type,
    MAX_BPF_EVENT_SIZE,
};
use kunai_common::config::{BpfConfig, Filter};
use kunai_common::{inspect_err, kernel};

use kunai_common::version::KernelVersion;
use kunai_macros::StrEnum;
use log::LevelFilter;
use serde::{Deserialize, Serialize};

use tokio::sync::mpsc::error::SendError;
use tokio::time::timeout;

use std::borrow::Cow;
use std::cmp::max;
use std::collections::{HashMap, HashSet, VecDeque};

use std::fs::{self, DirBuilder, File};
use std::io::{self, BufRead, Write};
use std::net::IpAddr;

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use std::str::FromStr;

use std::sync::Arc;

use std::process;
use std::time::Duration;

use aya::{
    include_bytes_aligned, maps::perf::AsyncPerfEventArray, maps::HashMap as AyaHashMap,
    util::online_cpus, Bpf,
};

use aya::{BpfLoader, Btf, VerifierLogLevel};

use log::{debug, error, info, warn};

use tokio::sync::{mpsc, Barrier, Mutex};
use tokio::{task, time};

use kunai::cache::*;

use kunai::compat::Programs;
use kunai::config::Config;
use kunai::util::namespaces::{unshare, Namespace};
use kunai::util::*;

use communityid::{Flow, Protocol};

const PAGE_SIZE: usize = 4096;
const KERNEL_IMAGE: &str = "kernel";

#[derive(Debug, Clone)]
struct Task {
    image: PathBuf,
    command_line: Vec<String>,
    pid: i32,
    // process flags PF_* defined in sched.h
    flags: u32,
    resolved: HashMap<IpAddr, String>,
    container: Option<Container>,
    // needs to be vec because of procfs
    cgroups: Vec<String>,
    nodename: Option<String>,
    parent_key: Option<TaskKey>,
    threads: HashSet<TaskKey>,
    // flag telling if this task comes from procfs
    // parsing at kunai start
    procfs: bool,
    exit: bool,
}

impl Task {
    #[inline(always)]
    fn is_kthread(&self) -> bool {
        // check if flag contains PF_KTHREAD
        self.flags & 0x00200000 == 0x00200000
    }

    #[inline(always)]
    fn command_line_string(&self) -> String {
        self.command_line.join(" ")
    }

    // run on task exit
    #[inline(always)]
    fn on_exit(&mut self) {
        // this does not allocate the new map
        self.resolved.clear();
        self.resolved.shrink_to_fit();
        self.exit = true;
    }
}

struct SystemInfo {
    host_uuid: uuid::Uuid,
    hostname: String,
    mount_ns: Namespace,
}

impl SystemInfo {
    fn from_sys() -> Result<Self, anyhow::Error> {
        let pid = process::id();
        Ok(SystemInfo {
            host_uuid: uuid::Uuid::from_u128(0),
            hostname: fs::read_to_string("/etc/hostname")?.trim_end().to_string(),
            mount_ns: Namespace::from_pid(namespaces::Kind::Mnt, pid)?,
        })
    }

    fn with_host_uuid(mut self, uuid: uuid::Uuid) -> Self {
        self.host_uuid = uuid;
        self
    }
}

pub enum Output {
    Stdout(std::io::Stdout),
    Stderr(std::io::Stderr),
    // variant too big, boxing suggested by clippy
    File(Box<firo::File>),
}

impl Output {
    #[inline(always)]
    fn stdout() -> Self {
        Self::Stdout(std::io::stdout())
    }

    #[inline(always)]
    fn stderr() -> Self {
        Self::Stderr(std::io::stderr())
    }
}

impl From<firo::File> for Output {
    fn from(value: firo::File) -> Self {
        Self::File(Box::new(value))
    }
}

impl io::Write for Output {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stdout(o) => o.write(buf),
            Self::Stderr(o) => o.write(buf),
            Self::File(o) => o.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stdout(o) => o.flush(),
            Self::Stderr(o) => o.flush(),
            Self::File(o) => o.flush(),
        }
    }
}

/// enum of supported actions
#[derive(StrEnum)]
enum Actions {
    #[str("kill")]
    Kill,
    #[str("scan-files")]
    ScanFiles,
}

impl std::fmt::Display for Actions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

struct EventConsumer<'s> {
    system_info: SystemInfo,
    config: Config,
    engine: gene::Engine,
    iocs: HashMap<String, u8>,
    random: u32,
    cache: cache::Cache,
    tasks: HashMap<TaskKey, Task>,
    resolved: HashMap<IpAddr, String>,
    exited_tasks: u64,
    output: Output,
    file_scanner: Option<Scanner<'s>>,
    // used to check if we must generate FileScan events
    scan_events_enabled: bool,
}

impl<'s> EventConsumer<'s> {
    fn prepare_output(config: &Config) -> anyhow::Result<Output> {
        let output = match &config.output.as_str() {
            &"stdout" => String::from("/dev/stdout"),
            &"stderr" => String::from("/dev/stderr"),
            v => v.to_string(),
        };

        let out = match output.as_str() {
            "/dev/stdout" => Output::stdout(),
            "/dev/stderr" => Output::stderr(),
            v => {
                let path = PathBuf::from(v);

                if let Some(parent) = path.parent() {
                    if !parent.exists() {
                        // we only create parent directory
                        DirBuilder::new().mode(0o700).create(parent).map_err(|e| {
                            anyhow!("failed to create output directory {parent:?}: {e}")
                        })?;
                    }
                }

                match config.output_settings.as_ref() {
                    Some(s) => firo::OpenOptions::new()
                        .mode(0o600)
                        .max_size(s.max_size)
                        .trigger(s.rotate_size.into())
                        .compression(firo::Compression::Gzip)
                        .create_append(v)?
                        .into(),
                    None => firo::OpenOptions::new()
                        .mode(0o600)
                        .create_append(v)?
                        .into(),
                }
            }
        };
        Ok(out)
    }

    pub fn with_config(config: Config) -> anyhow::Result<Self> {
        // building up system information
        let system_info = SystemInfo::from_sys()?.with_host_uuid(
            config
                .host_uuid()
                .ok_or(anyhow!("failed to read host_uuid"))?,
        );

        let scan_events_enabled = config
            .events
            .iter()
            .any(|e| e.name() == Type::FileScan.as_str() && e.is_enabled());

        let output = Self::prepare_output(&config)?;

        let mut ep = Self {
            system_info,
            config,
            engine: Engine::new(),
            iocs: HashMap::new(),
            random: util::getrandom::<u32>().unwrap(),
            cache: Cache::with_max_entries(10000),
            tasks: HashMap::with_capacity(512),
            exited_tasks: 0,
            resolved: HashMap::new(),
            output,
            file_scanner: None,
            scan_events_enabled,
        };

        // initializing yara rules
        ep.init_file_scanner()?;

        // initializing event scanner
        ep.init_event_scanner()?;

        // initialize IoCs
        ep.init_iocs()?;

        // should not raise any error, we just print it
        let _ = inspect_err! {
            ep.init_tasks_from_procfs(),
            |e: &anyhow::Error| warn!("failed to initialize tasks with procfs: {}", e)
        };

        Ok(ep)
    }

    #[inline(always)]
    fn init_file_scanner(&mut self) -> anyhow::Result<()> {
        let wo = WalkOptions::new()
            // we list only files
            .files()
            // will list only files
            // with following extensions
            .extension("yar")
            .extension("yara")
            // don't go recursive
            .max_depth(0);

        let mut c = yara_x::Compiler::new();

        let mut files_loaded = 0;
        for p in self.config.yara.iter() {
            debug!("looking for yara rules in: {}", p);
            let w = wo.clone().walk(p);
            for r in w {
                let rule_file = r?;
                info!(
                    "loading yara rule(s) from file: {}",
                    rule_file.to_string_lossy()
                );
                let src = SourceCode::from_rule_file(rule_file)?;
                c.add_source(src.to_native())?;
                files_loaded += 1;
            }
        }

        // we don't actually initialize an empty scanner
        if files_loaded > 0 {
            self.file_scanner = Some(Scanner::with_rules(c.build()));
        }

        Ok(())
    }

    fn init_event_scanner(&mut self) -> anyhow::Result<()> {
        // loading rules in the engine
        if self.config.rules.is_empty() {
            return Ok(());
        }

        let wo = WalkOptions::new()
            // we list only files
            .files()
            // will list only files
            // with following extensions
            .extension("gen")
            .extension("gene")
            // don't go recursive
            .max_depth(0);

        for p in self.config.rules.iter() {
            let w = wo.clone().walk(p);
            for r in w {
                let rule = r?;

                info!(
                    "loading detection/filter rules from: {}",
                    rule.to_string_lossy()
                );

                self.engine
                    .load_rules_yaml_reader(File::open(&rule)?)
                    .map_err(|e| anyhow!("failed to load file {}: {e}", rule.to_string_lossy()))?;
            }
        }

        info!("number of loaded rules: {}", self.engine.rules_count());

        Ok(())
    }

    fn init_iocs(&mut self) -> anyhow::Result<()> {
        // loading iocs
        if self.config.iocs.is_empty() {
            return Ok(());
        }

        let wo = WalkOptions::new()
            // we list only files
            .files()
            // will list only files
            // with following extensions
            .extension("ioc")
            // don't go recursive
            .max_depth(0);

        for p in self.config.iocs.clone() {
            let w = wo.clone().walk(p);
            for r in w {
                let f = r?;
                self.load_iocs(&f)
                    .map_err(|e| anyhow!("failed to load IoC file {}: {e}", f.to_string_lossy()))?;
            }
        }

        info!("number of IoCs loaded: {}", self.iocs.len());

        Ok(())
    }

    fn load_iocs<P: AsRef<Path>>(&mut self, p: P) -> io::Result<()> {
        let p = p.as_ref();
        let f = io::BufReader::new(File::open(p)?);

        for line in f.lines() {
            let line = line?;
            let ioc: IoC = serde_json::from_str(&line)?;
            self.iocs
                .entry(ioc.value)
                .and_modify(|e| *e = max(*e, ioc.severity))
                .or_insert(ioc.severity);
        }

        Ok(())
    }

    fn init_tasks_from_procfs(&mut self) -> anyhow::Result<()> {
        for p in (procfs::process::all_processes()?).flatten() {
            // flatten takes only the Ok() values of processes
            if let Err(e) = self.set_task_from_procfs(&p) {
                warn!(
                    "failed to initialize correlation for procfs process PID={}: {e}",
                    p.pid
                )
            }
        }

        // we try to resolve containers from tasks found in procfs
        for (tk, pk) in self
            .tasks
            .iter()
            .map(|(&k, v)| (k, v.parent_key))
            .collect::<Vec<(TaskKey, Option<TaskKey>)>>()
        {
            if let Some(parent) = pk {
                if let Some(t) = self.tasks.get_mut(&tk) {
                    // trying to find container type in cgroups
                    t.container = Container::from_cgroups(&t.cgroups);
                    if t.container.is_some() {
                        // we don't need to do the ancestor's lookup
                        continue;
                    }
                }

                // lookup in ancestors
                let ancestors = self.get_ancestors(parent, 0);
                if let Some(c) = Container::from_ancestors(&ancestors) {
                    self.tasks
                        .entry(tk)
                        .and_modify(|task| task.container = Some(c));
                }
            }
        }

        Ok(())
    }

    fn set_task_from_procfs(&mut self, p: &procfs::process::Process) -> anyhow::Result<()> {
        let stat = p.stat()?;

        let parent_pid = p.status()?.ppid;
        let parent_key = {
            if parent_pid != 0 {
                let parent = procfs::process::Process::new(parent_pid)?;
                Some(TaskKey::try_from(&parent)?)
            } else {
                None
            }
        };

        let tk = TaskKey::try_from(p)?;

        if self.tasks.contains_key(&tk) {
            return Ok(());
        }

        let image = {
            if stat.flags & 0x200000 == 0x200000 {
                KERNEL_IMAGE.into()
            } else {
                p.exe().unwrap_or("?".into())
            }
        };

        // we gather cgroups
        let cgroups = p
            .cgroups()?
            .0
            .into_iter()
            .map(|cg| cg.pathname)
            .collect::<Vec<String>>();

        let task = Task {
            image,
            command_line: p.cmdline().unwrap_or(vec!["?".into()]),
            pid: p.pid,
            flags: stat.flags,
            resolved: HashMap::new(),
            container: None,
            cgroups,
            nodename: None,
            parent_key,
            threads: HashSet::new(),
            procfs: true,
            exit: false,
        };

        self.tasks.insert(tk, task);

        Ok(())
    }

    #[inline]
    fn get_exe(&self, key: TaskKey) -> PathBuf {
        let mut exe = PathBuf::from("?");
        if let Some(task) = self.tasks.get(&key) {
            exe = task.image.clone();
        }
        exe
    }

    #[inline]
    fn get_command_line(&self, key: TaskKey) -> String {
        let mut cl = String::from("?");
        if let Some(t) = self.tasks.get(&key) {
            cl = t.command_line_string();
        }
        cl
    }

    #[inline]
    fn get_exe_and_command_line(&self, i: &StdEventInfo) -> (PathBuf, String) {
        let ck = i.task_key();
        (self.get_exe(ck), self.get_command_line(ck))
    }

    /// get the list of ancestors given a [TaskKey]. If skip is 0 the last
    /// item is the image of the task referenced by `tk`. One can skip ancestors
    /// by setting `skip` > 0.
    #[inline]
    fn get_ancestors(&self, mut tk: TaskKey, mut skip: u16) -> Vec<String> {
        let mut ancestors = vec![];
        let mut last = None;

        while let Some(task) = self.tasks.get(&tk) {
            last = Some(task);
            if skip == 0 {
                ancestors.insert(0, task.image.to_string_lossy().to_string());
            } else {
                skip -= 1;
            }

            tk = match task.parent_key {
                Some(v) => v,
                None => {
                    break;
                }
            };
        }

        if let Some(last) = last {
            if last.pid != 1 && !last.is_kthread() && skip == 0 {
                ancestors.insert(0, "?".into());
            }
        }

        ancestors
    }

    #[inline]
    fn get_ancestors_string(&self, i: &StdEventInfo) -> String {
        self.get_ancestors(i.task_key(), 1).join("|")
    }

    #[inline]
    fn get_parent_image(&self, i: &StdEventInfo) -> String {
        let ck = i.parent_key();
        self.tasks
            .get(&ck)
            .map(|c| c.image.to_string_lossy().to_string())
            .unwrap_or("?".into())
    }

    #[inline]
    fn update_resolved(&mut self, ip: IpAddr, resolved: &str, i: &StdEventInfo) {
        let ck = i.task_key();

        // update local resolve table
        self.tasks.get_mut(&ck).map(|c| {
            c.resolved
                .entry(ip)
                .and_modify(|r| *r = resolved.to_owned())
                .or_insert(resolved.to_owned())
        });

        // update global resolve table
        self.resolved
            .entry(ip)
            .and_modify(|r| *r = resolved.to_owned())
            .or_insert(resolved.to_owned());
    }

    #[inline]
    fn get_resolved(&self, ip: IpAddr, i: &StdEventInfo) -> Cow<'_, str> {
        let ck = i.task_key();

        // we lookup in the local table
        if let Some(domain) = self
            .tasks
            .get(&ck)
            .and_then(|c| c.resolved.get(&ip).map(Cow::from))
        {
            return domain;
        }

        // we lookup in the global table
        if let Some(domain) = self.resolved.get(&ip) {
            return domain.into();
        }

        // default value
        "?".into()
    }

    #[inline]
    fn get_hashes_with_ns(&mut self, ns: Option<Namespace>, p: &cache::Path) -> Hashes {
        if let Some(ns) = ns {
            match self.cache.get_or_cache_in_ns(ns, p) {
                Ok(h) => h,
                Err(e) => Hashes {
                    file: p.to_path_buf().clone(),
                    meta: FileMeta {
                        error: Some(format!("{e}")),
                        ..Default::default()
                    },
                },
            }
        } else {
            Hashes {
                file: p.to_path_buf().clone(),
                meta: FileMeta {
                    error: Some("unknown namespace".into()),
                    ..Default::default()
                },
            }
        }
    }

    #[inline(always)]
    /// method acting as a central place to get the mnt namespace of a
    /// task and printing out an error if not found
    fn task_mnt_ns(ei: &bpf_events::EventInfo) -> Option<Namespace> {
        match ei.process.namespaces {
            Some(ns) => Some(Namespace::mnt(ns.mnt)),
            None => {
                error!("task namespace must be known");
                None
            }
        }
    }

    #[inline]
    fn execve_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::ExecveEvent,
    ) -> UserEvent<ExecveData> {
        let ancestors = self.get_ancestors(info.parent_key(), 0);

        let opt_mnt_ns = Self::task_mnt_ns(&event.info);

        let mut data = ExecveData {
            ancestors: ancestors.join("|"),
            parent_exe: self.get_parent_image(&info),
            command_line: event.data.argv.to_command_line(),
            exe: self.get_hashes_with_ns(opt_mnt_ns, &cache::Path::from(&event.data.executable)),
            interpreter: None,
        };

        if event.data.executable != event.data.interpreter {
            data.interpreter = Some(
                self.get_hashes_with_ns(opt_mnt_ns, &cache::Path::from(&event.data.interpreter)),
            )
        }

        UserEvent::new(data, info)
    }

    #[inline]
    fn clone_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::CloneEvent,
    ) -> UserEvent<CloneData> {
        let data = CloneData {
            ancestors: self.get_ancestors_string(&info),
            exe: event.data.executable.to_path_buf().into(),
            command_line: event.data.argv.to_command_line(),
            flags: event.data.flags,
        };
        UserEvent::new(data, info)
    }

    #[inline]
    fn prctl_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::PrctlEvent,
    ) -> UserEvent<PrctlData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let option = PrctlOption::try_from_uint(event.data.option)
            .map(|o| o.as_str().into())
            .unwrap_or(format!("unknown({})", event.data.option))
            .to_string();

        let data = PrctlData {
            ancestors: self.get_ancestors_string(&info),
            exe: exe.into(),
            command_line,
            option,
            arg2: event.data.arg2,
            arg3: event.data.arg3,
            arg4: event.data.arg4,
            arg5: event.data.arg5,
            success: event.data.success,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn kill_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::KillEvent,
    ) -> UserEvent<KillData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let signal = Signal::from_uint_to_string(event.data.signal);

        // we need to set uuid part of target task
        let mut target = event.data.target;
        target.set_uuid_random(self.random);

        // get the command line
        let tk = TaskKey::from(target.tg_uuid);

        let data = KillData {
            ancestors: self.get_ancestors_string(&info),
            exe: exe.into(),
            command_line,
            signal,
            target: TargetTask {
                command_line: self.get_command_line(tk),
                exe: self.get_exe(tk).into(),
                task: target.into(),
            },
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn mmap_exec_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::MmapExecEvent,
    ) -> UserEvent<kunai::events::MmapExecData> {
        let filename = event.data.filename;
        let opt_mnt_ns = Self::task_mnt_ns(&event.info);
        let mmapped_hashes = self.get_hashes_with_ns(opt_mnt_ns, &cache::Path::from(&filename));

        let ck = info.task_key();

        let exe = self.get_exe(ck);

        let data = kunai::events::MmapExecData {
            ancestors: self.get_ancestors_string(&info),
            command_line: self.get_command_line(ck),
            exe: exe.into(),
            mapped: mmapped_hashes,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn dns_query_events(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::DnsQueryEvent,
    ) -> Vec<UserEvent<DnsQueryData>> {
        let mut out = vec![];
        let ck = info.task_key();
        let exe = self.get_exe(ck);
        let command_line = self.get_command_line(ck);

        let serv_ip: IpAddr = event.data.ip_port.into();
        let serv_port = event.data.ip_port.port();

        let proto = match event.data.proto {
            1 => "tcp".into(),
            2 => "udp".into(),
            _ => format!("unknown({})", event.data.proto),
        };

        let responses = event.data.answers().unwrap_or_default();
        let ancestors = self.get_ancestors_string(&info);

        for r in responses {
            let mut data = DnsQueryData::new().with_responses(r.answers);
            data.ancestors = ancestors.clone();
            data.command_line = command_line.clone();
            data.exe = exe.clone().into();
            data.query = r.question.clone();
            data.proto = proto.clone();
            data.dns_server = NetworkInfo {
                hostname: None,
                ip: serv_ip,
                port: serv_port,
                public: is_public_ip(serv_ip),
                is_v6: event.data.ip_port.is_v6(),
            };

            // update the resolution map
            data.responses().iter().for_each(|a| {
                // if we manage to parse IpAddr
                if let Ok(ip) = a.parse::<IpAddr>() {
                    self.update_resolved(ip, &r.question, &info);
                }
            });

            out.push(UserEvent::new(data, info.clone()));
        }

        out
    }

    #[inline]
    fn file_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::FileEvent,
    ) -> UserEvent<FileData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = FileData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            path: event.data.path.to_path_buf(),
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn unlink_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::UnlinkEvent,
    ) -> UserEvent<UnlinkData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = UnlinkData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            path: event.data.path.into(),
            success: event.data.success,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn bpf_prog_load_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::BpfProgLoadEvent,
    ) -> UserEvent<BpfProgLoadData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let mut data = BpfProgLoadData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            id: event.data.id,
            prog_type: BpfProgTypeInfo {
                id: event.data.prog_type,
                name: util::bpf::bpf_type_to_string(event.data.prog_type),
            },
            tag: hex::encode(event.data.tag),
            attached_func: event.data.attached_func_name.into(),
            name: event.data.name.into(),
            ksym: event.data.ksym.into(),
            bpf_prog: kunai::events::BpfProgInfo {
                md5: "?".into(),
                sha1: "?".into(),
                sha256: "?".into(),
                sha512: "?".into(),
                size: 0,
            },
            verified_insns: event.data.verified_insns,
            loaded: event.data.loaded,
        };

        if let Some(h) = &event.data.hashes {
            data.bpf_prog.md5 = h.md5.into();
            data.bpf_prog.sha1 = h.sha1.into();
            data.bpf_prog.sha256 = h.sha256.into();
            data.bpf_prog.sha512 = h.sha512.into();
            data.bpf_prog.size = h.size;
        }

        UserEvent::new(data, info)
    }

    #[inline]
    fn bpf_socket_filter_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::BpfSocketFilterEvent,
    ) -> UserEvent<BpfSocketFilterData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = BpfSocketFilterData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            socket: SocketInfo {
                domain: event.data.socket_info.domain_to_string(),
                ty: event.data.socket_info.type_to_string(),
            },
            filter: FilterInfo {
                md5: md5_data(event.data.filter.as_slice()),
                sha1: sha1_data(event.data.filter.as_slice()),
                sha256: sha256_data(event.data.filter.as_slice()),
                sha512: sha512_data(event.data.filter.as_slice()),
                len: event.data.filter_len, // size in filter sock_filter blocks
                size: event.data.filter.len(), // size in bytes
            },
            attached: event.data.attached,
        };

        //Self::json_event(info, data)
        UserEvent::new(data, info)
    }

    #[inline]
    fn mprotect_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::MprotectEvent,
    ) -> UserEvent<MprotectData> {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let data = MprotectData {
            ancestors: self.get_ancestors_string(&info),
            command_line: cmd_line,
            exe: exe.into(),
            addr: event.data.start,
            prot: event.data.prot,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn connect_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::ConnectEvent,
    ) -> UserEvent<ConnectData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);
        let src: SockAddr = event.data.src.into();
        let dst: SockAddr = event.data.dst.into();

        let flow: Flow = Flow::new(Protocol::TCP, src.ip, src.port, dst.ip, dst.port);

        let data = ConnectData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            src,
            dst: NetworkInfo {
                hostname: Some(self.get_resolved(dst.ip, &info).into()),
                ip: dst.ip,
                port: dst.port,
                public: is_public_ip(dst.ip),
                is_v6: dst.ip.is_ipv6(),
            },
            community_id: flow.community_id_v1(0).base64(),
            connected: event.data.connected,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn send_data_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::SendEntropyEvent,
    ) -> UserEvent<SendDataData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);
        let dst: SockAddr = event.data.dst.into();
        let src: SockAddr = event.data.src.into();

        let flow = Flow::new(Protocol::TCP, src.ip, src.port, dst.ip, dst.port);

        let data = SendDataData {
            ancestors: self.get_ancestors_string(&info),
            exe: exe.into(),
            command_line,
            src: event.data.src.into(),
            dst: NetworkInfo {
                hostname: Some(self.get_resolved(dst.ip, &info).into()),
                ip: dst.ip,
                port: dst.port,
                public: is_public_ip(dst.ip),
                is_v6: dst.ip.is_ipv6(),
            },
            community_id: flow.community_id_v1(0).base64(),
            data_entropy: event.shannon_entropy(),
            data_size: event.data.real_data_size,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn init_module_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::InitModuleEvent,
    ) -> UserEvent<InitModuleData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = InitModuleData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            syscall: event.data.args.syscall_name().into(),
            module_name: event.data.name.to_string(),
            args: event.data.uargs.to_string(),
            loaded: event.data.loaded,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn file_rename_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::FileRenameEvent,
    ) -> UserEvent<FileRenameData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = FileRenameData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            old: event.data.old_name.into(),
            new: event.data.new_name.into(),
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn exit_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::ExitEvent,
    ) -> UserEvent<ExitData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = ExitData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            error_code: event.data.error_code,
        };

        let etype = event.ty();
        // cleanup tasks when process exits
        if (matches!(etype, Type::Exit) && info.info.process.pid == info.info.process.tgid)
            || matches!(etype, Type::ExitGroup)
        {
            let tk = info.task_key();

            // we are exiting so our parent has one child less
            self.tasks.entry(info.parent_key()).and_modify(|t| {
                t.threads.remove(&tk);
            });

            // hashset of threads to be removed
            let mut remove_threads = HashSet::new();

            if let Some(t) = self.tasks.get(&tk) {
                // in case on exit_group we need to clean child
                // threads properly
                if matches!(etype, Type::ExitGroup) {
                    remove_threads.extend(t.threads.clone());
                }

                if t.threads.is_empty() && !t.procfs {
                    // if the task has no child and is not coming from procfs
                    // we can remove it from the table.
                    self.tasks.remove(&tk);
                } else {
                    // we can free up some memory and tag the task as exited
                    self.tasks.entry(tk).and_modify(|t| t.on_exit());
                }
            }

            if !remove_threads.is_empty() {
                // as parent we can decrease the number of our children
                self.tasks
                    .entry(tk)
                    .and_modify(|t| t.threads.retain(|k| !remove_threads.contains(k)));

                // for every child, we mark it as exited
                for c in remove_threads {
                    self.tasks.entry(c).and_modify(|t| t.on_exit());
                }
            }

            // we trigger some very specific cleanup
            if self.exited_tasks % 1000 == 0 {
                // we remove shadow tasks exited with no child
                self.tasks.retain(|_, t| !(t.exit && t.threads.is_empty()));
                // shrinking tasks HashMap
                self.tasks.shrink_to_fit();
            }

            self.exited_tasks = self.exited_tasks.wrapping_add(1);
        }

        UserEvent::new(data, info)
    }

    #[inline]
    fn handle_correlation_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::CorrelationEvent,
    ) {
        let ck = info.task_key();

        // Execve must remove any previous task (i.e. coming from
        // clone or tasksched for instance)
        if matches!(event.data.origin, Type::Execve | Type::ExecveScript) {
            self.tasks.remove(&ck);
        }

        // early return if task key exists
        if let Some(v) = self.tasks.get_mut(&ck) {
            // we fix nodename if not set yet
            // tasks init from procfs are lacking nodename
            if v.nodename.is_none() {
                v.nodename = event.data.nodename()
            }
            return;
        }

        let cgroup = event.data.cgroup;

        // we encountered some cgroup parsing error in eBPF
        // so we need to resolve cgroup in userland
        let cgroups = match cgroup.error {
            None => vec![cgroup.to_string()],
            Some(_) => {
                if let Ok(cgroups) =
                    procfs::process::Process::new(info.info.process.pid).and_then(|p| p.cgroups())
                {
                    // we return cgroup from procfs
                    cgroups
                        .0
                        .into_iter()
                        .map(|cg| cg.pathname)
                        .collect::<Vec<String>>()
                } else {
                    // we report an error
                    warn!(
                        "failed to resolve cgroup for pid={} guuid={}",
                        info.info.process.pid,
                        info.info.process.tg_uuid.into_uuid().hyphenated()
                    );
                    // still get a chance to do something with cgroup
                    vec![cgroup.to_string()]
                }
            }
        };

        let mut container_type = Container::from_cgroups(&cgroups);

        if container_type.is_none() {
            let ancestors = self.get_ancestors(info.parent_key(), 0);
            container_type = Container::from_ancestors(&ancestors);
        }

        let image = {
            if info.info.process.is_kernel_thread() {
                KERNEL_IMAGE.into()
            } else {
                event.data.exe.to_path_buf()
            }
        };

        // we update parent's information
        if matches!(event.data.origin, Type::Clone) {
            // the source is a Clone event so our task has spawned a child thread
            self.tasks.entry(info.parent_key()).and_modify(|e| {
                e.threads.insert(info.task_key());
            });
        }

        // we insert only if not existing
        self.tasks.entry(ck).or_insert(Task {
            image,
            command_line: event.data.argv.to_argv(),
            pid: info.info.process.tgid,
            flags: info.info.process.flags,
            resolved: HashMap::new(),
            container: container_type,
            cgroups,
            nodename: event.data.nodename(),
            parent_key: Some(info.parent_key()),
            threads: HashSet::new(),
            procfs: false,
            exit: false,
        });
    }

    #[inline]
    fn handle_hash_event(&mut self, info: StdEventInfo, event: &bpf_events::HashEvent) {
        let opt_mnt_ns = Self::task_mnt_ns(&info.info);
        self.get_hashes_with_ns(opt_mnt_ns, &cache::Path::from(&event.data.path));
    }

    fn build_std_event_info(&mut self, i: bpf_events::EventInfo) -> StdEventInfo {
        let opt_mnt_ns = Self::task_mnt_ns(&i);

        let std_info = StdEventInfo::from_bpf(i, self.random);

        let cd = self.tasks.get(&std_info.task_key());

        let host = kunai::info::HostInfo {
            name: self.system_info.hostname.clone(),
            uuid: self.system_info.host_uuid,
        };

        let mut container = None;

        if let Some(mnt_ns) = opt_mnt_ns {
            if mnt_ns != self.system_info.mount_ns {
                container = Some(kunai::info::ContainerInfo {
                    name: cd.and_then(|t| t.nodename.clone()).unwrap_or("?".into()),
                    ty: cd.and_then(|cd| cd.container),
                });
            }
        }

        std_info.with_additional_info(AdditionalInfo { host, container })
    }

    #[inline(always)]
    fn scan<T: Serialize + KunaiEvent>(&mut self, event: &mut T) -> Option<ScanResult> {
        let mut scan_result: Option<ScanResult> = None;

        if !self.engine.is_empty() {
            scan_result = match self.engine.scan(event) {
                Ok(sr) => sr.map(ScanResult::from),
                Err((sr, e)) => {
                    error!("event scanning error: {e}");
                    sr.map(ScanResult::from)
                }
            };
        }

        // we collect a vector of ioc matching
        let matching_iocs = event
            .iocs()
            .iter()
            .filter(|ioc| self.iocs.contains_key(&ioc.to_string()))
            .map(|ioc| ioc.to_string())
            .collect::<HashSet<String>>();

        let ioc_severity: usize = matching_iocs
            .iter()
            .map(|ioc| self.iocs.get(ioc).map(|e| *e as usize).unwrap_or_default())
            .sum();

        if !matching_iocs.is_empty() {
            // we create a new ScanResult if necessary
            if scan_result.is_none() {
                scan_result = Some(ScanResult::default());
            }

            // we add ioc matching to the list of matching rules
            if let Some(sr) = scan_result.as_mut() {
                sr.iocs = matching_iocs;
                sr.severity = ioc_severity.clamp(0, MAX_SEVERITY as usize) as u8;
            }
        }

        scan_result
    }

    #[inline(always)]
    fn handle_actions<T: Serialize + KunaiEvent>(
        &mut self,
        event: &T,
        actions: &HashSet<String>,
        is_detection: bool,
    ) {
        // some actions are allowed only for detections
        #[allow(clippy::collapsible_if)]
        if is_detection {
            // for the moment we only support killing the
            // task itself and not its parent. Additional
            // care must be taken to the parent as we need
            // to be sure we are not killing something critical.
            // Generally speaking killing action must be done with
            // care as sending a SIGKILL to a critical process
            // might impact the system.
            if actions.contains(Actions::Kill.as_str()) {
                let pid = event.info().task.pid;
                // this is the kind of information we want to have
                // at all time so we put this as a warning not to
                // be disabled by the default logging policy
                warn!("sending SIGKILL to PID={pid}");
                if let Err(e) = kill(pid, libc::SIGKILL) {
                    error!("error sending SIGKILL to PID={pid}: {e}")
                }
            }
        }

        // if action contains scan-file and if scan events are enabled
        if self.scan_events_enabled && actions.contains(Actions::ScanFiles.as_str()) {
            let _ = self
                .action_scan_files(event)
                .inspect_err(|e| error!("{} action failed: {e}", Actions::ScanFiles));
        }
    }

    #[inline(always)]
    fn file_scan_event<T: Serialize + KunaiEvent>(
        &mut self,
        event: &T,
        ns: Namespace,
        p: &Path,
    ) -> UserEvent<FileScanData> {
        // if the scanner is None, signatures will be an empty Vec
        let (sigs, err) = match self.file_scanner.as_mut() {
            Some(s) => match self
                .cache
                .get_sig_or_cache(ns, &cache::Path::from(p.to_path_buf()), s)
            {
                Ok(sigs) => (sigs, None),
                Err(e) => (vec![], Some(format!("{e}"))),
            },
            None => (vec![], None),
        };

        let pos = sigs.len();
        let mut data = FileScanData::from_hashes(
            self.get_hashes_with_ns(Some(ns), &cache::Path::from(p.to_path_buf())),
        );
        data.source_event = event.info().event.uuid.clone();
        data.signatures = sigs;
        data.positives = pos;
        data.scan_error = err;

        let info = EventInfo::from_other_with_type(event.info().clone(), Type::FileScan);
        UserEvent::with_data_and_info(data, info)
    }

    #[inline(always)]
    fn action_scan_files<T: Serialize + KunaiEvent>(&mut self, event: &T) -> anyhow::Result<()> {
        // this check prevents infinite loop for FileScan events
        if event.info().event.id == Type::FileScan.id() {
            return Ok(());
        }

        let ns = match event.info().task.namespaces.as_ref() {
            Some(ns) => Namespace::mnt(ns.mnt),
            None => return Err(anyhow!("namespace not found")),
        };

        for p in event.scannable_files() {
            let mut event = self.file_scan_event(event, ns, &p);
            // print a warning if a positive scan happens so that a trace
            // is kept in system logs
            if event.data.positives > 0 {
                warn!(
                    "file={} matches detection signatures={:?} triggered by event uuid={}",
                    p.to_string_lossy(),
                    &event.data.signatures,
                    &event.info().event.uuid,
                );
            }

            // we run through event scanning engine
            let got_printed = self.scan_and_print(&mut event);

            if !got_printed && self.config.always_show_positive_scans {
                match serde_json::to_string(&event) {
                    Ok(ser) => writeln!(self.output, "{ser}").expect("failed to write json event"),
                    Err(e) => error!("failed to serialize event to json: {e}"),
                }
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn scan_and_print<T: Serialize + KunaiEvent>(&mut self, event: &mut T) -> bool {
        let mut printed = false;

        macro_rules! print_serialized {
            ($event:expr) => {
                match serde_json::to_string($event) {
                    Ok(ser) => {
                        writeln!(self.output, "{ser}").expect("failed to write json event");
                        printed = true;
                    }
                    Err(e) => error!("failed to serialize event to json: {e}"),
                }
            };
        }

        // we have neither rules nor iocs to inspect for
        if self.iocs.is_empty() && self.engine.is_empty() {
            print_serialized!(event);
            return printed;
        }

        // scan for iocs and filter/matching rules
        if let Some(sr) = self.scan(event) {
            if sr.is_detection() {
                event.set_detection(sr);
                print_serialized!(event);
                // get_detection will always be false for filters
                if let Some(sr) = event.get_detection() {
                    self.handle_actions(event, &sr.actions, true);
                }
            } else if sr.is_only_filter() {
                print_serialized!(event);
                self.handle_actions(event, &sr.actions, false);
            }
        }

        printed
    }

    fn handle_event(&mut self, enc_event: &mut EncodedEvent) {
        let i = unsafe { enc_event.info() }.unwrap();

        // we don't handle our own events
        if i.process.tgid as u32 == std::process::id() {
            debug!("skipping our event");
        }

        let etype = i.etype;

        if let Some(mnt_ns) = Self::task_mnt_ns(i) {
            let pid = i.process.pid;
            if let Err(e) = self.cache.cache_ns(pid, mnt_ns) {
                debug!("failed to cache namespace pid={pid} ns={mnt_ns}: {e}");
            }
        }

        let std_info = self.build_std_event_info(*i);

        match etype {
            Type::Unknown => {
                error!("Unknown event type: {}", etype as u64)
            }
            Type::Max | Type::EndConfigurable | Type::TaskSched | Type::FileScan => {}
            Type::Execve | Type::ExecveScript => {
                match event!(enc_event, bpf_events::ExecveEvent) {
                    Ok(e) => {
                        // this event is used for correlation but cannot be processed
                        // asynchronously so we have to handle correlation here
                        self.handle_correlation_event(
                            std_info.clone(),
                            &bpf_events::CorrelationEvent::from(e),
                        );
                        // we have to rebuild std_info as it has it is uses correlation
                        // information
                        let std_info = self.build_std_event_info(std_info.info);
                        let mut e = self.execve_event(std_info, e);

                        self.scan_and_print(&mut e);
                    }
                    Err(e) => error!("failed to decode {} event: {:?}", etype, e),
                }
            }

            Type::Clone => match event!(enc_event, bpf_events::CloneEvent) {
                Ok(e) => {
                    // this event is used for correlation but cannot be processed
                    // asynchronously so we have to handle correlation here
                    self.handle_correlation_event(
                        std_info.clone(),
                        &bpf_events::CorrelationEvent::from(e),
                    );
                    // we have to rebuild std_info as it has it is uses correlation
                    // information
                    let std_info = self.build_std_event_info(std_info.info);
                    let mut e = self.clone_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Prctl => match event!(enc_event, bpf_events::PrctlEvent) {
                Ok(e) => {
                    let mut e = self.prctl_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Kill => match event!(enc_event, bpf_events::KillEvent) {
                Ok(e) => {
                    let mut e = self.kill_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::MmapExec => match event!(enc_event, bpf_events::MmapExecEvent) {
                Ok(e) => {
                    let mut e = self.mmap_exec_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::MprotectExec => match event!(enc_event, bpf_events::MprotectEvent) {
                Ok(e) => {
                    let mut e = self.mprotect_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Connect => match event!(enc_event, bpf_events::ConnectEvent) {
                Ok(e) => {
                    let mut e = self.connect_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::DnsQuery => match event!(enc_event, bpf_events::DnsQueryEvent) {
                Ok(e) => {
                    for e in self.dns_query_events(std_info, e).iter_mut() {
                        self.scan_and_print(e);
                    }
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::SendData => match event!(enc_event, bpf_events::SendEntropyEvent) {
                Ok(e) => {
                    let mut e = self.send_data_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::InitModule => match event!(enc_event, bpf_events::InitModuleEvent) {
                Ok(e) => {
                    let mut e = self.init_module_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::WriteConfig
            | Type::Write
            | Type::ReadConfig
            | Type::Read
            | Type::WriteAndClose => match event!(enc_event, bpf_events::FileEvent) {
                Ok(e) => {
                    let mut e = self.file_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::FileUnlink => match event!(enc_event, bpf_events::UnlinkEvent) {
                Ok(e) => {
                    let mut e = self.unlink_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::FileRename => match event!(enc_event, bpf_events::FileRenameEvent) {
                Ok(e) => {
                    let mut e = self.file_rename_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::BpfProgLoad => match event!(enc_event, bpf_events::BpfProgLoadEvent) {
                Ok(e) => {
                    let mut e = self.bpf_prog_load_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::BpfSocketFilter => match event!(enc_event, bpf_events::BpfSocketFilterEvent) {
                Ok(e) => {
                    let mut e = self.bpf_socket_filter_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Exit | Type::ExitGroup => match event!(enc_event, bpf_events::ExitEvent) {
                Ok(e) => {
                    let mut e = self.exit_event(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Correlation => match event!(enc_event) {
                Ok(e) => {
                    self.handle_correlation_event(std_info, e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::CacheHash => match event!(enc_event) {
                Ok(e) => {
                    self.handle_hash_event(std_info, e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Error => panic!("error events should be processed earlier"),
            Type::SyscoreResume => { /*  just ignore it */ }
        }
    }
}

struct EventProducer {
    config: Config,
    batch: usize,
    pipe: VecDeque<EncodedEvent>,
    sender: mpsc::Sender<EncodedEvent>,
    filter: Filter,
    stats: AyaHashMap<MapData, Type, u64>,
    perf_array: AsyncPerfEventArray<MapData>,
    tasks: Vec<tokio::task::JoinHandle<Result<(), anyhow::Error>>>,
    stop: bool,
    // flag to be set when the producer needs to reload
    reload: bool,
}

#[inline(always)]
const fn optimal_page_count(page_size: usize, max_event_size: usize, n_events: usize) -> usize {
    // Aya's PerfBuffer expects a page_count being a power of two
    // this is something required by the linux kernel
    ((max_event_size * n_events) / page_size).next_power_of_two()
}

impl EventProducer {
    pub fn with_params(
        bpf: &mut Bpf,
        config: Config,
        sender: mpsc::Sender<EncodedEvent>,
    ) -> anyhow::Result<Self> {
        let filter = (&config).try_into()?;
        let stats_map: AyaHashMap<_, Type, u64> =
            AyaHashMap::try_from(bpf.take_map(bpf_events::KUNAI_STATS_MAP).unwrap()).unwrap();

        let perf_array =
            AsyncPerfEventArray::try_from(bpf.take_map(bpf_events::KUNAI_EVENTS_MAP).unwrap())
                .unwrap();

        Ok(EventProducer {
            config,
            pipe: VecDeque::new(),
            batch: 0,
            sender,
            filter,
            stats: stats_map,
            perf_array,
            tasks: vec![],
            stop: false,
            reload: false,
        })
    }

    // Event ordering is a very important piece as it impacts on-host correlations.
    // Additionaly it is very useful as it guarantees events are printed/piped into
    // other tools in the damn good order.
    #[inline(always)]
    async fn process_piped_events(&mut self) -> Result<usize, SendError<EncodedEvent>> {
        let mut c = 0;
        // nothing to do
        if self.pipe.is_empty() {
            return Ok(c);
        }

        // we sort events out by timestamp
        // this should never fail because we pushed only
        // events for which info can be decoded
        self.pipe
            .make_contiguous()
            .sort_unstable_by_key(|enc_evt| unsafe { enc_evt.info_unchecked().timestamp });

        while let Some(enc_evt) = self.pipe.front() {
            let eb = unsafe { enc_evt.info_unchecked() }.batch;
            // process all events but the current batch
            if eb >= self.batch.saturating_sub(1) {
                break;
            }
            // send event to event processor
            self.sender
                // unwrap cannot fail as we are sure there is an element at front
                .send(self.pipe.pop_front().unwrap())
                .await?;
            c += 1;
        }

        Ok(c)
    }

    #[inline]
    async fn send_event<T>(&self, event: Event<T>) -> Result<(), SendError<EncodedEvent>> {
        self.sender.send(EncodedEvent::from_event(event)).await
    }

    /// function used to pre-process some targetted events where time is critical and for which
    /// processing can be done in EventReader
    /// this function must return true if main processing loop has to pass to the next event
    /// after the call.
    #[inline]
    fn process_time_critical(&mut self, e: &mut EncodedEvent) -> bool {
        let i = unsafe { e.info() }.expect("info should not fail here");

        #[allow(clippy::single_match)]
        match i.etype {
            Type::Execve => {
                let event = mut_event!(e, bpf_events::ExecveEvent).unwrap();
                if event.data.interpreter != event.data.executable {
                    event.info.etype = Type::ExecveScript
                }
            }
            Type::BpfProgLoad => {
                let event = mut_event!(e, bpf_events::BpfProgLoadEvent).unwrap();

                // dumping eBPF program from userland
                match util::bpf::bpf_dump_xlated_by_id_and_tag(event.data.id, event.data.tag) {
                    Ok(insns) => {
                        let h = bpf_events::ProgHashes {
                            md5: md5_data(insns.as_slice()).try_into().unwrap(),
                            sha1: sha1_data(insns.as_slice()).try_into().unwrap(),
                            sha256: sha256_data(insns.as_slice()).try_into().unwrap(),
                            sha512: sha512_data(insns.as_slice()).try_into().unwrap(),
                            size: insns.len(),
                        };

                        event.data.hashes = Some(h);
                    }

                    Err(e) => {
                        if e.is_io_error_not_found() {
                            // It may happen that we do not manage to get program's metadata. This happens
                            // when programs gets loaded and very quickly unloaded. It seems a common
                            // practice to load a few eBPF instructions (Aya, Docker ...) to test eBPF features.
                            warn!("couldn't retrieve bpf program's metadata for event={}, it probably got unloaded too quickly", event.info.uuid.into_uuid().as_hyphenated());
                        } else {
                            error!("failed to retrieve bpf_prog instructions: {}", e);
                        }
                    }
                }
            }
            Type::Error => {
                let e = event!(e, bpf_events::ErrorEvent).unwrap();
                match e.data.level {
                    error::Level::Warn => warn!("{}", e),
                    error::Level::Error => error!("{}", e),
                }
                // we don't need to process such event further
                return true;
            }
            Type::SyscoreResume => {
                debug!("received syscore_resume event");
                self.reload = true;
                // we don't need to process such event further
                return true;
            }
            _ => {}
        }

        false
    }

    /// this method pass through some events directly to the event processor
    /// only events that can be processed asynchronously should be passed through
    async fn pass_through_events(&self, e: &EncodedEvent) {
        let i = unsafe { e.info() }.unwrap();

        match i.etype {
            Type::Execve | Type::ExecveScript => {
                let event = event!(e, bpf_events::ExecveEvent).unwrap();
                for e in bpf_events::HashEvent::all_from_execve(event) {
                    self.send_event(e).await.unwrap();
                }
            }

            Type::MmapExec => {
                let event = event!(e, bpf_events::MmapExecEvent).unwrap();
                self.send_event(bpf_events::HashEvent::from(event))
                    .await
                    .unwrap();
            }

            _ => {}
        }
    }

    async fn produce(self) -> Arc<Mutex<Self>> {
        let online_cpus = online_cpus().expect("failed to get online cpus");
        let barrier = Arc::new(Barrier::new(online_cpus.len()));
        // we choose what task will handle the reduce process (handle piped events)
        let leader_cpu_id = online_cpus[0];
        let config = self.config.clone();
        let shared = Arc::new(Mutex::new(self));

        let event_producer = shared.clone();

        // we spawn a task processing events waiting in the pipe
        let t = task::spawn(async move {
            loop {
                let c = event_producer.lock().await.process_piped_events().await?;

                // we break the loop if producer is stopped
                if event_producer.lock().await.stop {
                    break;
                }

                // we adapt sleep time when load increases
                let millis = match c {
                    0..=500 => 100,
                    501..=1000 => 50,
                    1001.. => 25,
                };

                tokio::time::sleep(Duration::from_millis(millis)).await;
            }

            Ok::<_, anyhow::Error>(())
        });

        shared.lock().await.tasks.push(t);

        for cpu_id in online_cpus {
            // open a separate perf buffer for each cpu
            let mut buf = shared
                .lock()
                .await
                .perf_array
                .open(
                    cpu_id,
                    Some(optimal_page_count(
                        PAGE_SIZE,
                        MAX_BPF_EVENT_SIZE,
                        config.max_buffered_events as usize,
                    )),
                )
                .unwrap();
            let event_producer = shared.clone();
            let bar = barrier.clone();
            let conf = config.clone();

            // process each perf buffer in a separate task
            let t = task::spawn(async move {
                // the number of buffers we want to use gives us the number of events we can read
                // in one go in userland
                let mut buffers = (0..conf.max_buffered_events)
                    .map(|_| BytesMut::with_capacity(MAX_BPF_EVENT_SIZE))
                    .collect::<Vec<_>>();

                let timeout = time::Duration::from_millis(10);

                loop {
                    // we time this out so that the barrier does not wait too long
                    let events =
                    // this is timing out only if we cannot access the perf array as long as the buffer
                    // is available events will be read (because only waiting for the buffer is async).
                        match time::timeout(timeout, buf.read_events(&mut buffers)).await {
                            Ok(r) => r?,
                            _ => Events { read: 0, lost: 0 },
                        };

                    // checking out lost events
                    if events.lost > 0 {
                        error!(
                            "some events have been lost in the way from kernel read={} lost={}: consider filtering out some events or increase the number of buffered events in configuration",
                            events.read, events.lost
                        );

                        {
                            let ep = event_producer.lock().await;
                            for ty in Type::variants() {
                                if ty.is_configurable() {
                                    error!(
                                        "stats {}: {}",
                                        ty,
                                        ep.stats.get(&ty, 0).unwrap_or_default()
                                    );
                                }
                            }
                            // drop producer
                        }
                    }

                    // events.read contains the number of events that have been read,
                    // and is always <= buffers.len()
                    for buf in buffers.iter().take(events.read) {
                        let mut dec = EncodedEvent::from_bytes(buf);
                        let mut ep = event_producer.lock().await;

                        // we make sure here that only events for which we can grab info for
                        // are pushed to the pipe. It is simplifying the error handling process
                        // in sorting the pipe afterwards
                        let info = match unsafe { dec.info_mut() } {
                            Ok(info) => info,
                            Err(_) => {
                                error!("failed to decode info");
                                continue;
                            }
                        };

                        // we set the proper batch number
                        info.batch = ep.batch;

                        // pre-processing events
                        // we eventually change event type in this function
                        // example: Execve -> ExecveScript if necessary
                        // when the function returns true event doesn't need to go further
                        if ep.process_time_critical(&mut dec) {
                            continue;
                        }

                        // passing through some events directly to the consumer
                        // this is mostly usefull for correlation purposes
                        ep.pass_through_events(&dec).await;

                        // we must get the event type here because we eventually changed it
                        // info_unchecked can be used here as we are sure info is valid
                        let etype = unsafe { dec.info_unchecked() }.etype;

                        // filtering out unwanted events
                        if !ep.filter.is_enabled(etype) {
                            continue;
                        }

                        ep.pipe.push_back(dec);
                    }

                    // all threads wait here after some events have been collected
                    bar.wait().await;

                    // we increase batch number in one task only
                    if cpu_id == leader_cpu_id {
                        event_producer.lock().await.batch += 1;
                    }

                    // we break the loop if processor is stopped
                    if event_producer.lock().await.stop {
                        break;
                    }
                }

                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            });

            shared.lock().await.tasks.push(t);
        }

        shared
    }

    fn stop(&mut self) {
        self.stop = true
    }

    #[inline(always)]
    fn is_finished(&self) -> bool {
        self.tasks.iter().all(|t| t.is_finished())
    }

    async fn join(&mut self) -> anyhow::Result<()> {
        for t in self.tasks.iter_mut() {
            if t.is_finished() {
                t.await??;
            }
        }
        Ok(())
    }

    async fn arc_join(arc: &Arc<Mutex<Self>>, sleep: Duration) -> anyhow::Result<()> {
        loop {
            // drop lock  before sleep
            {
                if arc.lock().await.is_finished() {
                    break;
                }
            }
            time::sleep(sleep).await;
        }
        arc.lock().await.join().await
    }
}

const ABOUT_KUNAI: &str = r#"
     ▲
    / \    
   / | \   
  /  |  \   Kunai is a multi-purpose security monitoring tool for Linux systems.
 / _ | _ \ 
 \   |   /
  \  |  /  This software is licensed under the GNU General Public License version 3.0 (GPL-3.0).
   \   /   You are free to use, modify, and distribute this software under the terms of
    |-|    the GPL-3.0 license. For more details, please refer to the full text of the
    |\|    license at: https://www.gnu.org/licenses/gpl-3.0.html
    |\|
    |\|
    |-|
   /   \
   \___/"#;

#[derive(Parser)]
#[command(author, version, about = ABOUT_KUNAI, long_about = None)]
struct Cli {
    /// Enable debugging
    #[arg(short, long)]
    debug: bool,

    /// Silents out debug, info, error logging.
    #[arg(short, long)]
    silent: bool,

    /// Set verbosity level, repeat option for more verbosity.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Specify a kunai command (if any)
    #[clap(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Parser)]
struct ReplayOpt {
    /// Specify a configuration file to use. Command line options supersede the ones specified in the configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Detection/filtering rule file. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE")]
    rule_file: Option<Vec<String>>,

    /// File containing IoCs (json line).
    #[arg(short, long, value_name = "FILE")]
    ioc_file: Option<Vec<String>>,

    log_files: Vec<String>,
}

impl TryFrom<ReplayOpt> for Config {
    type Error = anyhow::Error;
    fn try_from(opt: ReplayOpt) -> Result<Self, Self::Error> {
        let mut conf = Self::default();

        if let Some(conf_file) = opt.config {
            conf = Self::from_toml(std::fs::read_to_string(conf_file)?)?;
        }

        // command line supersedes configuration

        // supersedes configuration
        if let Some(rules) = opt.rule_file {
            conf.rules = rules;
        }

        // supersedes configuration
        if let Some(iocs) = opt.ioc_file {
            conf.iocs = iocs;
        }

        Ok(conf)
    }
}

#[derive(Debug, Parser)]
struct RunOpt {
    /// Specify a configuration file to use. Command line options supersede the ones specified in the configuration file.
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,

    /// Number of worker threads used by kunai. By default kunai runs
    /// in a single threaded mode. If you want to use all available
    /// threads, set this option to 0.
    #[arg(short, long)]
    workers: Option<usize>,

    /// Harden Kunai at runtime by preventing process tampering attempts.
    /// If Kunai is run as a service, the only way to stop it may be
    /// to disable the service and then reboot the machine.
    #[arg(long)]
    harden: bool,

    /// Exclude events by name (comma separated).
    #[arg(long)]
    exclude: Option<String>,

    /// Include events by name (comma separated). Supersedes any exclude filter.
    #[arg(long)]
    include: Option<String>,

    /// Increase the size of the buffer shared between eBPF probes and userland.
    #[arg(long)]
    max_buffered_events: Option<u16>,

    /// Minimum amount of data sent to trigger a send_data event,
    /// set it to 0 to get all send_data events.
    #[arg(long)]
    send_data_min_len: Option<u64>,

    /// Detection/filtering rule file. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE")]
    rule_file: Option<Vec<String>>,

    /// File containing IoCs (json line).
    #[arg(short, long, value_name = "FILE")]
    ioc_file: Option<Vec<String>>,

    /// Yara rules dir/file. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE")]
    yara_rules: Option<Vec<String>>,
}

impl TryFrom<RunOpt> for Config {
    type Error = anyhow::Error;
    fn try_from(opt: RunOpt) -> Result<Self, Self::Error> {
        let mut conf = Self::default();

        if let Some(conf_file) = opt.config {
            conf = Self::from_toml(std::fs::read_to_string(conf_file)?)?;
        }

        // command line supersedes configuration
        if let Some(workers) = opt.workers {
            conf.workers = Some(workers);
        }

        // supersedes configuration
        if let Some(rules) = opt.rule_file {
            conf.rules = rules;
        }

        // supersedes configuration
        if let Some(iocs) = opt.ioc_file {
            conf.iocs = iocs;
        }

        // supersedes configuration
        if let Some(yara_rules) = opt.yara_rules {
            conf.yara = yara_rules;
        }

        // supersedes configuration if true
        if opt.harden {
            conf.harden = opt.harden
        }

        // we want to increase max_buffered_events
        if opt.max_buffered_events.is_some() {
            conf.max_buffered_events = opt.max_buffered_events.unwrap();
        }

        // we configure min len for send_data events
        conf.send_data_min_len = opt.send_data_min_len;

        // we exclude events
        if let Some(exclude) = opt.exclude {
            let exclude: Vec<&str> = exclude.split(',').collect();
            if exclude.iter().any(|&s| s == "all") {
                conf.disable_all()
            } else {
                for exc in exclude {
                    if let Some(e) = conf.events.iter_mut().find(|e| e.name() == exc) {
                        e.disable()
                    }
                }
            }
        }

        // we include events
        if let Some(include) = opt.include {
            let include: Vec<&str> = include.split(',').collect();
            if include.iter().any(|&s| s == "all") {
                conf.enable_all()
            } else {
                for inc in include {
                    if let Some(e) = conf.events.iter_mut().find(|e| e.name() == inc) {
                        e.enable()
                    }
                }
            }
        }
        Ok(conf)
    }
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run kunai with custom options
    Run(RunOpt),
    /// Replay logs into detection / filtering engine (useful to test rules and IoC based detection)
    Replay(ReplayOpt),
    /// Dump a default configuration
    Config,
    /// Show information about Kunai events
    Events,
}

const BPF_ELF: &[u8] = {
    #[cfg(debug_assertions)]
    let d = include_bytes_aligned!("../../../target/bpfel-unknown-none/debug/kunai-ebpf");
    #[cfg(not(debug_assertions))]
    let d = include_bytes_aligned!("../../../target/bpfel-unknown-none/release/kunai-ebpf");
    d
};

fn prepare_bpf(kernel: KernelVersion, conf: &Config, vll: VerifierLogLevel) -> anyhow::Result<Bpf> {
    let page_size = page_size()? as u64;
    let page_shift = page_shift()? as u64;

    let mut bpf = BpfLoader::new()
        .verifier_log_level(vll)
        .set_global("PAGE_SHIFT", &page_shift, true)
        .set_global("PAGE_SIZE", &page_size, true)
        .set_global("LINUX_KERNEL_VERSION", &kernel, true)
        .load(BPF_ELF)?;

    BpfConfig::init_config_in_bpf(&mut bpf, conf.clone().try_into()?)
        .expect("failed to initialize bpf configuration");

    Ok(bpf)
}

fn load_and_attach_bpf<'a>(
    conf: &'a Config,
    kernel: KernelVersion,
    bpf: &'a mut Bpf,
) -> anyhow::Result<Programs<'a>> {
    // make possible probe selection in debug
    #[allow(unused_mut)]
    let mut en_probes: Vec<String> = vec![];
    #[cfg(debug_assertions)]
    if let Ok(enable) = std::env::var("PROBES") {
        enable.split(',').for_each(|s| en_probes.push(s.into()));
    }

    // We need to parse eBPF ELF to extract section names
    let mut programs = Programs::with_bpf(bpf).with_elf_info(BPF_ELF)?;
    let btf = Btf::from_sys_fs()?;

    kunai::configure_probes(conf, &mut programs, kernel);

    // generic program loader
    for (_, p) in programs.sorted_by_prio() {
        // filtering probes to enable (only available in debug)
        if !en_probes.is_empty() && en_probes.iter().filter(|e| p.name.contains(*e)).count() == 0 {
            continue;
        }

        // we force enabling of selected probes
        // debug probes are disabled by default
        if !en_probes.is_empty() {
            p.enable();
        }

        if !p.enable {
            warn!("{} probe has been disabled", p.name);
            continue;
        }

        if !p.is_compatible(&kernel) {
            warn!(
                "{} probe is not compatible with current kernel: min={} max={} current={}",
                p.name,
                p.compat.min(),
                p.compat.max(),
                kernel
            );
            continue;
        }

        info!(
            "loading: {} {:?} with priority={}",
            p.name,
            p.prog_type(),
            p.prio
        );

        p.load_and_attach(&btf)?;
    }

    Ok(programs)
}

impl Command {
    fn replay(o: ReplayOpt) -> anyhow::Result<()> {
        let log_files = o.log_files.clone();
        let conf: Config = o.try_into()?;

        let mut p = EventConsumer::with_config(conf.stdout_output())?;
        for f in log_files {
            let f = {
                if f == "-" {
                    "/dev/stdin".into()
                } else {
                    f
                }
            };
            let reader = std::io::BufReader::new(fs::File::open(f)?);
            let mut de = serde_json::Deserializer::from_reader(reader);
            while let Ok(v) = serde_json::Value::deserialize(&mut de) {
                // we attempt at getting event name from json
                if let Some(name) = v
                    .get("info")
                    .and_then(|info| info.get("event"))
                    .and_then(|event| event.get("name"))
                    .and_then(|name| name.as_str())
                {
                    macro_rules! scan_event {
                        ($scanner:expr, $into:ty) => {{
                            let mut e: UserEvent<$into> = serde_json::from_value(v)?;
                            $scanner.scan_and_print(&mut e);
                        }};
                    }

                    let t = Type::from_str(name).map_err(|e| anyhow!("{e}"))?;

                    // exhaustive pattern matching so that we don't miss new events
                    match t {
                        Type::Execve | Type::ExecveScript => scan_event!(p, ExecveData),
                        Type::Clone => scan_event!(p, CloneData),
                        Type::Prctl => scan_event!(p, PrctlData),
                        Type::Kill => unimplemented!(),
                        Type::MmapExec => scan_event!(p, MmapExecData),
                        Type::MprotectExec => scan_event!(p, MprotectData),
                        Type::Connect => scan_event!(p, ConnectData),
                        Type::DnsQuery => scan_event!(p, DnsQueryData),
                        Type::SendData => scan_event!(p, SendDataData),
                        Type::InitModule => scan_event!(p, InitModuleData),
                        Type::WriteConfig
                        | Type::Write
                        | Type::ReadConfig
                        | Type::Read
                        | Type::WriteAndClose => {
                            scan_event!(p, FileData)
                        }
                        Type::FileUnlink => scan_event!(p, UnlinkData),
                        Type::FileRename => scan_event!(p, FileRenameData),
                        Type::BpfProgLoad => scan_event!(p, BpfProgLoadData),
                        Type::BpfSocketFilter => scan_event!(p, BpfSocketFilterData),
                        Type::Exit | Type::ExitGroup => scan_event!(p, ExitData),
                        Type::FileScan => scan_event!(p, FileScanData),

                        // types that shound never be seen in replay
                        Type::Unknown
                        | Type::CacheHash
                        | Type::Correlation
                        | Type::Error
                        | Type::EndConfigurable
                        | Type::TaskSched
                        | Type::SyscoreResume
                        | Type::Max => {}
                    }
                }
            }
        }

        Ok(())
    }

    fn run(opt_ro: Option<RunOpt>, vll: VerifierLogLevel) -> anyhow::Result<()> {
        // checking that we are running as root
        if get_current_uid() != 0 {
            return Err(anyhow::Error::msg(
                "You need to be root to run this program, this is necessary to load eBPF programs",
            ));
        }

        let current_kernel = Utsname::kernel_version()?;
        let conf: Config = match opt_ro {
            Some(ro) => ro.try_into()?,
            None => Config::default(),
        };

        // checks on harden mode
        if conf.harden {
            if current_kernel < kernel!(5, 7, 0) {
                return Err(anyhow!(
                    "harden mode is not supported for kernels below 5.7.0"
                ));
            }

            if current_kernel >= kernel!(5, 7, 0) && !is_bpf_lsm_enabled()? {
                return Err(anyhow!(
                    "trying to run in harden mode but BPF LSM is not enabled"
                ));
            }
        }

        // create the tokio runtime builder
        let mut builder = {
            match conf.workers {
                Some(workers) => {
                    let mut b = tokio::runtime::Builder::new_multi_thread();
                    // if number of workers is positive we set desired
                    // number of workers. If not tokio default will be
                    // taken (i.e. number of available threads).
                    if workers > 0 {
                        b.worker_threads(workers);
                    }
                    b
                }
                None => tokio::runtime::Builder::new_current_thread(),
            }
        };

        // creating tokio runtime
        let runtime = builder
            // the thread must drop CLONE_FS in order to be able to navigate in mnt namespaces
            .on_thread_start(|| unshare(libc::CLONE_FS).unwrap())
            .enable_all()
            .build()
            .unwrap();

        // we start event reader and event processor before loading the programs
        // if we load the programs first we might have some event lost errors
        let (sender, mut receiver) = mpsc::channel::<EncodedEvent>(512);

        // we start consumer
        let mut cons = EventConsumer::with_config(conf.clone())?;
        let mut cons_task = runtime.spawn(async move {
            #[cfg(debug_assertions)]
            let mut last_ts = 0;
            #[cfg(debug_assertions)]
            let mut hist = vec![];
            #[cfg(debug_assertions)]
            let mut last_batch = 0;

            while let Some(mut enc) = receiver.recv().await {
                // this is a debug_assertion testing that events arrive in
                // the order they were generated in eBPF. At this time
                // encoded event's timestamp is the one generated in eBPF
                #[cfg(debug_assertions)]
                {
                    let info = unsafe { enc.info_unchecked() };
                    // we skip correlation (passe through events)
                    if !matches!(info.etype, Type::CacheHash) {
                        let evt_ts = info.timestamp;
                        let batch = info.batch;
                        debug_assert!(
                            evt_ts >= last_ts,
                            "last={last_ts} (batch={last_batch}) > current={evt_ts} (batch={batch}"
                        );
                        // all historical ts must be smaller than current
                        debug_assert!(hist.iter().all(|&ts| ts <= evt_ts));
                        last_ts = evt_ts;
                        last_batch = batch;
                        // we insert at front so that we can truncate
                        hist.insert(0, evt_ts);
                        hist.truncate(30_000);
                    }
                };

                cons.handle_event(&mut enc);
            }

            Ok::<(), anyhow::Error>(())
        });

        runtime.block_on(async move {
            // we spawn a task to reload producer when needed
            let main = async move {
                loop {
                    info!("Starting event producer");
                    // we start producer
                    let mut bpf = prepare_bpf(current_kernel, &conf, vll)?;
                    let arc_prod =
                        EventProducer::with_params(&mut bpf, conf.clone(), sender.clone())?
                            .produce()
                            .await;

                    // we load and attach bpf programs
                    load_and_attach_bpf(&conf, current_kernel, &mut bpf)?;

                    loop {
                        // block make sure lock is dropped before sleeping
                        if arc_prod.lock().await.reload {
                            info!("Reloading event producer");
                            arc_prod.lock().await.stop();
                            // we wait for event producer to be ready
                            EventProducer::arc_join(&arc_prod, Duration::from_millis(500)).await?;

                            // we do not need to unload programs as this will be done at drop
                            break;
                        }

                        // we check if task spawned by consumer failed
                        // if yes we make it panic
                        let cons = &mut cons_task;
                        if let Ok(res) = timeout(Duration::from_nanos(1), cons).await {
                            res.unwrap().unwrap();
                        }

                        // we check if a task spawned by the producer failed
                        // if yes we make it panic
                        for t in arc_prod.lock().await.tasks.iter_mut() {
                            // we go really quick on awaiting as
                            // we just wanna know if the task failed
                            if let Ok(res) = timeout(Duration::from_nanos(1), t).await {
                                res.unwrap().unwrap();
                            }
                        }

                        time::sleep(Duration::from_millis(500)).await;
                    }
                }

                #[allow(unreachable_code)]
                Ok::<_, anyhow::Error>(())
            };

            info!("Waiting for Ctrl-C...");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => Ok(()),
                res = main => res
            }
        })
    }
}

fn main() -> Result<(), anyhow::Error> {
    let c = {
        let c: clap::Command = Cli::command();
        let styles = styling::Styles::styled()
            .header(styling::AnsiColor::Green.on_default() | styling::Effects::BOLD)
            .usage(styling::AnsiColor::Green.on_default() | styling::Effects::BOLD)
            .literal(styling::AnsiColor::Blue.on_default() | styling::Effects::BOLD)
            .placeholder(styling::AnsiColor::Cyan.on_default());

        c.styles(styles).help_template(
            r#"{about-with-newline}
{author-with-newline}
{usage-heading} {usage}

{all-args}"#,
        )
    };

    let cli: Cli = Cli::from_arg_matches(&c.get_matches())?;

    // Handling any CLI argument not needing to run eBPF
    // setting log level according to the verbosity level
    let mut log_level = LevelFilter::Warn;
    match cli.verbose {
        1 => log_level = LevelFilter::Info,
        2 => log_level = LevelFilter::Debug,
        3..=u8::MAX => log_level = LevelFilter::Trace,
        _ => {}
    }

    // silent out logging if specified in CLI
    if cli.silent {
        log_level = LevelFilter::Off;
    }

    let mut verifier_level = match std::env::var("VERIFIER_LOG_LEVEL") {
        Ok(s) => match s.as_str() {
            "debug" => VerifierLogLevel::DEBUG,
            "verbose" => VerifierLogLevel::VERBOSE,
            "disable" => VerifierLogLevel::DISABLE,
            _ => VerifierLogLevel::STATS,
        },
        _ => VerifierLogLevel::STATS,
    };

    // handling debugging flag
    if cli.debug {
        log_level = LevelFilter::Debug;
        verifier_level = VerifierLogLevel::DEBUG;
    }

    // building the logger
    Builder::new().filter_level(log_level).init();

    match cli.command {
        Some(Command::Events) => {
            for v in bpf_events::Type::variants() {
                if v.is_configurable() {
                    let pad = 25 - v.as_str().len();
                    println!("{}: {:>pad$}", v.as_str(), v as u32)
                }
            }
            Ok(())
        }
        Some(Command::Config) => {
            let mut conf = Config::default();
            conf.generate_host_uuid();
            println!("{}", conf.to_toml()?);
            Ok(())
        }
        Some(Command::Replay(o)) => Command::replay(o),
        Some(Command::Run(o)) => Command::run(Some(o), verifier_level),
        None => Command::run(None, verifier_level),
    }
}
