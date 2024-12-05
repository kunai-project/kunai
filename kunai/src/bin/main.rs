#![deny(unused_imports)]

use anyhow::anyhow;
use aya::maps::perf::Events;
use aya::maps::MapData;
use bytes::BytesMut;

use clap::builder::styling;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use env_logger::Builder;
use fs_walk::WalkOptions;
use gene::rules::MAX_SEVERITY;
use gene::{Compiler, Engine};
use huby::ByteSize;
use kunai::containers::Container;
use kunai::events::{
    BpfProgLoadData, BpfProgTypeInfo, BpfSocketFilterData, CloneData, ConnectData, DnsQueryData,
    EventInfo, ExecveData, ExitData, FileData, FileRenameData, FileScanData, FilterInfo,
    InitModuleData, KillData, KunaiEvent, MmapExecData, MprotectData, NetworkInfo, PrctlData,
    PtraceData, ScanResult, SendDataData, SockAddr, SocketInfo, TargetTask, TaskSection,
    UnlinkData, UserEvent,
};
use kunai::info::{AdditionalInfo, ProcKey, StdEventInfo, TaskAdditionalInfo};
use kunai::ioc::IoC;
use kunai::util::uname::Utsname;

use kunai::yara::{Scanner, SourceCode};
use kunai::{cache, util};
use kunai_common::bpf_events::{
    self, error, event, mut_event, EncodedEvent, Event, PrctlOption, Signal, TaskInfo, Type,
    MAX_BPF_EVENT_SIZE,
};
use kunai_common::config::Filter;
use kunai_common::{inspect_err, kernel};

use kunai_macros::StrEnum;
use log::LevelFilter;
use lru_st::collections::LruHashSet;
use namespace::{Mnt, Namespace};
use serde::{Deserialize, Serialize};

use tokio::sync::mpsc::error::SendError;
use tokio::time::timeout;

use std::borrow::Cow;
use std::cmp::max;
use std::collections::{HashMap, HashSet, VecDeque};

use std::fs::{self, DirBuilder, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use std::str::FromStr;

use std::sync::Arc;

use std::process;
use std::time::Duration;

use aya::{maps::perf::AsyncPerfEventArray, maps::HashMap as AyaHashMap, util::online_cpus, Ebpf};

use aya::VerifierLogLevel;

use log::{debug, error, info, warn};

use tokio::sync::{mpsc, Barrier, Mutex};
use tokio::{task, time};

use kunai::cache::*;

use kunai::config::{self, Config};
use kunai::util::namespace::unshare;
use kunai::util::*;

use communityid::{Flow, Protocol};

const PAGE_SIZE: usize = 4096;
const KERNEL_IMAGE: &str = "kernel";

#[derive(Debug, Clone)]
struct Process {
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
    // this is the key of the real parent process
    real_parent_key: Option<ProcKey>,
    // children processes
    children: HashSet<ProcKey>,
    // ebpf task info for this task
    kernel_task_info: Option<TaskInfo>,
    // flag telling if this task comes from procfs
    // parsing at kunai start
    procfs: bool,
    // exit state of the task
    exit: bool,
    // zombie state of the task
    zombie: bool,
}

impl Process {
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
    mount_ns: Mnt,
}

impl SystemInfo {
    fn from_sys() -> Result<Self, anyhow::Error> {
        let pid = process::id();
        Ok(SystemInfo {
            host_uuid: uuid::Uuid::from_u128(0),
            hostname: fs::read_to_string("/etc/hostname")?.trim_end().to_string(),
            mount_ns: Mnt::from_pid(pid)?,
        })
    }

    fn with_host_uuid(mut self, uuid: uuid::Uuid) -> Self {
        self.host_uuid = uuid;
        self
    }
}

enum Input {
    Stdin(std::io::Stdin),
    File(std::fs::File),
}

impl Input {
    fn from_file(f: fs::File) -> Self {
        Self::File(f)
    }

    fn from_stdin() -> Self {
        Self::Stdin(std::io::stdin())
    }
}

impl Read for Input {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Stdin(stdin) => stdin.read(buf),
            Self::File(f) => f.read(buf),
        }
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
enum Action {
    #[str("kill")]
    Kill,
    #[str("scan-files")]
    ScanFiles,
}

impl Action {
    fn description(&self) -> &'static str {
        match self {
            Action::Kill => "kill the process",
            Action::ScanFiles => {
                "scan any file path available in the event with all the Yara rules loaded"
            }
        }
    }
}

impl std::fmt::Display for Action {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

struct EventConsumer<'s> {
    system_info: SystemInfo,
    config: Config,
    filter: Filter,
    engine: gene::Engine,
    iocs: HashMap<String, u8>,
    random: u32,
    cache: cache::Cache,
    processes: HashMap<ProcKey, Process>,
    resolved: HashMap<IpAddr, String>,
    killed_tasks: LruHashSet<String>,
    exited_tasks: u64,
    output: Output,
    file_scanner: Option<Scanner<'s>>,
    // used to check if we must generate FileScan events
    scan_events_enabled: bool,
}

impl<'s> EventConsumer<'s> {
    fn prepare_output(config: &Config) -> anyhow::Result<Output> {
        let output = match &config.output.path.as_str() {
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

                let mut opts = firo::OpenOptions::new();

                opts.mode(0o600);

                if let Some(max_size) = config.output.max_size {
                    opts.max_size(max_size);
                }

                if let Some(rotate_size) = config.output.rotate_size {
                    opts.trigger(rotate_size.into());
                    opts.compression(firo::Compression::Gzip);
                }

                opts.create_append(v)?.into()
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
            .any(|(&ty, e)| ty == Type::FileScan && e.is_enabled());

        let output = Self::prepare_output(&config)?;

        let filter = Filter::try_from(&config)?;

        let mut ep = Self {
            system_info,
            config,
            filter,
            engine: Engine::new(),
            iocs: HashMap::new(),
            random: util::getrandom::<u32>().unwrap(),
            cache: Cache::with_max_entries(10000),
            processes: HashMap::with_capacity(512),
            killed_tasks: LruHashSet::with_max_entries(512),
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
        for p in self.config.scanner.yara.iter() {
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

    fn load_kunai_rule_file<P: AsRef<Path>>(
        &mut self,
        compiler: &mut Compiler,
        rule_file: P,
    ) -> anyhow::Result<()> {
        let rule_file = rule_file.as_ref();

        info!(
            "loading detection/filter rules from: {}",
            rule_file.to_string_lossy()
        );

        for document in serde_yaml::Deserializer::from_reader(File::open(rule_file)?) {
            // we deserialize into a value so that we can process string event ids
            let mut value = serde_yaml::Value::deserialize(document)?;

            // get rule name. We don't check here if there is a name as
            // later parsing is supposed to catch it.
            let rule_name = value
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or(String::from("unknown"));

            if let Some(events) = value
                .get_mut("match-on")
                .and_then(|mo| mo.get_mut("events"))
                .and_then(|e| e.get_mut("kunai"))
                .and_then(|events| events.as_sequence_mut())
            {
                for v in events.iter_mut() {
                    // we handle string event name
                    if let Some(event_name) = v.as_str() {
                        let id = if event_name.starts_with('-') {
                            let event_name = event_name.trim_start_matches('-');
                            let ty = Type::from_str(event_name)
                            .map_err(|_| {anyhow!("file={} rule={rule_name} parse error: unknown event name {event_name}",rule_file.to_string_lossy())})?;
                            -i64::from(ty as u32)
                        } else {
                            let ty = Type::from_str(event_name).map_err(|_| {
                                anyhow!("file={} rule={rule_name} parse error: unknown event name {event_name}",rule_file.to_string_lossy())
                            })?;
                            i64::from(ty as u32)
                        };

                        // we actually replace string by i64
                        *v = serde_yaml::Value::Number(id.into());
                    }
                }
            }

            // we insert rule into the engine
            compiler.load(gene::Rule::deserialize(value).map_err(|e| {
                anyhow!(
                    "file={} rule={rule_name} parse error: {e}",
                    rule_file.to_string_lossy()
                )
            })?)?;
        }

        Ok(())
    }

    fn compile_kunai_rules(&mut self) -> anyhow::Result<Compiler> {
        let mut compiler = Compiler::new();

        // loading rules in the engine
        if self.config.scanner.rules.is_empty() {
            return Ok(compiler);
        }

        let rules_wo = WalkOptions::new()
            // we list only files
            .files()
            // with following extensions
            .extension("kun")
            .extension("kunai")
            .extension("gen")
            .extension("gene")
            .sort(true)
            // don't go recursive
            .max_depth(0);

        let tpl_wo = WalkOptions::new()
            // we list only files
            .files()
            // with following extensions
            .extension("yaml")
            .extension("yml")
            .sort(true)
            // don't go recursive
            .max_depth(0);

        for p in self.config.scanner.rules.clone().iter().map(PathBuf::from) {
            if !p.exists() {
                error!(
                    "kunai rule loader: no such file or directory {}",
                    p.to_string_lossy()
                );
            } else if p.is_file() {
                // we load file regardless of its extension
                self.load_kunai_rule_file(&mut compiler, p)?;
            } else if p.is_dir() {
                // loading rule templates located in directory
                for t in tpl_wo.clone().walk(&p) {
                    let p = t?;
                    info!("loading template: {}", p.to_string_lossy());
                    let reader = File::open(p)?;
                    compiler.load_templates_from_reader(reader)?;
                }

                // load rule files
                for r in rules_wo.clone().walk(&p) {
                    self.load_kunai_rule_file(&mut compiler, r?)?;
                }
            }
        }

        Ok(compiler)
    }

    fn init_event_scanner(&mut self) -> anyhow::Result<()> {
        self.engine = Engine::try_from(self.compile_kunai_rules()?)?;
        info!("number of loaded rules: {}", self.engine.rules_count());
        Ok(())
    }

    fn init_iocs(&mut self) -> anyhow::Result<()> {
        // loading iocs
        if self.config.scanner.iocs.is_empty() {
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

        for p in self.config.scanner.iocs.clone().iter().map(PathBuf::from) {
            if !p.exists() {
                error!(
                    "ioc file loader: no such file or directory {}",
                    p.to_string_lossy()
                )
            } else if p.is_file() {
                self.load_iocs(&p)
                    .map_err(|e| anyhow!("failed to load IoC file {}: {e}", p.to_string_lossy()))?;
            } else if p.is_dir() {
                let w = wo.clone().walk(p);
                for r in w {
                    let f = r?;
                    self.load_iocs(&f).map_err(|e| {
                        anyhow!("failed to load IoC file {}: {e}", f.to_string_lossy())
                    })?;
                }
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
            .processes
            .iter()
            .map(|(&k, v)| (k, v.real_parent_key))
            .collect::<Vec<(ProcKey, Option<ProcKey>)>>()
        {
            if let Some(parent) = pk {
                if let Some(t) = self.processes.get_mut(&tk) {
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
                    self.processes
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
                Some(ProcKey::try_from(&parent)?)
            } else {
                None
            }
        };

        let tk = ProcKey::try_from(p)?;

        if self.processes.contains_key(&tk) {
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

        let task = Process {
            image,
            command_line: p.cmdline().unwrap_or(vec!["?".into()]),
            pid: p.pid,
            flags: stat.flags,
            resolved: HashMap::new(),
            container: None,
            cgroups,
            nodename: None,
            real_parent_key: parent_key,
            kernel_task_info: None,
            children: HashSet::new(),
            procfs: true,
            exit: false,
            zombie: false,
        };

        self.processes.insert(tk, task);

        Ok(())
    }

    #[inline(always)]
    fn get_exe(&self, key: ProcKey) -> PathBuf {
        let mut exe = PathBuf::from("?");
        if let Some(task) = self.processes.get(&key) {
            exe = task.image.clone();
        }
        exe
    }

    #[inline(always)]
    fn get_command_line(&self, key: ProcKey) -> String {
        let mut cl = String::from("?");
        if let Some(t) = self.processes.get(&key) {
            cl = t.command_line_string();
        }
        cl
    }

    #[inline(always)]
    fn get_exe_and_command_line(&self, i: &StdEventInfo) -> (PathBuf, String) {
        let ck = i.process_key();
        (self.get_exe(ck), self.get_command_line(ck))
    }

    /// get the list of ancestors given a [TaskKey]. If skip is 0 the last
    /// item is the image of the task referenced by `tk`. One can skip ancestors
    /// by setting `skip` > 0.
    #[inline(always)]
    fn get_ancestors(&self, mut tk: ProcKey, mut skip: u16) -> Vec<String> {
        let mut ancestors = vec![];
        let mut last = None;

        while let Some(task) = self.processes.get(&tk) {
            last = Some(task);
            if skip == 0 {
                ancestors.insert(0, task.image.to_string_lossy().to_string());
            } else {
                skip -= 1;
            }

            tk = match task.real_parent_key {
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

    #[inline(always)]
    fn get_ancestors_string(&self, i: &StdEventInfo) -> String {
        self.get_ancestors(i.process_key(), 1).join("|")
    }

    #[inline(always)]
    fn get_parent_image(&self, i: &StdEventInfo) -> String {
        let ck = i.process_key();
        self.processes
            .get(&ck)
            .and_then(|t| t.real_parent_key)
            .and_then(|ptk| self.processes.get(&ptk))
            .map(|c| c.image.to_string_lossy().to_string())
            .unwrap_or("?".into())
    }

    #[inline(always)]
    fn update_resolved(&mut self, ip: IpAddr, resolved: &str, i: &StdEventInfo) {
        let ck = i.process_key();

        // update local resolve table
        self.processes.get_mut(&ck).map(|c| {
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

    #[inline(always)]
    fn get_resolved(&self, ip: IpAddr, i: &StdEventInfo) -> Cow<'_, str> {
        let ck = i.process_key();

        // we lookup in the local table
        if let Some(domain) = self
            .processes
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

    #[inline(always)]
    fn get_hashes_in_ns(&mut self, ns: Option<Mnt>, p: &cache::Path) -> Hashes {
        if let Some(ns) = ns {
            match self.cache.get_hashes_in_ns(ns, p) {
                Ok(h) => h,
                Err(e) => {
                    let meta = FileMeta {
                        error: Some(format!("{e}")),
                        ..Default::default()
                    };
                    Hashes::with_meta(p.to_path_buf().clone(), meta)
                }
            }
        } else {
            let meta = FileMeta {
                error: Some("unknown namespace".into()),
                ..Default::default()
            };
            Hashes::with_meta(p.to_path_buf().clone(), meta)
        }
    }

    #[inline(always)]
    fn mnt_ns_from_task(ti: &bpf_events::TaskInfo) -> Option<Mnt> {
        ti.namespaces.map(|ns| Mnt::from_inum(ns.mnt))
    }

    #[inline(always)]
    /// method acting as a central place to get the mnt namespace of a
    /// parent task and printing out an error if not found
    fn task_mnt_ns(ei: &bpf_events::EventInfo) -> Option<Mnt> {
        match Self::mnt_ns_from_task(&ei.process) {
            Some(o) => Some(o),
            None => {
                debug!(
                    "no mnt namespace for event: type={} event_uuid={}",
                    ei.etype,
                    ei.uuid.into_uuid()
                );
                None
            }
        }
    }

    #[inline(always)]
    /// method acting as a central place to get the mnt namespace of a
    /// task and printing out an error if not found
    fn parent_mnt_ns(ei: &bpf_events::EventInfo) -> Option<Mnt> {
        match Self::mnt_ns_from_task(&ei.parent) {
            Some(o) => Some(o),
            None => {
                debug!(
                    "no mnt namespace for event: type={} event_uuid={}",
                    ei.etype,
                    ei.uuid.into_uuid()
                );
                None
            }
        }
    }

    #[inline(always)]
    fn execve_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::ExecveEvent,
    ) -> UserEvent<ExecveData> {
        let ancestors = self.get_ancestors_string(&info);
        let cli = self.get_command_line(info.process_key());

        let opt_mnt_ns = Self::task_mnt_ns(&event.info);

        let mut data = ExecveData {
            ancestors,
            parent_exe: self.get_parent_image(&info),
            command_line: cli,
            exe: self.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&event.data.executable)),
            interpreter: None,
        };

        if event.data.executable != event.data.interpreter {
            data.interpreter =
                Some(self.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&event.data.interpreter)))
        }

        UserEvent::new(data, info)
    }

    #[inline(always)]
    fn clone_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::CloneEvent,
    ) -> UserEvent<CloneData> {
        let data = CloneData {
            ancestors: self.get_ancestors_string(&info),
            exe: event.data.executable.to_path_buf().into(),
            command_line: self.get_command_line(info.process_key()),
            flags: event.data.flags,
        };
        UserEvent::new(data, info)
    }

    #[inline(always)]
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

    #[inline(always)]
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
        let tk = ProcKey::from(target.tg_uuid);

        let tai =
            Self::mnt_ns_from_task(&target).map(|ns| self.build_task_additional_info(ns, &target));

        let data = KillData {
            ancestors: self.get_ancestors_string(&info),
            exe: exe.into(),
            command_line,
            signal,
            target: TargetTask {
                command_line: self.get_command_line(tk),
                exe: self.get_exe(tk).into(),
                task: TaskSection::from_task_info_with_addition(target, tai.unwrap_or_default()),
            },
        };

        UserEvent::new(data, info)
    }

    #[inline(always)]
    fn ptrace_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::PtraceEvent,
    ) -> UserEvent<PtraceData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        // we need to set uuid part of target task
        let mut target = event.data.target;
        target.set_uuid_random(self.random);

        // get the command line
        let tk = ProcKey::from(target.tg_uuid);
        let tai =
            Self::mnt_ns_from_task(&target).map(|ns| self.build_task_additional_info(ns, &target));

        let data = PtraceData {
            ancestors: self.get_ancestors_string(&info),
            exe: exe.into(),
            command_line,
            mode: event.data.mode,
            target: TargetTask {
                command_line: self.get_command_line(tk),
                exe: self.get_exe(tk).into(),
                task: TaskSection::from_task_info_with_addition(target, tai.unwrap_or_default()),
            },
        };

        UserEvent::new(data, info)
    }

    #[inline(always)]
    fn mmap_exec_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::MmapExecEvent,
    ) -> UserEvent<kunai::events::MmapExecData> {
        let filename = event.data.filename;
        let opt_mnt_ns = Self::task_mnt_ns(&event.info);
        let mmapped_hashes = self.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&filename));

        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = kunai::events::MmapExecData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            mapped: mmapped_hashes,
        };

        UserEvent::new(data, info)
    }

    #[inline(always)]
    fn dns_query_events(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::DnsQueryEvent,
    ) -> Vec<UserEvent<DnsQueryData>> {
        let mut out = vec![];
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let src: SockAddr = event.data.src.into();
        let dst: SockAddr = event.data.dst.into();
        let si = SocketInfo::from(event.data.socket);

        let community_id = Flow::new(
            // this is valid to cast as a u8
            Protocol::from(event.data.socket.proto as u8),
            src.ip,
            src.port,
            dst.ip,
            dst.port,
        )
        .community_id_v1(0)
        .base64();

        let responses = event.data.answers().unwrap_or_default();
        let ancestors = self.get_ancestors_string(&info);

        for r in responses {
            let mut data = DnsQueryData::new().with_responses(r.answers);
            data.ancestors = ancestors.clone();
            data.command_line = command_line.clone();
            data.exe = exe.clone().into();
            data.query = r.question.clone();
            data.socket = si.clone();
            data.src = src;
            data.dns_server = NetworkInfo {
                hostname: None,
                ip: dst.ip,
                port: dst.port,
                public: is_public_ip(dst.ip),
                is_v6: dst.ip.is_ipv6(),
            };
            data.community_id = community_id.clone();

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

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
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
            socket: SocketInfo::from(event.data.socket_info),
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

    #[inline(always)]
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

    #[inline(always)]
    fn connect_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::ConnectEvent,
    ) -> UserEvent<ConnectData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);
        let src: SockAddr = event.data.src.into();
        let dst: SockAddr = event.data.dst.into();

        let flow: Flow = Flow::new(
            Protocol::from(event.data.socket.proto as u8),
            src.ip,
            src.port,
            dst.ip,
            dst.port,
        );

        let data = ConnectData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe: exe.into(),
            socket: SocketInfo::from(event.data.socket),
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

    #[inline(always)]
    fn send_data_event(
        &self,
        info: StdEventInfo,
        event: &bpf_events::SendEntropyEvent,
    ) -> UserEvent<SendDataData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);
        let dst: SockAddr = event.data.dst.into();
        let src: SockAddr = event.data.src.into();

        let flow = Flow::new(
            Protocol::from(event.data.socket.proto as u8),
            src.ip,
            src.port,
            dst.ip,
            dst.port,
        );

        let data = SendDataData {
            ancestors: self.get_ancestors_string(&info),
            exe: exe.into(),
            command_line,
            socket: SocketInfo::from(event.data.socket),
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

    #[inline(always)]
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

    #[inline(always)]
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

    #[inline(always)]
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
        if (matches!(etype, Type::Exit) && info.task_info().pid == info.task_info().tgid)
            || matches!(etype, Type::ExitGroup)
        {
            let pk = info.process_key();

            if let Some(t) = self.processes.get(&pk) {
                if !self.proc_has_running_descendent(&pk) && !t.procfs {
                    // if the task has no descendent and is not coming from procfs
                    // we can remove it from the table.
                    self.processes.remove(&pk);
                } else {
                    // the process has some running descendent, thus it needs to be
                    // kept in the table to construct a sound ancestors list for descendent(s).
                    // However we can free up some memory and tag the task as exited
                    self.processes.entry(pk).and_modify(|t| t.on_exit());
                }
            }

            // we trigger some very specific cleanup
            if self.exited_tasks % 1000 == 0 {
                let shadow_proc = self.find_shadow_procs();
                // we remove shadow processes
                self.processes.retain(|pk, _| !shadow_proc.contains(pk));
                // shrinking processes HashMap
                self.processes.shrink_to_fit();
            }

            self.exited_tasks = self.exited_tasks.wrapping_add(1);
        }

        UserEvent::new(data, info)
    }

    // shadow processes are processes still in the hashmap but which have exited and
    // have all descendents exited. They are not useful anymore because they are not needed
    // to reconstruct ancestors.
    #[inline(always)]
    fn find_shadow_procs(&self) -> HashSet<ProcKey> {
        let mut no_running_desc = HashSet::with_capacity(self.processes.len());

        for pk in self
            .processes
            .iter()
            // we don't process collected from procfs
            .filter(|(_, p)| !p.procfs)
            // we don't want running processes
            .filter(|(_, p)| p.exit)
            .map(|(k, _)| *k)
        {
            // if our parent has no running descendent we know we do too
            if let Some(rpk) = self
                .processes
                .get(&pk)
                .and_then(|p| p.real_parent_key)
                .as_ref()
            {
                if no_running_desc.contains(rpk) {
                    no_running_desc.insert(pk);
                    continue;
                }
            }

            if !self.proc_has_running_descendent(&pk) {
                no_running_desc.insert(pk);
            }
        }

        no_running_desc
    }

    #[inline(always)]
    fn proc_has_running_descendent(&self, pk: &ProcKey) -> bool {
        if let Some(p) = self.processes.get(pk) {
            for ck in p.children.iter() {
                if let Some(child) = self.processes.get(ck) {
                    // if we have one child that didn't exit
                    if !child.exit {
                        return true;
                    }

                    // if one descendent of our childen is running
                    if self.proc_has_running_descendent(ck) {
                        return true;
                    }
                }
            }
        }
        false
    }

    #[inline(always)]
    fn handle_correlation_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::CorrelationEvent,
    ) {
        let pk = info.process_key();
        let mut parent_key = info.parent_key();
        let execve_flag = matches!(event.data.origin, Type::Execve | Type::ExecveScript);

        // Execve must remove any previous task (i.e. coming from
        // clone or tasksched for instance)
        if execve_flag {
            if let Some(p) = self.processes.get(&pk).and_then(|p| p.real_parent_key) {
                // we keep track of real parent_key in case of zombie task
                parent_key = p;
            }
            // we start from scratch with this process
            self.processes.remove(&pk);
        }

        // early return if task key exists
        if let Some(v) = self.processes.get_mut(&pk) {
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
                    procfs::process::Process::new(info.task_info().pid).and_then(|p| p.cgroups())
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
                        info.task_info().pid,
                        info.task_info().tg_uuid.into_uuid().hyphenated()
                    );
                    // still get a chance to do something with cgroup
                    vec![cgroup.to_string()]
                }
            }
        };

        let mut container_type = Container::from_cgroups(&cgroups);

        if container_type.is_none() {
            let ancestors = self.get_ancestors(parent_key, 0);
            container_type = Container::from_ancestors(&ancestors);
        }

        let image = {
            if info.task_info().is_kernel_thread() {
                KERNEL_IMAGE.into()
            } else {
                event.data.exe.to_path_buf()
            }
        };

        // we update parent's information
        // we track children processes, not tasks
        self.processes.entry(parent_key).and_modify(|e| {
            e.children.insert(info.process_key());
        });

        // we insert only if not existing
        self.processes.entry(pk).or_insert(Process {
            image,
            command_line: event.data.argv.to_argv(),
            pid: info.task_info().tgid,
            flags: info.task_info().flags,
            resolved: HashMap::new(),
            container: container_type,
            cgroups,
            nodename: event.data.nodename(),
            real_parent_key: Some(parent_key),
            kernel_task_info: Some(*info.task_info()),
            children: HashSet::new(),
            procfs: false,
            exit: false,
            zombie: false,
        });
    }

    #[inline(always)]
    fn handle_hash_event(&mut self, info: StdEventInfo, event: &bpf_events::HashEvent) {
        let opt_mnt_ns = Self::task_mnt_ns(&info.bpf);
        self.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&event.data.path));
    }

    #[inline(always)]
    fn track_zombie_task(&mut self, std_info: &mut StdEventInfo) {
        // we need to find if task is a zombie and replace
        // its parent with the real one if needed
        if let Some(kti) = self
            .processes
            .get_mut(&std_info.process_key())
            .and_then(|t| {
                if t.zombie
                    || (t.real_parent_key.is_some()
                        && t.real_parent_key != Some(std_info.parent_key()))
                {
                    // task is a zombie
                    t.zombie = true;
                    // we must continue with the real parent task key
                    t.real_parent_key
                } else {
                    None
                }
            })
            // we get real parent
            .and_then(|tk| self.processes.get(&tk))
            // we get real parent's TaskInfo
            .and_then(|t| t.kernel_task_info)
        {
            // if we arrive here, this means the task is a zombie
            // and we need to replace its parent by the real one
            std_info.bpf.parent = kti;
            std_info.bpf.process.zombie = true
        }

        // we must set the zombie flag of the parent if needed
        if self
            .processes
            .get(&std_info.parent_key())
            .map(|t| t.zombie)
            .unwrap_or_default()
        {
            std_info.bpf.parent.zombie = true
        }
    }

    #[inline(always)]
    fn build_task_additional_info(
        &mut self,
        mnt_ns: Mnt,
        ti: &bpf_events::TaskInfo,
    ) -> TaskAdditionalInfo {
        // getting user and group information for task
        let (user, group) = self
            .cache
            .get_user_group_in_ns(mnt_ns, &ti.uid, &ti.gid)
            .inspect_err(|e| {
                if !e.is_unknown_ns() {
                    error!("failed to get task user: {e}")
                }
            })
            .unwrap_or_default();

        TaskAdditionalInfo::new(user.cloned(), group.cloned())
    }

    #[inline(always)]
    fn build_std_event_info(&mut self, i: bpf_events::EventInfo) -> StdEventInfo {
        let opt_mnt_ns = Self::task_mnt_ns(&i);
        let opt_parent_ns = Self::parent_mnt_ns(&i);

        let mut std_info = StdEventInfo::from_bpf(i, self.random);

        let host = kunai::info::HostInfo {
            name: self.system_info.hostname.clone(),
            uuid: self.system_info.host_uuid,
        };

        let mut container = None;
        let mut task = None;
        let mut parent = None;

        if let Some(mnt_ns) = opt_mnt_ns {
            if mnt_ns != self.system_info.mount_ns {
                let t = self.processes.get(&std_info.process_key());
                container = Some(kunai::info::ContainerInfo {
                    name: t.and_then(|t| t.nodename.clone()).unwrap_or("?".into()),
                    ty: t.and_then(|cd| cd.container),
                });
            }
            // getting task additional info
            task = Some(self.build_task_additional_info(mnt_ns, &i.process));
        }

        // getting user and group information for parent task
        if let Some(parent_ns) = opt_parent_ns {
            parent = Some(self.build_task_additional_info(parent_ns, &i.parent));
        }

        self.track_zombie_task(&mut std_info);

        std_info.with_additional_info(AdditionalInfo {
            host,
            container,
            task: task.unwrap_or_default(),
            parent: parent.unwrap_or_default(),
        })
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

        // no need to scan for IoC if not necessary
        if !self.iocs.is_empty() {
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
            if actions.contains(Action::Kill.as_str()) {
                let pid = event.info().task.pid;
                let guuid = &event.info().task.guuid;
                // don't kill ourself: this check is redundant because kunai
                // events aren't supposed to arrive until here but it is a cheap test
                if pid as u32 != process::id() && !self.killed_tasks.contains(guuid) {
                    // this is the kind of information we want to have
                    // at all time so we put this as a warning not to
                    // be disabled by the default logging policy
                    warn!("sending SIGKILL to PID={pid}");
                    if let Err(e) = kill(pid, libc::SIGKILL) {
                        error!("error sending SIGKILL to PID={pid}: {e}")
                    } else {
                        self.killed_tasks.insert(guuid.clone());
                    }
                }
            }
        }

        // if action contains scan-file and if scan events are enabled
        if self.scan_events_enabled && actions.contains(Action::ScanFiles.as_str()) {
            let _ = self
                .action_scan_files(event)
                .inspect_err(|e| error!("{} action failed: {e}", Action::ScanFiles));
        }
    }

    #[inline(always)]
    fn file_scan_event<T: Serialize + KunaiEvent>(
        &mut self,
        event: &T,
        ns: Mnt,
        p: &Path,
    ) -> UserEvent<FileScanData> {
        // if the scanner is None, signatures will be an empty Vec
        let (sigs, err) = match self.file_scanner.as_mut() {
            Some(s) => match self
                .cache
                .get_sig_in_ns(ns, &cache::Path::from(p.to_path_buf()), s)
            {
                Ok(sigs) => (sigs, None),
                Err(e) => (vec![], Some(format!("{e}"))),
            },
            None => (vec![], None),
        };

        let pos = sigs.len();
        let mut data = FileScanData::from_hashes(
            self.get_hashes_in_ns(Some(ns), &cache::Path::from(p.to_path_buf())),
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
            Some(ns) => Mnt::from_inum(ns.mnt),
            None => return Err(anyhow!("namespace not found")),
        };

        for p in event
            .scannable_files()
            .iter()
            // we don't scan file paths being ?
            .filter(|&p| p != &PathBuf::from("?").into())
        {
            let mut event = self.file_scan_event(event, ns, p);
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

            // - we can force printing positive scans even if there is no filtering rule for it
            // - an attempt to print the event if there is an error was made but it generates
            // noisy events. A better way to handle scan errors is to create a filtering rule
            if !got_printed
                && self.config.scanner.show_positive_file_scan
                && event.data.positives > 0
            {
                match serde_json::to_string(&event) {
                    Ok(ser) => writeln!(self.output, "{ser}").expect("failed to write json event"),
                    Err(e) => error!("failed to serialize event to json: {e}"),
                }
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn serialize_print<T: Serialize + KunaiEvent>(&mut self, event: &mut T) -> bool {
        match serde_json::to_string(event) {
            Ok(ser) => {
                writeln!(self.output, "{ser}").expect("failed to write json event");
                // if output is unbuffered we flush it
                // unbuffered output allow to have logs written in near
                // real-time into output file
                if !self.config.output.buffered {
                    self.output.flush().expect("failed to flush output");
                }
                return true;
            }
            Err(e) => error!("failed to serialize event to json: {e}"),
        }
        false
    }

    #[inline(always)]
    fn scan_and_print<T: Serialize + KunaiEvent>(&mut self, event: &mut T) -> bool {
        let mut printed = false;

        // default: we have neither rules nor iocs
        // to scan for so we print event
        if self.iocs.is_empty() && self.engine.is_empty() {
            return self.serialize_print(event);
        }

        // scan for iocs and filter/matching rules
        if let Some(sr) = self.scan(event) {
            if sr.is_detection() {
                let severity = sr.severity;
                event.set_detection(sr);

                // we print event only if needed
                printed = if severity >= self.config.scanner.min_severity {
                    self.serialize_print(event)
                } else {
                    false
                };

                // get_detection will always be false for filters
                if let Some(sr) = event.get_detection() {
                    self.handle_actions(event, &sr.actions, true);
                }
            } else if sr.is_only_filter() {
                printed = self.serialize_print(event);
                self.handle_actions(event, &sr.actions, false);
            }
        }

        printed
    }

    #[inline(always)]
    fn cache_namespaces(&mut self, i: &bpf_events::EventInfo) {
        if let Some(t_mnt_ns) = Self::task_mnt_ns(i) {
            let pid = i.process.pid;
            if let Err(e) = self.cache.cache_mnt_ns(pid, t_mnt_ns) {
                debug!("failed to cache namespace pid={pid} ns={t_mnt_ns}: {e}");
            }
        }

        if let Some(p_mnt_ns) = Self::parent_mnt_ns(i) {
            let pid = i.parent.pid;
            if let Err(e) = self.cache.cache_mnt_ns(pid, p_mnt_ns) {
                debug!("failed to cache namespace pid={pid} ns={p_mnt_ns}: {e}");
            }
        }
    }

    #[inline(always)]
    fn handle_event(&mut self, enc_event: &mut EncodedEvent) {
        let i = unsafe { enc_event.info() }.unwrap();

        // we don't handle our own events
        if i.process.tgid as u32 == std::process::id() {
            debug!("skipping our event");
        }

        let etype = i.etype;

        self.cache_namespaces(i);

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

                        if self.filter.is_enabled(std_info.bpf.etype) {
                            // we have to rebuild std_info as it has it is uses correlation
                            // information
                            let std_info = self.build_std_event_info(std_info.bpf);
                            let mut e = self.execve_event(std_info, e);

                            self.scan_and_print(&mut e);
                        }
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

                    // we let clone event go in EventProducer not to break correlation
                    if self.filter.is_enabled(Type::Clone) {
                        // we have to rebuild std_info as it has it is uses correlation
                        // information
                        let std_info = self.build_std_event_info(std_info.bpf);
                        let mut e = self.clone_event(std_info, e);
                        self.scan_and_print(&mut e);
                    }
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

            Type::Ptrace => match event!(enc_event, bpf_events::PtraceEvent) {
                Ok(e) => {
                    let mut e = self.ptrace_event(std_info, e);
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
            | Type::WriteClose
            | Type::FileCreate => match event!(enc_event, bpf_events::FileEvent) {
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
                    let ty = std_info.bpf.etype;
                    let mut e = self.exit_event(std_info, e);
                    // exit and exit_group will always reach consumer as they are used
                    // to clean up the processes HashMap. So we need to check if we want
                    // to display those only now.
                    if self.filter.is_enabled(ty) {
                        self.scan_and_print(&mut e);
                    }
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
        bpf: &mut Ebpf,
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

    #[inline(always)]
    async fn send_event<T>(&self, event: Event<T>) -> Result<(), SendError<EncodedEvent>> {
        self.sender.send(EncodedEvent::from_event(event)).await
    }

    /// function used to pre-process some targetted events where time is critical and for which
    /// processing can be done in EventReader
    /// this function must return true if main processing loop has to pass to the next event
    /// after the call.
    #[inline(always)]
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
    #[inline(always)]
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

                        // verify that we filter properly kunai events in eBPF
                        debug_assert!(
                            info.process.pid as u32 != process::id(),
                            "kunai event should not reach userland"
                        );

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

                        // filtering out unwanted events but let Excve/Clone go as those are used
                        // for correlation on consumer side.
                        if ep.filter.is_disabled(etype)
                            && !matches!(
                                etype,
                                Type::Execve
                                    | Type::ExecveScript
                                    | Type::Clone
                                    // exit and exit_group are used to cleanup hashmap
                                    | Type::Exit
                                    | Type::ExitGroup
                            )
                        {
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

    /// Benchmark scanning engine
    #[arg(long)]
    bench: bool,

    /// Detection/filtering rule file. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE")]
    rule_file: Option<Vec<String>>,

    /// File containing IoCs (json line).
    #[arg(short, long, value_name = "FILE")]
    ioc_file: Option<Vec<String>>,

    /// Minimal severity required to show detection
    #[arg(long, short = 's')]
    min_severity: Option<u8>,

    log_files: Vec<String>,
}

impl TryFrom<ReplayOpt> for Config {
    type Error = anyhow::Error;
    fn try_from(opt: ReplayOpt) -> Result<Self, Self::Error> {
        let mut conf = Self::default();

        if let Some(conf_file) = opt.config {
            conf = serde_yaml::from_str(&std::fs::read_to_string(conf_file)?)?;
        }

        // command line supersedes configuration

        // supersedes configuration
        if let Some(rules) = opt.rule_file {
            conf.scanner.rules = rules;
        }

        // supersedes configuration
        if let Some(iocs) = opt.ioc_file {
            conf.scanner.iocs = iocs;
        }

        // supersedes configuration
        if let Some(min_severity) = opt.min_severity {
            conf.scanner.min_severity = min_severity;
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

    /// Minimal severity required to show detection
    #[arg(long)]
    min_severity: Option<u8>,
}

impl TryFrom<RunOpt> for Config {
    type Error = anyhow::Error;
    fn try_from(opt: RunOpt) -> Result<Self, Self::Error> {
        let mut conf = Self::default();

        if let Some(conf_file) = opt.config {
            conf = serde_yaml::from_str(&std::fs::read_to_string(conf_file)?)?;
        }

        // command line supersedes configuration
        if let Some(workers) = opt.workers {
            conf.workers = Some(workers);
        }

        // supersedes configuration
        if let Some(rules) = opt.rule_file {
            conf.scanner.rules = rules;
        }

        // supersedes configuration
        if let Some(iocs) = opt.ioc_file {
            conf.scanner.iocs = iocs;
        }

        // supersedes configuration
        if let Some(yara_rules) = opt.yara_rules {
            conf.scanner.yara = yara_rules;
        }

        // supersedes configuration if true
        if opt.harden {
            conf.harden = opt.harden
        }

        // we want to increase max_buffered_events
        if let Some(max_buffered_events) = opt.max_buffered_events {
            conf.max_buffered_events = max_buffered_events;
        }

        // supersedes configuration
        if let Some(min_severity) = opt.min_severity {
            conf.scanner.min_severity = min_severity
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
                    if let Some((_, e)) = conf.events.iter_mut().find(|(ty, _)| ty.as_str() == exc)
                    {
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
                    if let Some((_, e)) = conf.events.iter_mut().find(|(ty, _)| ty.as_str() == inc)
                    {
                        e.enable()
                    }
                }
            }
        }
        Ok(conf)
    }
}

#[derive(Debug, Args)]
struct ConfigOpt {
    /// Dump a default configuration on the terminal
    #[arg(long, exclusive = true)]
    dump: bool,

    /// List the available remediation actions supported
    #[arg(long, exclusive = true)]
    list_actions: bool,

    /// List available events
    #[arg(long, exclusive = true)]
    list_events: bool,
}

#[derive(Debug, Args)]
struct InstallOpt {
    /// Install in harden mode. First verify that
    /// /sys/kernel/security/lsm contains bpf
    #[arg(long)]
    harden: bool,

    /// Set a custom installation directory
    #[arg(long, default_value_t = String::from("/usr/bin/"))]
    install_dir: String,

    /// Log file where kunai logs will be written
    #[arg(long, default_value_t = String::from("/var/log/kunai/events.log"))]
    log_file: String,

    /// Where to write the configuration file. Any intermediate directory
    /// will be created if needed.
    #[arg(long, default_value_t = String::from("/etc/kunai/config.yaml"))]
    config: String,

    /// Make a systemd unit installation
    #[arg(long)]
    systemd: bool,

    /// Install a systemd unit but do not enable it
    #[arg(short, long = "systemd-unit", default_value_t = String::from("/lib/systemd/system/00-kunai.service"))]
    unit: String,

    /// Enable Kunai unit (kunai will start at boot)
    #[arg(long)]
    enable_unit: bool,
}

#[derive(Debug, Args)]
struct LogsOpt {
    /// Path to the configuration file
    #[arg(short, long, default_value_t = String::from("/etc/kunai/config.yaml"))]
    config: String,

    /// Path to the log file to open. The path must point to the plain-text
    /// log file, not to one of the archives.
    #[arg(short, long, conflicts_with = "config")]
    log_file: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Install Kunai on the system
    Install(InstallOpt),
    /// Run kunai with custom options
    Run(RunOpt),
    /// Replay logs into detection / filtering engine (useful to test rules and IoC based detection)
    Replay(ReplayOpt),
    /// Dump a default configuration
    Config(ConfigOpt),
    /// Easy way to show Kunai logs. This will work only with a configuration file and with an output
    /// file being configured.
    Logs(LogsOpt),
}

fn time_it<F: FnMut()>(mut f: F) -> Duration {
    let start_time = std::time::Instant::now();
    f();
    let end_time = std::time::Instant::now();
    end_time - start_time
}

impl Command {
    fn replay(o: ReplayOpt) -> anyhow::Result<()> {
        let bench = o.bench;
        let log_files = o.log_files.clone();
        let conf: Config = o.try_into()?;
        let mut kunai_scan_time = Duration::new(0, 0);
        let mut data_size = ByteSize::from_bytes(0);

        let mut p = EventConsumer::with_config(conf.stdout_output())?;
        for f in log_files {
            let reader = if f == "-" {
                std::io::BufReader::new(Input::from_stdin())
            } else {
                std::io::BufReader::new(Input::from_file(fs::File::open(f)?))
            };

            let mut de = serde_json::Deserializer::from_reader(reader);

            while let Ok(v) = serde_json::Value::deserialize(&mut de) {
                // we need to know the size of the data we scan to compute throughput
                if bench {
                    data_size += ByteSize::from_bytes(serde_json::to_string(&v)?.len() as u64);
                }

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
                            if bench {
                                kunai_scan_time += time_it(|| {
                                    let _ = $scanner.scan(&mut e);
                                });
                            } else {
                                $scanner.scan_and_print(&mut e);
                            }
                        }};
                    }

                    let t = Type::from_str(name).map_err(|e| anyhow!("{e}"))?;

                    // exhaustive pattern matching so that we don't miss new events
                    match t {
                        Type::Execve | Type::ExecveScript => scan_event!(p, ExecveData),
                        Type::Clone => scan_event!(p, CloneData),
                        Type::Prctl => scan_event!(p, PrctlData),
                        Type::Kill => scan_event!(p, KillData),
                        Type::Ptrace => scan_event!(p, PtraceData),
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
                        | Type::WriteClose
                        | Type::FileCreate => {
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

        if bench {
            let throughput = ByteSize::from_bytes(
                (data_size.in_bytes() as f64 / kunai_scan_time.as_secs_f64()) as u64,
            );
            println!("scan duration: {kunai_scan_time:?}");
            println!("scan throughput: {throughput}/s");
        }

        Ok(())
    }

    fn inner_run(opt_ro: Option<RunOpt>, vll: VerifierLogLevel) -> anyhow::Result<()> {
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
                    let mut bpf = kunai::prepare_bpf(current_kernel, &conf, vll)?;
                    let arc_prod =
                        EventProducer::with_params(&mut bpf, conf.clone(), sender.clone())?
                            .produce()
                            .await;

                    // we load and attach bpf programs
                    kunai::load_and_attach_bpf(&conf, current_kernel, &mut bpf)?;

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

    fn run(opt_ro: Option<RunOpt>, vll: VerifierLogLevel) -> anyhow::Result<()> {
        // checking that we are running as root
        if get_current_uid() != 0 {
            return Err(anyhow::Error::msg(
                "You need to be root to run this program, this is necessary to load eBPF programs",
            ));
        }

        let run_dir = PathBuf::from("/run/kunai");
        let pid_file = run_dir.join("kunai.pid");

        // we prevent the service manager to restart kunai when in harden mode
        if !run_dir.exists() {
            let _ = DirBuilder::new()
                .mode(0o700)
                .create(&run_dir)
                .inspect_err(|e| {
                    warn!(
                        "failed to create run dir {}: {e}",
                        run_dir.to_string_lossy()
                    )
                });
        }

        // we read pid from file
        if let Some(pid) = fs::read_to_string(&pid_file)
            .ok()
            .and_then(|s| s.parse::<i32>().ok())
        {
            // the pid still exists
            if kill(pid, 0).is_ok() {
                warn!("An instance of Kunai pid={pid} is already running");
                return Ok(());
            }
        }

        // we write pid to file
        let _ = fs::OpenOptions::new()
            .mode(0o700)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&pid_file)
            .and_then(|mut f| f.write(process::id().to_string().as_bytes()))
            .inspect_err(|e| warn!("failed to write pid file: {e}"));

        let res = Self::inner_run(opt_ro, vll);
        let _ = fs::remove_file(&pid_file).inspect_err(|e| warn!("failed to delete pid file: {e}"));
        res
    }

    fn config(co: ConfigOpt) -> anyhow::Result<()> {
        if co.dump {
            let conf = Config::default().generate_host_uuid();
            println!("{}", serde_yaml::to_string(&conf)?);
            return Ok(());
        }

        if co.list_actions {
            for a in Action::variants() {
                let pad = 12usize.saturating_sub(a.as_str().len());
                println!("{a}: {:<pad$}{}", " ", a.description());
            }
            return Ok(());
        }

        if co.list_events {
            for v in bpf_events::Type::variants() {
                if v.is_configurable() {
                    let pad = 25usize.saturating_sub(v.as_str().len());
                    println!("{v}: {:>pad$}", v as u32)
                }
            }
            return Ok(());
        }

        Ok(())
    }

    fn run_command(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
        let output = process::Command::new(cmd).args(args).output()?;

        if !output.status.success() {
            std::io::stdout().write_all(&output.stderr)?;
            std::io::stderr().write_all(&output.stderr)?;
            return Err(anyhow::format_err!("systemctl daemon-reload failed"));
        }

        Ok(())
    }

    fn systemd_install(
        co: &InstallOpt,
        install_bin: &Path,
        config_path: &Path,
    ) -> anyhow::Result<()> {
        // we proceed with systemd installation
        let unit_path = PathBuf::from(&co.unit);
        let unit = format!(
            r#"[Unit]
Description=Kunai Service
            
# Documentation
Documentation=https://why.kunai.rocks
Documentation=https://github.com/kunai-project/kunai
            
# This is needed to start before sysinit.target
DefaultDependencies=no
Before=sysinit.target
After=local-fs.target
After=systemd-journald-audit.socket
# If harden mode is configured, set this to true to
# prevent systemd attempting to stop kunai, which would
# fail.
RefuseManualStop={harden}
            
[Service]
Type=exec
ExecStart={install_bin} run -c {config_path}
StandardOutput=journal
StandardError=journal
            
[Install]
Alias=kunai.service
WantedBy=sysinit.target"#,
            harden = co.harden,
            install_bin = install_bin.to_string_lossy(),
            config_path = config_path.to_string_lossy(),
        );

        println!(
            "Writing systemd unit file to: {}",
            unit_path.to_string_lossy()
        );
        fs::write(&unit_path, unit)?;

        // we want to enable systemd unit
        if co.enable_unit {
            let unit_name = unit_path
                .file_name()
                .ok_or(anyhow!(
                    "unknown unit name: {}",
                    unit_path.to_string_lossy()
                ))?
                .to_string_lossy();
            println!("Enabling kunai systemd unit");
            // we first need to run daemon-reload because we added a new unit
            Self::run_command("systemctl", &["daemon-reload"])?;
            // then we can enable the unit
            Self::run_command("systemctl", &["enable", &unit_name])?;
        }

        Ok(())
    }

    fn install(co: InstallOpt) -> anyhow::Result<()> {
        let current_kernel = Utsname::kernel_version()
            .map_err(|e| anyhow!("cannot retrieve kernel version: {e}"))?;
        let log_path = PathBuf::from(&co.log_file);
        let log_dir = log_path.parent().ok_or(anyhow!(
            "cannot find dirname for log path: {}",
            log_path.to_string_lossy()
        ))?;

        // checks on harden mode
        if co.harden {
            if current_kernel < kernel!(5, 7, 0) {
                return Err(anyhow!(
                    "harden mode is not supported for kernels below 5.7.0"
                ));
            }

            if current_kernel >= kernel!(5, 7, 0) && !is_bpf_lsm_enabled()? {
                return Err(anyhow!(
                    "trying to install in harden mode but BPF LSM is not enabled"
                ));
            }
        }

        // we create the directory where to store logs
        println!("Creating log directory: {}", log_dir.to_string_lossy());
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(log_dir)?;

        let config_path = PathBuf::from(&co.config);
        let config_dir = config_path.parent().ok_or(anyhow!(
            "cannot find dirname for config path: {}",
            config_path.to_string_lossy()
        ))?;
        println!(
            "Creating configuration directory: {}",
            config_dir.to_string_lossy()
        );
        // we create the directory where to store configuration
        fs::create_dir_all(config_dir)?;

        // create configuration for installation
        let conf = Config::default()
            .harden(co.harden)
            .generate_host_uuid()
            .output(config::Output {
                path: log_path.to_string_lossy().to_string(),
                rotate_size: Some(huby::ByteSize::from_mb(10)),
                max_size: Some(huby::ByteSize::from_gb(1)),
                buffered: false,
            });
        println!(
            "Writing configuration file: {}",
            config_path.to_string_lossy()
        );
        // we write configuration file
        fs::write(&config_path, serde_yaml::to_string(&conf)?)?;

        // we read our own binary
        let self_bin = fs::read("/proc/self/exe")?;
        let install_bin = PathBuf::from(&co.install_dir).join("kunai");
        println!("Writing kunai binary to: {}", install_bin.to_string_lossy());
        // we write kunai bin
        fs::write(&install_bin, self_bin)?;

        // setting file permission
        let mode = fs::metadata(&install_bin)?.permissions().mode() & 0o000777;

        println!(
            "Setting file permission: chmod +x {}",
            install_bin.to_string_lossy()
        );
        // make the binary executable
        fs::set_permissions(&install_bin, PermissionsExt::from_mode(mode | 0o111))?;

        if !co.systemd {
            return Ok(());
        }

        Self::systemd_install(&co, &install_bin, &config_path)
    }

    fn logs(o: LogsOpt) -> anyhow::Result<()> {
        let output = if o.log_file.is_none() {
            let config: Config = serde_yaml::from_reader(
                File::open(o.config).map_err(|e| anyhow!("failed to read config file: {e}"))?,
            )
            .map_err(|e| anyhow!("failed to parse config file: {e}"))?;

            PathBuf::from(config.output.path)
        } else {
            // cannot panic as it is Some
            o.log_file.unwrap()
        };

        if !output.is_file() {
            return Err(anyhow!(
                "kunai output={} is not a regular file",
                output.to_string_lossy()
            ));
        }

        // for the time being kunai does not allow specifying custom
        // log storage options so we can fix them
        let fd = firo::OpenOptions::new()
            .compression(firo::Compression::Gzip)
            .open(&output)?;

        let reader = BufReader::new(fd);

        for line in reader.lines() {
            let line = line.map_err(|e| anyhow!("failed to read log file:{e}"))?;

            // depending how the service got stopped some null
            // bytes may appear in stop / start transition
            let line = line.trim_matches('\0');

            println!("{line}",);
        }

        Ok(())
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
        Some(Command::Install(o)) => Command::install(o),
        Some(Command::Config(o)) => Command::config(o),
        Some(Command::Replay(o)) => Command::replay(o),
        Some(Command::Logs(o)) => Command::logs(o),
        Some(Command::Run(o)) => Command::run(Some(o), verifier_level),
        None => Command::run(None, verifier_level),
    }
}
