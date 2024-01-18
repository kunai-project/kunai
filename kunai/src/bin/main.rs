use anyhow::anyhow;
use aya::maps::MapData;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Builder;
use gene::rules::MAX_SEVERITY;
use gene::Engine;
use kunai::containers::Container;
use kunai::events::{
    BpfProgLoadData, BpfProgTypeInfo, BpfSocketFilterData, CloneData, ConnectData, DnsQueryData,
    ExecveData, ExitData, FileRenameData, FilterInfo, InitModuleData, KunaiEvent, MountData,
    MprotectData, NetworkInfo, PrctlData, RWData, ScanResult, SendDataData, SocketInfo, UnlinkData,
    UserEvent,
};
use kunai::info::{AdditionalInfo, CorrInfo, ProcFsInfo, ProcFsTaskInfo, StdEventInfo};
use kunai::ioc::IoC;
use kunai::{cache, util};
use kunai_common::bpf_events::{
    self, event, mut_event, EncodedEvent, Event, PrctlOption, Type, MAX_BPF_EVENT_SIZE,
};
use kunai_common::config::{BpfConfig, Filter};
use kunai_common::inspect_err;

use log::LevelFilter;
use serde::Serialize;

use std::borrow::Cow;
use std::collections::{HashMap, HashSet, VecDeque};

use std::fs::{self, File};
use std::io::{self, BufRead, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use std::sync::mpsc::{channel, Receiver, SendError, Sender};
use std::sync::Arc;

use std::{process, thread};

use aya::{
    include_bytes_aligned,
    maps::perf::{AsyncPerfEventArray, Events, PerfBufferError},
    maps::HashMap as AyaHashMap,
    util::online_cpus,
    Bpf, Btf,
};
#[allow(unused_imports)]
use aya::{BpfLoader, VerifierLogLevel};
use aya_log::BpfLogger;

use log::{debug, error, info, warn};

use tokio::sync::{Barrier, Mutex};
use tokio::{signal, task, time};

use kunai::cache::*;

use kunai::compat::{KernelVersion, Programs};
use kunai::config::Config;
use kunai::util::namespaces::{unshare, Namespace};
use kunai::util::*;

const PAGE_SIZE: usize = 4096;
const KERNEL_IMAGE: &'static str = "kernel";

#[derive(Debug, Clone)]
struct CorrelationData {
    image: PathBuf,
    command_line: Vec<String>,
    // process flags PF_* defined in sched.h
    flags: u32,
    resolved: HashMap<IpAddr, String>,
    container: Option<Container>,
    info: CorrInfo,
}

impl CorrelationData {
    #[inline(always)]
    fn is_kthread(&self) -> bool {
        // check if flag contains PF_KTHREAD
        self.flags & 0x00200000 == 0x00200000
    }

    #[inline(always)]
    fn command_line_string(&self) -> String {
        self.command_line.join(" ")
    }

    fn free_memory(&mut self) {
        self.resolved = HashMap::new();
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

struct EventProcessor {
    system_info: SystemInfo,
    engine: gene::Engine,
    iocs: HashSet<String>,
    random: u32,
    cache: cache::Cache,
    receiver: Receiver<EncodedEvent>,
    correlations: HashMap<u128, CorrelationData>,
    resolved: HashMap<IpAddr, String>,
    output: std::fs::File,
}

impl EventProcessor {
    pub fn init(config: Config, receiver: Receiver<EncodedEvent>) -> anyhow::Result<()> {
        let output = match &config.output.as_str() {
            &"stdout" => String::from("/dev/stdout"),
            &"stderr" => String::from("/dev/stderr"),
            v => v.to_string(),
        };

        // building up system information
        let system_info = SystemInfo::from_sys()?.with_host_uuid(
            config
                .host_uuid()
                .ok_or(anyhow!("failed to read host_uuid"))?,
        );

        let mut ep = Self {
            system_info,
            engine: Engine::new(),
            iocs: HashSet::new(),
            random: util::getrandom::<u32>().unwrap(),
            cache: Cache::with_max_entries(10000),
            correlations: HashMap::new(),
            resolved: HashMap::new(),
            receiver,
            output: std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(output)?,
        };

        // loading rules in the engine
        if !config.rules.is_empty() {
            for rule in config.rules.iter() {
                info!("loading detection/filter rules from: {rule}");
                ep.engine
                    .load_rules_yaml_reader(File::open(rule)?)
                    .map_err(|e| anyhow!("failed to load file {rule}: {e}"))?;
            }
            info!("number of loaded rules: {}", ep.engine.rules_count());
        }

        // loading iocs
        if !config.iocs.is_empty() {
            for file in config.iocs.clone() {
                ep.load_iocs(file.to_string())
                    .map_err(|e| anyhow!("failed to load IoC file: {e}"))?;
            }
            info!("number of IoCs loaded: {}", ep.iocs.len());
        }

        config
            .host_uuid()
            .ok_or(anyhow!("failed to read host_uuid"))?;

        // should not raise any error, we just print it
        inspect_err! {
            ep.init_correlations_from_procfs(),
            |e: anyhow::Error| warn!("failed to initialize correlations with procfs: {}", e)
        };

        thread::spawn(move || {
            // the thread must drop CLONE_FS in order to be able to navigate in namespaces
            unshare(libc::CLONE_FS).unwrap();
            while let Ok(mut enc) = ep.receiver.recv() {
                ep.handle_event(&mut enc);
            }
        });

        Ok(())
    }

    fn load_iocs<P: AsRef<Path>>(&mut self, p: P) -> io::Result<()> {
        let p = p.as_ref();
        let f = io::BufReader::new(File::open(p)?);

        for line in f.lines() {
            let line = line?;
            let ioc: IoC = serde_json::from_str(&line)?;
            self.iocs.insert(ioc.value);
        }

        Ok(())
    }

    fn init_correlations_from_procfs(&mut self) -> anyhow::Result<()> {
        for p in (procfs::process::all_processes()?).flatten() {
            // flatten takes only the Ok() values of processes
            if let Err(e) = self.set_correlation_from_procfs(&p) {
                warn!(
                    "failed to initialize correlation for procfs process PID={}: {e}",
                    p.pid
                )
            }
        }
        Ok(())
    }

    fn set_correlation_from_procfs(&mut self, p: &procfs::process::Process) -> anyhow::Result<()> {
        let mut ppi: Option<ProcFsTaskInfo> = None;

        let stat = p.stat()?;
        let pi = ProcFsTaskInfo::new(stat.starttime, self.random, p.pid);

        let parent_pid = p.status()?.ppid;

        if parent_pid != 0 {
            let parent = procfs::process::Process::new(parent_pid)?;

            ppi = Some(ProcFsTaskInfo::new(
                parent.stat()?.starttime,
                self.random,
                parent_pid,
            ));
        }

        let ci = CorrInfo::from(ProcFsInfo::new(pi, ppi));

        let ck = ci.correlation_key();

        if self.correlations.contains_key(&ck) {
            return Ok(());
        }

        let image = {
            if stat.flags & 0x200000 == 0x200000 {
                KERNEL_IMAGE.into()
            } else {
                p.exe().unwrap_or("?".into())
            }
        };

        let cor = CorrelationData {
            image: image,
            command_line: p.cmdline().unwrap_or(vec!["?".into()]),
            flags: stat.flags,
            resolved: HashMap::new(),
            container: None,
            info: ci,
        };

        self.correlations.insert(ck, cor);

        Ok(())
    }

    #[inline]
    fn get_exe(&self, key: u128) -> PathBuf {
        let mut exe = PathBuf::from("?");
        if let Some(corr) = self.correlations.get(&key) {
            exe = corr.image.clone();
        }
        exe
    }

    #[inline]
    fn get_command_line(&self, key: u128) -> String {
        let mut cl = String::from("?");
        if let Some(corr) = self.correlations.get(&key) {
            cl = corr.command_line_string();
        }
        cl
    }

    #[inline]
    fn get_exe_and_command_line(&self, i: &StdEventInfo) -> (PathBuf, String) {
        let ck = i.correlation_key();
        (self.get_exe(ck), self.get_command_line(ck))
    }

    #[inline]
    fn get_ancestors(&self, i: &StdEventInfo) -> Vec<String> {
        let mut ck = i.parent_correlation_key();
        let mut ancestors = vec![];
        let mut last = None;

        while let Some(cor) = self.correlations.get(&ck) {
            last = Some(cor);
            ancestors.insert(0, cor.image.to_string_lossy().to_string());
            ck = match cor.info.parent_correlation_key() {
                Some(v) => v,
                None => break,
            };
        }

        if let Some(last) = last {
            if last.info.pid() != 1 && !last.is_kthread() {
                ancestors.insert(0, "?".into());
            }
        }

        ancestors
    }

    #[inline]
    fn get_ancestors_string(&self, i: &StdEventInfo) -> String {
        self.get_ancestors(i).join("|")
    }

    #[inline]
    fn get_parent_image(&self, i: &StdEventInfo) -> String {
        let ck = i.parent_correlation_key();
        self.correlations
            .get(&ck)
            .map(|c| c.image.to_string_lossy().to_string())
            .unwrap_or("?".into())
    }

    #[inline]
    fn update_resolved(&mut self, ip: IpAddr, resolved: &str, i: &StdEventInfo) {
        let ck = i.correlation_key();

        // update local resolve table
        self.correlations.get_mut(&ck).map(|c| {
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
        let ck = i.correlation_key();

        // we lookup in the local table
        if let Some(domain) = self
            .correlations
            .get(&ck)
            .map(|c| c.resolved.get(&ip).map(|s| Cow::from(s)))
            .flatten()
        {
            return domain.into();
        }

        // we lookup in the global table
        if let Some(domain) = self.resolved.get(&ip) {
            return domain.into();
        }

        // default value
        "?".into()
    }

    #[inline]
    fn get_hashes_with_ns(&mut self, ns: Namespace, p: &kunai_common::path::Path) -> Hashes {
        match self.cache.get_or_cache_in_ns(ns, p) {
            Ok(h) => h,
            Err(e) => Hashes {
                file: p.to_path_buf(),
                error: Some(format!("{e}")),
                ..Default::default()
            },
        }
    }

    #[inline]
    fn to_execve(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::ExecveEvent,
    ) -> UserEvent<ExecveData> {
        let ancestors = self.get_ancestors(&info);

        let mnt_ns = Namespace::mnt(event.info.process.namespaces.mnt);

        let mut data = ExecveData {
            ancestors: ancestors.join("|"),
            parent_exe: self.get_parent_image(&info),
            command_line: event.data.argv.to_command_line(),
            exe: self.get_hashes_with_ns(mnt_ns, &event.data.executable),
            interpreter: None,
        };

        if event.data.executable != event.data.interpreter {
            data.interpreter = Some(self.get_hashes_with_ns(mnt_ns, &event.data.interpreter))
        }

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_clone(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::CloneEvent,
    ) -> UserEvent<CloneData> {
        let data = CloneData {
            exe: event.data.executable.to_path_buf(),
            command_line: event.data.argv.to_command_line(),
            flags: event.data.flags,
        };
        UserEvent::new(data, info)
    }

    #[inline]
    fn to_prctl(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::PrctlEvent,
    ) -> UserEvent<PrctlData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let option = PrctlOption::try_from_uint(event.data.option)
            .and_then(|o| Ok(o.as_str().into()))
            .unwrap_or(format!("unknown({})", event.data.option))
            .to_string();

        let data = PrctlData {
            exe,
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
    fn to_mmap_exec(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::MmapExecEvent,
    ) -> UserEvent<kunai::events::MmapExecData> {
        let filename = event.data.filename;
        let mnt_ns = Namespace::mnt(event.info.process.namespaces.mnt);
        let mmapped_hashes = self.get_hashes_with_ns(mnt_ns, &filename);

        let ck = info.correlation_key();

        let exe = self.get_exe(ck);

        let data = kunai::events::MmapExecData {
            command_line: self.get_command_line(ck),
            exe: exe,
            mapped: mmapped_hashes,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_dns_queries(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::DnsQueryEvent,
    ) -> Vec<UserEvent<DnsQueryData>> {
        let mut out = vec![];
        let ck = info.correlation_key();
        let exe = self.get_exe(ck);
        let command_line = self.get_command_line(ck);

        let serv_ip: IpAddr = event.data.ip_port.into();
        let serv_port = event.data.ip_port.port();

        let proto = match event.data.proto {
            1 => "tcp".into(),
            2 => "udp".into(),
            _ => format!("unknown({})", event.data.proto),
        };

        debug!(
            "packet data len={}: {:?}",
            event.data.data.len(),
            event.data.packet_data()
        );

        let responses = event.data.answers().unwrap_or_default();

        for r in responses {
            let mut data = DnsQueryData::new().with_responses(r.answers);
            data.command_line = command_line.clone();
            data.exe = exe.clone();
            data.query = r.question.clone();
            data.proto = proto.clone().into();
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
    fn to_rw(&mut self, info: StdEventInfo, event: &bpf_events::ConfigEvent) -> UserEvent<RWData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = RWData {
            command_line,
            exe,
            path: event.data.path.to_path_buf(),
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_unlink(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::UnlinkEvent,
    ) -> UserEvent<UnlinkData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = UnlinkData {
            command_line,
            exe,
            path: event.data.path.into(),
            success: event.data.success,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_mount(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::MountEvent,
    ) -> UserEvent<MountData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = MountData {
            command_line,
            exe,
            dev_name: event.data.dev_name.into(),
            path: event.data.path.into(),
            ty: event.data.ty.into(),
            success: event.data.rc == 0,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_bpf_prog_load(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::BpfProgLoadEvent,
    ) -> UserEvent<BpfProgLoadData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let mut data = BpfProgLoadData {
            command_line,
            exe,
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
    fn to_bpf_socket_filter(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::BpfSocketFilterEvent,
    ) -> UserEvent<BpfSocketFilterData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = BpfSocketFilterData {
            command_line,
            exe,
            socket: SocketInfo {
                domain: event.data.socket_info.domain_to_string(),
                ty: event.data.socket_info.type_to_string().into(),
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
    fn to_mprotect(
        &self,
        info: StdEventInfo,
        event: &bpf_events::MprotectEvent,
    ) -> UserEvent<MprotectData> {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let data = MprotectData {
            command_line: cmd_line,
            exe: exe,
            addr: event.data.start,
            prot: event.data.prot,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_connect(
        &self,
        info: StdEventInfo,
        event: &bpf_events::ConnectEvent,
    ) -> UserEvent<ConnectData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);
        let dst_ip: IpAddr = event.data.ip_port.into();

        let data = ConnectData {
            command_line,
            exe,
            dst: NetworkInfo {
                hostname: Some(self.get_resolved(dst_ip, &info).into()),
                ip: dst_ip,
                port: event.data.ip_port.port(),
                public: is_public_ip(dst_ip),
                is_v6: event.data.ip_port.is_v6(),
            },
            connected: event.data.connected,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_send_data(
        &self,
        info: StdEventInfo,
        event: &bpf_events::SendEntropyEvent,
    ) -> UserEvent<SendDataData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);
        let dst_ip: IpAddr = event.data.ip_port.into();

        let data = SendDataData {
            exe,
            command_line,
            dst: NetworkInfo {
                hostname: Some(self.get_resolved(dst_ip, &info).into()),
                ip: dst_ip,
                port: event.data.ip_port.port(),
                public: is_public_ip(dst_ip),
                is_v6: event.data.ip_port.is_v6(),
            },
            data_entropy: event.shannon_entropy(),
            data_size: event.data.real_data_size,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_init_module(
        &self,
        info: StdEventInfo,
        event: &bpf_events::InitModuleEvent,
    ) -> UserEvent<InitModuleData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = InitModuleData {
            ancestors: self.get_ancestors_string(&info),
            command_line,
            exe,
            module_name: event.data.name.to_string(),
            args: event.data.uargs.to_string(),
            userspace_addr: event.data.umod,
            loaded: event.data.loaded,
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_file_rename(
        &self,
        info: StdEventInfo,
        event: &bpf_events::FileRenameEvent,
    ) -> UserEvent<FileRenameData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = FileRenameData {
            command_line,
            exe,
            old: event.data.old_name.into(),
            new: event.data.new_name.into(),
        };

        UserEvent::new(data, info)
    }

    #[inline]
    fn to_exit(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::ExitEvent,
    ) -> UserEvent<ExitData> {
        let (exe, command_line) = self.get_exe_and_command_line(&info);

        let data = ExitData {
            command_line,
            exe,
            error_code: event.data.error_code,
        };

        let etype = event.ty();
        // cleanup correlations when process exits
        if (matches!(etype, Type::Exit) && info.info.process.pid == info.info.process.tgid)
            || matches!(etype, Type::ExitGroup)
        {
            // find a more elaborated way to save space
            // we need to keep some minimal correlations
            // maybe through cached ancestors and parent_image
            self.correlations
                .entry(info.correlation_key())
                .and_modify(|c| c.free_memory());
        }

        UserEvent::new(data, info)
    }

    #[inline]
    fn handle_correlation_event(
        &mut self,
        info: StdEventInfo,
        event: &bpf_events::CorrelationEvent,
    ) {
        let ck = info.correlation_key();

        // Execve must remove any previous correlation (i.e. coming from
        // clone or tasksched for instance)
        if matches!(event.data.origin, Type::Execve | Type::ExecveScript) {
            self.correlations.remove(&ck);
        }

        // early return if correlation key exists
        if self.correlations.contains_key(&ck) {
            return;
        }

        let cgroup = event.data.cgroup;

        let mut container_type = Container::from_cgroup(&cgroup);

        if container_type.is_none() {
            let ancestors = self.get_ancestors(&info);
            container_type = Container::from_ancestors(ancestors);
        }

        let image = {
            if info.info.process.is_kernel_thread() {
                KERNEL_IMAGE.into()
            } else {
                event.data.exe.to_path_buf()
            }
        };

        // we insert only if not existing
        self.correlations.entry(ck).or_insert(CorrelationData {
            image,
            command_line: event.data.argv.to_argv(),
            flags: info.info.process.flags,
            resolved: HashMap::new(),
            container: container_type,
            info: CorrInfo::Event(info),
        });
    }

    #[inline]
    fn handle_hash_event(&mut self, info: StdEventInfo, event: &bpf_events::HashEvent) {
        let mnt_ns = Namespace::mnt(info.info.process.namespaces.mnt);
        self.get_hashes_with_ns(mnt_ns, &event.data.path);
    }

    fn build_std_event_info(&mut self, i: bpf_events::EventInfo) -> StdEventInfo {
        let mnt_ns = Namespace::mnt(i.process.namespaces.mnt);

        let std_info = StdEventInfo::from_bpf(i, self.random);

        let cd = self.correlations.get(&std_info.correlation_key());

        let host = kunai::info::HostInfo {
            name: self.system_info.hostname.clone(),
            uuid: self.system_info.host_uuid,
        };

        let mut container = None;

        if mnt_ns != self.system_info.mount_ns {
            container = Some(kunai::info::ContainerInfo {
                name: self.cache.get_hostname(mnt_ns).unwrap_or("?".into()),
                ty: cd.and_then(|cd| cd.container),
            });
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
            .filter_map(|ioc| {
                if self.iocs.contains(&ioc.to_string()) {
                    return Some(ioc);
                }
                None
            })
            .map(|ioc| ioc.to_string())
            .collect::<HashSet<String>>();

        if !matching_iocs.is_empty() {
            // we create a new ScanResult if necessary
            if scan_result.is_none() {
                scan_result = Some(ScanResult::default());
            }

            // we add ioc matching to the list of matching rules
            scan_result.as_mut().map(|sr| {
                sr.iocs = matching_iocs;
                // if we match an ioc we consider the event is of
                // the higher severity
                sr.severity = MAX_SEVERITY;
            });
        }

        scan_result
    }

    #[inline(always)]
    fn scan_and_print<T: Serialize + KunaiEvent>(&mut self, event: &mut T) {
        macro_rules! serialize {
            ($event:expr) => {
                match serde_json::to_string($event) {
                    Ok(ser) => writeln!(self.output, "{ser}").expect("failed to write json event"),
                    Err(e) => error!("failed to serialize event to json: {e}"),
                }
            };
        }

        // we have neither rules nor iocs to inspect for
        if self.iocs.is_empty() && self.engine.is_empty() {
            serialize!(event);
            return;
        }

        // scan for iocs and filter/matching rules
        if let Some(sr) = self.scan(event) {
            if sr.is_detection() {
                event.set_detection(sr);
                serialize!(event);
            } else if sr.is_only_filter() {
                serialize!(event);
            }
        }
    }

    fn handle_event(&mut self, enc_event: &mut EncodedEvent) {
        let i = unsafe { enc_event.info() }.unwrap();

        // we don't handle our own events
        if i.process.tgid as u32 == std::process::id() {
            debug!("skipping our event");
        }

        let pid = i.process.tgid;
        let ns = Namespace::mnt(i.process.namespaces.mnt);

        if let Err(e) = self.cache.cache_ns(pid, ns) {
            debug!("failed to cache namespace pid={pid} ns={ns}: {e}");
        }

        let std_info = self.build_std_event_info(*i);

        let etype = std_info.info.etype;

        match etype {
            Type::Unknown => {
                error!("Unknown event type: {}", etype as u64)
            }
            Type::Max | Type::EndEvents | Type::TaskSched => {}
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
                        let std_info = self.build_std_event_info(*i);
                        let mut e = self.to_execve(std_info, e);

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
                    let std_info = self.build_std_event_info(*i);
                    let mut e = self.to_clone(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Prctl => match event!(enc_event, bpf_events::PrctlEvent) {
                Ok(e) => {
                    let mut e = self.to_prctl(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::MmapExec => match event!(enc_event, bpf_events::MmapExecEvent) {
                Ok(e) => {
                    let mut e = self.to_mmap_exec(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::MprotectExec => match event!(enc_event, bpf_events::MprotectEvent) {
                Ok(e) => {
                    let mut e = self.to_mprotect(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Connect => match event!(enc_event, bpf_events::ConnectEvent) {
                Ok(e) => {
                    let mut e = self.to_connect(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::DnsQuery => match event!(enc_event, bpf_events::DnsQueryEvent) {
                Ok(e) => {
                    for e in self.to_dns_queries(std_info, e).iter_mut() {
                        self.scan_and_print(e);
                    }
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::SendData => match event!(enc_event, bpf_events::SendEntropyEvent) {
                Ok(e) => {
                    let mut e = self.to_send_data(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::InitModule => match event!(enc_event, bpf_events::InitModuleEvent) {
                Ok(e) => {
                    let mut e = self.to_init_module(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::WriteConfig | Type::Write | Type::ReadConfig | Type::Read => {
                match event!(enc_event, bpf_events::ConfigEvent) {
                    Ok(e) => {
                        let mut e = self.to_rw(std_info, e);
                        self.scan_and_print(&mut e);
                    }
                    Err(e) => error!("failed to decode {} event: {:?}", etype, e),
                }
            }

            Type::FileUnlink => match event!(enc_event, bpf_events::UnlinkEvent) {
                Ok(e) => {
                    let mut e = self.to_unlink(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Mount => match event!(enc_event, bpf_events::MountEvent) {
                Ok(e) => {
                    let mut e = self.to_mount(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::FileRename => match event!(enc_event, bpf_events::FileRenameEvent) {
                Ok(e) => {
                    let mut e = self.to_file_rename(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::BpfProgLoad => match event!(enc_event, bpf_events::BpfProgLoadEvent) {
                Ok(e) => {
                    let mut e = self.to_bpf_prog_load(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::BpfSocketFilter => match event!(enc_event, bpf_events::BpfSocketFilterEvent) {
                Ok(e) => {
                    let mut e = self.to_bpf_socket_filter(std_info, e);
                    self.scan_and_print(&mut e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            Type::Exit | Type::ExitGroup => match event!(enc_event, bpf_events::ExitEvent) {
                Ok(e) => {
                    let mut e = self.to_exit(std_info, e);
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
        }
    }
}

struct EventReader {
    batch: usize,
    pipe: VecDeque<EncodedEvent>,
    sender: Sender<EncodedEvent>,
    filter: Filter,
    stats: AyaHashMap<MapData, Type, u64>,
}

#[inline(always)]
fn optimal_page_count(page_size: usize, max_event_size: usize, n_events: usize) -> usize {
    let c = (max_event_size * n_events) / page_size;
    2usize.pow(c.ilog2() + 1)
}

impl EventReader {
    pub fn init(
        bpf: &mut Bpf,
        config: Config,
        sender: Sender<EncodedEvent>,
    ) -> anyhow::Result<Arc<Mutex<Self>>> {
        let filter = (&config).try_into()?;
        let stats_map: AyaHashMap<_, Type, u64> =
            AyaHashMap::try_from(bpf.take_map(bpf_events::KUNAI_STATS_MAP).unwrap()).unwrap();

        let ep = EventReader {
            pipe: VecDeque::new(),
            batch: 0,
            sender,
            filter,
            stats: stats_map,
        };

        let safe = Arc::new(Mutex::new(ep));
        Self::read_events(&safe, bpf, &config);
        Ok(safe)
    }

    #[inline(always)]
    fn has_pending_events(&self) -> bool {
        !self.pipe.is_empty()
    }

    // Event ordering is a very important piece as it impacts on-host correlations.
    // Additionaly it is very useful as it guarantees events are printed/piped into
    // other tools in the damn good order.
    //
    // Ordering correctness relies on two factors
    // 1. the pace (controlled by timeout) at which we read buffers must be
    //    greater than the slowest probe we have. This means that on a period of TWO
    //    timeouts we are sure to have all events to reconstruct at least ONE (the oldest) batch.
    // 2. we process only one batch of events at a time (always the oldest first). If
    //    only one batch is available we don't do anything because we will need it to
    //    reconstruct next batch.
    #[inline(always)]
    async fn process_piped_events(&mut self) {
        // nothing to do
        if self.pipe.is_empty() {
            return;
        }

        // we sort events out by timestamp
        // this should never fail because we pushed only
        // events for which info can be decoded
        self.pipe
            .make_contiguous()
            .sort_unstable_by_key(|enc_evt| unsafe {
                enc_evt
                    .info()
                    .expect("info should never fail here")
                    .timestamp
            });

        // we find the last event corresponding to previous batch
        // if we cannot find one it means all events are of the current batch
        // so we should not process any event (satisfies condition 2)
        let index_first = self
            .pipe
            .iter()
            .enumerate()
            .rev()
            .find(|(_, e)| {
                unsafe { e.info() }
                    .expect("info should never fail here")
                    .batch
                    != self.batch
            })
            .map(|(i, _)| i)
            .unwrap_or_default();

        // converts index into a counter
        let mut counter = index_first + 1;

        // processing count piped events, we need to pop front as events
        // are sorted ascending by timestamp
        while counter > 0 {
            // at this point pop_front cannot fail as count takes account of the elements in the pipe
            let enc_evt = self
                .pipe
                .pop_front()
                .expect("pop_front should never fail here");

            // send event to event processor
            self.sender.send(enc_evt).unwrap();

            counter -= 1;
        }
    }

    #[inline]
    fn send_event<T>(&self, event: Event<T>) -> Result<(), SendError<EncodedEvent>> {
        self.sender.send(EncodedEvent::from_event(event))
    }

    /// function used to pre-process some targetted events where time is critical and for which
    /// processing can be done in EventReader
    #[inline]
    fn pre_process_events(&self, e: &mut EncodedEvent) {
        let i = unsafe { e.info() }.expect("info should not fail here");

        #[allow(clippy::single_match)]
        match i.etype {
            Type::Execve => {
                let mut event = mut_event!(e, bpf_events::ExecveEvent).unwrap();
                if event.data.interpreter != event.data.executable {
                    event.info.etype = Type::ExecveScript
                }
            }
            Type::BpfProgLoad => {
                let mut event = mut_event!(e, bpf_events::BpfProgLoadEvent).unwrap();

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
                        error!("failed to retrieve bpf_prog instructions: {:?}", e)
                    }
                }
            }
            _ => {}
        }
    }

    /// this method pass through some events directly to the event processor
    /// only events that can be processed asynchronously should be passed through
    fn pass_through_events(&self, e: &EncodedEvent) {
        let i = unsafe { e.info() }.unwrap();

        match i.etype {
            Type::Execve | Type::ExecveScript => {
                let event = event!(e, bpf_events::ExecveEvent).unwrap();
                for e in bpf_events::HashEvent::all_from_execve(event) {
                    self.send_event(e).unwrap()
                }
            }

            Type::MmapExec => {
                let event = event!(e, bpf_events::MmapExecEvent).unwrap();
                self.send_event(bpf_events::HashEvent::from(event)).unwrap();
            }

            Type::TaskSched => {
                let c: bpf_events::CorrelationEvent =
                    event!(e, bpf_events::ScheduleEvent).unwrap().into();
                self.send_event(c).unwrap();
            }

            _ => {}
        }
    }

    fn read_events(er: &Arc<Mutex<Self>>, bpf: &mut Bpf, config: &Config) {
        // try to convert the PERF_ARRAY map to an AsyncPerfEventArray
        let mut perf_array =
            AsyncPerfEventArray::try_from(bpf.take_map(bpf_events::KUNAI_EVENTS_MAP).unwrap())
                .unwrap();

        let online_cpus = online_cpus().expect("failed to get online cpus");
        let barrier = Arc::new(Barrier::new(online_cpus.len()));
        // we choose what task will handle the reduce process (handle piped events)
        let reducer_cpu_id = online_cpus[0];

        for cpu_id in online_cpus {
            // open a separate perf buffer for each cpu
            let mut buf = perf_array
                .open(
                    cpu_id,
                    Some(optimal_page_count(
                        PAGE_SIZE,
                        MAX_BPF_EVENT_SIZE,
                        config.max_buffered_events as usize,
                    )),
                )
                .unwrap();

            let event_reader = er.clone();
            let bar = barrier.clone();
            let conf = config.clone();

            // process each perf buffer in a separate task
            task::spawn(async move {
                // the number of buffers we want to use gives us the number of events we can read
                // in one go in userland
                let mut buffers = (0..conf.max_buffered_events)
                    .map(|_| BytesMut::with_capacity(MAX_BPF_EVENT_SIZE))
                    .collect::<Vec<_>>();

                // we need to be sure that timeout is bigger than the slowest of
                // our probes to guarantee that we can correctly re-order events
                let timeout_ms = 100;

                loop {
                    // we time this out so that the barrier does not wait too long
                    let events = match time::timeout(
                        time::Duration::from_millis(timeout_ms),
                        buf.read_events(&mut buffers),
                    )
                    .await
                    {
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
                            let er = event_reader.lock().await;
                            for ty in Type::variants() {
                                if ty.is_configurable() {
                                    error!(
                                        "stats {}: {}",
                                        ty,
                                        er.stats.get(&ty, 0).unwrap_or_default()
                                    );
                                }
                            }
                            // drop er
                        }
                    }

                    // events.read contains the number of events that have been read,
                    // and is always <= buffers.len()
                    for buf in buffers.iter().take(events.read) {
                        let mut dec = EncodedEvent::from_bytes(buf);
                        let mut er = event_reader.lock().await;

                        // we make sure here that only events for which we can grab info for
                        // are pushed to the pipe. It is simplifying the error handling process
                        // in sorting the pipe afterwards
                        if let Ok(info) = unsafe { dec.info_mut() } {
                            info.batch = er.batch;
                        } else {
                            error!("failed to decode info");
                            continue;
                        }

                        // pre-processing events
                        // we eventually change event type in this function
                        // example: Execve -> ExecveScript if necessary
                        er.pre_process_events(&mut dec);
                        // passing through some events used for correlation
                        er.pass_through_events(&dec);

                        // we must get the event type here because we eventually
                        // changed it
                        let etype = unsafe { dec.info() }
                            .expect("info should not fail here")
                            .etype;

                        // filtering out unwanted events
                        if !er.filter.is_enabled(etype) {
                            continue;
                        }

                        if matches!(etype, Type::TaskSched) {
                            continue;
                        }

                        er.pipe.push_back(dec);
                    }

                    // all threads wait here after some events have been collected
                    bar.wait().await;

                    // only one task needs to reduce
                    if cpu_id == reducer_cpu_id {
                        let mut ep = event_reader.lock().await;
                        if ep.has_pending_events() {
                            ep.process_piped_events().await;
                            ep.batch += 1;
                        }
                    }

                    // all threads wait that piped events are processed so that the reducer does not
                    // handle events being piped in the same time by others
                    bar.wait().await;
                }

                #[allow(unreachable_code)]
                Ok::<_, PerfBufferError>(())
            });
        }
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(long, help = "Enable debugging")]
    debug: bool,

    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Specify a configuration file to use. Command line options superseed the ones specified in the configuration file."
    )]
    config: Option<PathBuf>,

    #[arg(long, help = "Prints a default configuration to stdout")]
    dump_config: bool,

    #[arg(long, help = "Show details about configurable events on stdout")]
    show_events: bool,

    #[arg(long, help = "Exclude events by name (comma separated)")]
    exclude: Option<String>,

    #[arg(
        long,
        help = "Include events by name (comma separated). Superseeds any exclude filter."
    )]
    include: Option<String>,

    #[arg(
        long,
        help = "Increase the size of the buffer shared between eBPF probes and userland"
    )]
    max_buffered_events: Option<u16>,

    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "Detection/filtering rule file. Superseeds configuration file"
    )]
    rule_file: Option<Vec<String>>,

    #[arg(
        short,
        long,
        value_name = "FILE",
        help = "File containing IoCs (json line)"
    )]
    ioc_file: Option<Vec<String>>,

    #[arg(short, long, action = clap::ArgAction::Count, help="Set verbosity level, repeat option for more verbosity.")]
    verbose: u8,

    #[arg(short, long)]
    silent: bool,
}

// todo: make single-threaded / multi-threaded available in configuration
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    let mut conf = Config::default();

    // Handling any CLI argument not needing to run eBPF
    // setting log level according to the verbosity level
    let mut log_level = LevelFilter::Error;
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

    // dumping configuration
    if cli.dump_config {
        let mut conf = Config::default();
        conf.generate_host_uuid();
        println!("{}", conf.to_toml()?);
        return Ok(());
    }

    // show events
    if cli.show_events {
        for v in bpf_events::Type::variants() {
            if v.is_configurable() {
                let pad = 25 - v.as_str().len();
                println!("{}: {:>pad$}", v.as_str(), v as u32)
            }
        }
        return Ok(());
    }

    if let Some(conf_file) = cli.config {
        conf = Config::from_toml(std::fs::read_to_string(conf_file)?)?;
    }

    // command line superseeds configuration

    // superseeds configuration
    if let Some(rules) = cli.rule_file {
        conf.rules = rules;
    }

    // superseeds configuration
    if let Some(iocs) = cli.ioc_file {
        conf.iocs = iocs;
    }

    // we want to increase max_buffered_events
    if cli.max_buffered_events.is_some() {
        conf.max_buffered_events = cli.max_buffered_events.unwrap();
    }

    // we exclude events
    if let Some(exclude) = cli.exclude {
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
    if let Some(include) = cli.include {
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

    // checking that we are running as root
    if get_current_uid() != 0 {
        return Err(anyhow::Error::msg(
            "You need to be root to run this program, this is necessary to load eBPF programs",
        ));
    }

    #[cfg(debug_assertions)]
    let mut bpf =
        BpfLoader::new()
            .verifier_log_level(verifier_level)
            .load(include_bytes_aligned!(
                "../../../target/bpfel-unknown-none/debug/kunai-ebpf"
            ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf =
        BpfLoader::new()
            .verifier_log_level(verifier_level)
            .load(include_bytes_aligned!(
                "../../../target/bpfel-unknown-none/release/kunai-ebpf"
            ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    BpfConfig::init_config_in_bpf(&mut bpf, conf.clone().try_into()?)
        .expect("failed to initialize bpf configuration");

    // we start event reader and event processor before loading the programs
    // if we load the programs first we might have some event lost errors
    let (sender, receiver) = channel::<EncodedEvent>();

    EventReader::init(&mut bpf, conf.clone(), sender)?;
    EventProcessor::init(conf, receiver)?;

    let btf = Btf::from_sys_fs()?;

    let current_kernel = KernelVersion::from_sys()?;

    // make possible probe selection in debug
    #[allow(unused_mut)]
    let mut en_probes: Vec<String> = vec![];
    #[cfg(debug_assertions)]
    if let Ok(enable) = std::env::var("PROBES") {
        enable.split(',').for_each(|s| en_probes.push(s.into()));
    }

    let mut programs = Programs::from_bpf(&mut bpf);

    kunai::configure_probes(&mut programs, current_kernel);

    // generic program loader
    for (_, mut p) in programs.into_vec_sorted_by_prio() {
        // filtering probes to enable (only available in debug)
        if !en_probes.is_empty() && en_probes.iter().filter(|e| p.name.contains(*e)).count() == 0 {
            continue;
        }

        // we force enabling of selected probes
        // debug probes are disabled by default
        if !en_probes.is_empty() {
            p.enable();
        }

        info!(
            "loading: {} {:?} with priority={}",
            p.name,
            p.prog_type(),
            p.prio
        );

        if !p.enable {
            warn!("{} probe has been disabled", p.name);
            continue;
        }

        if !p.is_compatible(&current_kernel) {
            warn!(
                "{} probe is not compatible with current kernel: min={} max={} current={}",
                p.name,
                p.compat.min(),
                p.compat.max(),
                current_kernel
            );
            continue;
        }

        p.attach(&btf)?;
    }

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
