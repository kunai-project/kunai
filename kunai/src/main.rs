mod cache;
mod compat;
mod info;
mod util;

use info::{AdditionalFields, StdEventInfo};
use json::{object, JsonValue};
use kunai_common::cgroup::Cgroup;
use kunai_common::config::{self, BpfConfig, Config};

use std::collections::{HashMap, VecDeque};

use std::net::IpAddr;
use std::path::PathBuf;

use std::sync::mpsc::{channel, Receiver, SendError, Sender};
use std::sync::Arc;
use std::thread;
use users::get_current_uid;
use util::*;

use aya::{
    include_bytes_aligned,
    maps::perf::{AsyncPerfEventArray, Events, PerfBufferError},
    util::online_cpus,
    Bpf, Btf,
};
#[allow(unused_imports)]
use aya::{BpfLoader, VerifierLogLevel};
use aya_log::BpfLogger;
use kunai_common::{
    events::{self, EncodedEvent, Event, *},
    inspect_err, perf,
    uuid::TaskUuid,
};

use log::{debug, error, info, warn};

//use tokio::sync::{Barrier, Mutex};
use tokio::sync::{Barrier, Mutex};
use tokio::{signal, task, time};

use cache::*;

use crate::compat::{KernelVersion, Programs};
use crate::util::namespaces::unshare;

const PAGE_SIZE: usize = 4096;
const MAX_EVENT_SIZE: usize = core::mem::size_of::<Event<ExecveData>>();
const MAX_EVENT_COUNT: usize = 256;

macro_rules! format_ptr {
    ($value:expr) => {
        format!("{:p}", $value as *const u8)
    };
}

#[derive(Debug, Clone, Copy)]
struct ProcFsTaskInfo {
    pid: i32,
    uuid: TaskUuid,
}

impl ProcFsTaskInfo {
    fn new(start_time_clk_tck: u64, random: u32, pid: i32) -> Self {
        // starttime in procfs is measured in tick count so we need to convert it
        let clk_tck = get_clk_tck() as u64;

        Self {
            pid,
            uuid: TaskUuid::new(
                // convert time to the same scale as starttime in task_struct
                start_time_clk_tck * 1_000_000_000 / clk_tck,
                random,
                pid as u32,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ProcFsInfo {
    task: ProcFsTaskInfo,
    parent: Option<ProcFsTaskInfo>,
}

#[derive(Debug, Clone)]
enum CorrInfo {
    ProcFs(ProcFsInfo),
    Event(StdEventInfo),
}

impl CorrInfo {
    fn corr_key(tuuid: TaskUuid) -> u128 {
        // in task_struct start_time has a higher resolution so we need to scale it
        // down in order to have a comparable value with the procfs one
        let start_time_sec = tuuid.start_time_ns / 1_000_000_000;
        TaskUuid::new(start_time_sec, tuuid.random, tuuid.pid).into()
    }

    #[inline]
    fn pid(&self) -> i32 {
        match self {
            Self::ProcFs(pi) => pi.task.pid,
            Self::Event(si) => si.info.process.tgid,
        }
    }

    #[inline]
    fn correlation_key(&self) -> u128 {
        match self {
            Self::ProcFs(pi) => Self::corr_key(pi.task.uuid),
            Self::Event(si) => Self::corr_key(si.info.process.tg_uuid),
        }
    }

    #[inline]
    fn parent_correlation_key(&self) -> Option<u128> {
        match self {
            Self::ProcFs(pi) => Some(Self::corr_key(pi.parent?.uuid)),
            Self::Event(si) => Some(Self::corr_key(si.info.parent.tg_uuid)),
        }
    }
}

#[derive(Debug, Clone)]
struct CorrelationData {
    image: PathBuf,
    command_line: Vec<String>,
    resolved: HashMap<IpAddr, String>,
    container: Option<String>,
    info: CorrInfo,
}

struct EventProcessor {
    random: u32,
    hcache: cache::Cache,
    receiver: Receiver<EncodedEvent>,
    correlations: HashMap<u128, CorrelationData>,
}

impl EventProcessor {
    #[inline]
    fn container_type_from_cgroup(cgrp: &Cgroup) -> Option<String> {
        let s: Vec<String> = cgrp.to_vec();

        if let Some(last) = s.last() {
            if last.starts_with("docker-") {
                return Some("docker".into());
            }
        }

        if let Some(first) = s.get(1) {
            if first.starts_with("lxc.payload.") {
                return Some("lxc".into());
            }
        }

        None
    }

    #[inline]
    fn json_event(info: StdEventInfo, data: JsonValue) -> JsonValue {
        object! {data: data, info: info,}
    }

    #[inline]
    fn json_event_info_ref(info: &StdEventInfo, data: JsonValue) -> JsonValue {
        object! {data: data, info: info}
    }

    pub fn init(receiver: Receiver<EncodedEvent>) {
        let mut ep = Self {
            random: util::getrandom::<u32>().unwrap(),
            hcache: Cache::with_max_entries(10000),
            correlations: HashMap::new(),
            receiver,
        };

        // should not raise any error, we just print it
        inspect_err! {
            ep.init_correlations_from_procfs(),
            |e: anyhow::Error| warn!("failed to initialize correlations with procfs: {}", e)
        };

        thread::spawn(move || {
            // the thread must drop CLONE_FS in order to be able to navigate
            // in namespaces
            unshare(libc::CLONE_FS).unwrap();
            while let Ok(mut enc) = ep.receiver.recv() {
                ep.handle_event(&mut enc);
            }
        });

        //ep
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

        let pi = ProcFsTaskInfo::new(p.stat()?.starttime, self.random, p.pid);

        let parent_pid = p.status()?.ppid;

        if parent_pid != 0 {
            let parent = procfs::process::Process::new(parent_pid)?;

            ppi = Some(ProcFsTaskInfo::new(
                parent.stat()?.starttime,
                self.random,
                parent_pid,
            ));
        }

        let ci = CorrInfo::ProcFs(ProcFsInfo {
            task: pi,
            parent: ppi,
        });

        let ck = ci.correlation_key();

        if self.correlations.contains_key(&ck) {
            return Ok(());
        }

        let cor = CorrelationData {
            image: p.exe().unwrap_or("?".into()),
            command_line: p.cmdline().unwrap_or(vec!["?".into()]),
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
            cl = corr.command_line.join(" ");
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
        let mut last_pid = -1;
        while let Some(cor) = self.correlations.get(&ck) {
            last_pid = cor.info.pid();

            ancestors.insert(
                0,
                format!("{}[{}]", cor.image.to_string_lossy(), cor.info.pid(),),
            );
            ck = match cor.info.parent_correlation_key() {
                Some(v) => v,
                None => break,
            };
        }
        // it means we did not manage to get ancestors until init
        if last_pid != 1 {
            ancestors.insert(0, "?".into());
        }
        ancestors
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
        self.correlations.get_mut(&ck).map(|c| {
            c.resolved
                .entry(ip)
                .and_modify(|r| *r = resolved.to_owned())
                .or_insert(resolved.to_owned())
        });
    }

    #[inline]
    fn get_resolved(&self, ip: IpAddr, i: &StdEventInfo) -> String {
        let ck = i.correlation_key();
        self.correlations
            .get(&ck)
            .map(|c| c.resolved.get(&ip))
            .and_then(|o| o.cloned())
            .unwrap_or("?".into())
    }

    #[inline]
    fn get_hashes_with_ns(&mut self, ns_inum: u32, p: &kunai_common::path::Path) -> Hashes {
        match self.hcache.get_or_cache_in_ns(ns_inum, p) {
            Ok(h) => h,
            Err(e) => Hashes {
                file: p.to_path_buf(),
                error: Some(format!("{e}")),
                ..Default::default()
            },
        }
    }

    #[inline]
    fn json_execve(&mut self, mut info: StdEventInfo, event: &mut ExecveEvent) -> JsonValue {
        let ancestors = self.get_ancestors(&info);

        //let executable = event.data.executable.to_path_buf();
        //let interpreter = event.data.interpreter.to_path_buf();
        let mnt_ns = event.info.process.namespaces.mnt;

        let mut data = object! {
            ancestors: ancestors.join("|"),
            parent_exe: self.get_parent_image(&info),
            command_line: event.data.argv.to_command_line(),
            exe: self.get_hashes_with_ns(mnt_ns, &event.data.executable),

        };

        // we check wether a script is being interpreted
        if event.data.executable != event.data.interpreter {
            info.info.etype = Type::ExecveScript;
            data["interpreter"] = self
                .get_hashes_with_ns(mnt_ns, &event.data.executable)
                .into();
        }

        Self::json_event_info_ref(&info, data)
    }

    #[inline]
    fn json_mmap_exec(&mut self, info: StdEventInfo, event: &mut MmapExecEvent) -> JsonValue {
        // todo : handle this better
        let filename = event.data.filename;
        let mnt_ns = event.info.process.namespaces.mnt;
        let mmapped_hashes = self.get_hashes_with_ns(mnt_ns, &filename);

        let ck = info.correlation_key();

        let exe = self.get_exe(ck);

        let data = object! {
            command_line: self.get_command_line(ck),
            exe: exe.to_string_lossy().to_string(),
            mapped: mmapped_hashes,
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_dns_queries(&mut self, info: StdEventInfo, event: &DnsQueryEvent) -> Vec<JsonValue> {
        let mut out: Vec<JsonValue> = vec![];
        let ck = info.correlation_key();
        let exe = self.get_exe(ck);
        let cmd_line = self.get_command_line(ck);

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
            out.push(Self::json_event(
                info.clone(),
                object! {
                    command_line: cmd_line.clone(),
                    exe: exe.to_string_lossy().to_string(),
                    query: r.question.clone(),
                    proto: proto.as_str(),
                    response: r.answers.join(";"),
                    dns_server: {
                        ip: serv_ip.to_string(),
                        port: serv_port,
                        public: is_public_ip(serv_ip),
                    }
                },
            ));

            // update the resolution map
            r.answers.iter().for_each(|a| {
                // if we manage to parse IpAddr
                if let Ok(ip) = a.parse::<IpAddr>() {
                    self.update_resolved(ip, &r.question, &info);
                }
            });
        }

        out
    }

    #[inline]
    fn json_config_event(&mut self, info: StdEventInfo, event: &ConfigEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        Self::json_event(
            info,
            object! {
                command_line: cmd_line,
                exe: exe.to_string_lossy().to_string(),
                path: event.data.path.to_string(),
            },
        )
    }

    #[inline]
    fn json_mount_event(&mut self, info: StdEventInfo, event: &MountEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let mut data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            dev_name: event.data.dev_name.to_string(),
            path: event.data.path.to_string(),
        };

        // we cannot use type keyword in object! macro
        data["type"] = event.data.ty.to_string().into();
        // in order to display success after type
        data["success"] = (event.data.rc == 0).into();

        Self::json_event(info, data)
    }

    #[inline]
    fn json_bpf_prog_load(&mut self, info: StdEventInfo, event: &BpfProgLoadEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);
        let mut data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            id: event.data.id,
            prog_type: {
                id: event.data.prog_type,
                name: util::bpf::bpf_type_to_string(event.data.prog_type),
            },
            tag: hex::encode(event.data.tag),
            attached_func: event.data.attached_func_name.to_string(),
            name: event.data.name.to_string(),
            ksym: event.data.ksym.to_string(),
            bpf_prog: {
                md5: "?".to_string(),
                sha1: "?".to_string(),
                sha256: "?".to_string(),
                sha512: "?".to_string(),
                size: 0,
            },
            // count of verified instructions
            verified_insns: event.data.verified_insns,
            // if loading was successful
            loaded: event.data.loaded,
        };

        if let Some(h) = &event.data.hashes {
            data["bpf_prog"]["md5"] = h.md5.to_string().into();
            data["bpf_prog"]["sha1"] = h.sha1.to_string().into();
            data["bpf_prog"]["sha256"] = h.sha256.to_string().into();
            data["bpf_prog"]["sha512"] = h.sha512.to_string().into();
            data["bpf_prog"]["size"] = h.size.into();
        }

        Self::json_event(info, data)
    }

    #[inline]
    fn json_mprotect(&self, info: StdEventInfo, event: &MprotectEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);
        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            addr: format_ptr!(event.data.start),
            prot: format!("0x{:08x}", event.data.prot),
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_connect(&self, info: StdEventInfo, event: &ConnectEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);
        let dst_ip: IpAddr = event.data.ip_port.into();
        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            dst: object!{
                hostname: self.get_resolved(dst_ip, &info),
                ip: dst_ip.to_string(),
                port: event.data.ip_port.port(),
                public: is_public_ip(dst_ip),
                is_v6: event.data.ip_port.is_v6(),
            },
            connected: event.data.connected,
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_send_data(&self, info: StdEventInfo, event: &SendEntropyEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);
        let dst_ip: IpAddr = event.data.ip_port.into();
        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            dst: object!{
                hostname: self.get_resolved(dst_ip, &info),
                ip: dst_ip.to_string(),
                port: event.data.ip_port.port(),
                public: is_public_ip(dst_ip),
                is_v6: event.data.ip_port.is_v6(),
            },
            data_entropy: event.shannon_entropy(),
            data_size: event.data.real_data_size,
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_init_module(&self, info: StdEventInfo, event: &InitModuleEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            module_name: event.data.name.to_string(),
            args: event.data.uargs.to_string(),
            userspace_addr: format_ptr!(event.data.umod),
            loaded: event.data.loaded,
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_file_rename(&self, info: StdEventInfo, event: &FileRenameEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
            old: event.data.old_name.to_string(),
            new: event.data.new_name.to_string(),
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_exit(&mut self, info: StdEventInfo, event: &ExitEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().to_string(),
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
            //self.correlations.remove(&info.correlation_key());
        }

        Self::json_event(info, data)
    }

    #[inline]
    fn handle_correlation_event(&mut self, info: StdEventInfo, event: &CorrelationEvent) {
        let ck = info.correlation_key();

        // early return if correlation key exists
        if self.correlations.contains_key(&ck) {
            return;
        }

        let cgroup = event.data.cgroup;

        let container_type = Self::container_type_from_cgroup(&cgroup);

        // we insert only if not existing
        self.correlations.entry(ck).or_insert(CorrelationData {
            image: event.data.exe.to_path_buf(),
            command_line: event.data.argv.to_argv(),
            resolved: HashMap::new(),
            container: container_type,
            info: CorrInfo::Event(info),
        });
    }

    #[inline]
    fn handle_hash_event(&mut self, info: StdEventInfo, event: &HashEvent) {
        let mnt_ns = info.info.process.namespaces.mnt;
        self.get_hashes_with_ns(mnt_ns, &event.data.path);
    }

    fn build_std_event_info(&mut self, i: EventInfo) -> StdEventInfo {
        let ns = i.process.namespaces.mnt;

        let std_info = StdEventInfo::with_event_info(i, self.random);

        let cd = self.correlations.get(&std_info.correlation_key());

        let additional = AdditionalFields {
            hostname: self.hcache.get_hostname(ns).unwrap_or("?".into()),
            container: cd.and_then(|cd| cd.container.clone()),
        };

        std_info.with_additional_fields(additional)
    }

    fn handle_event(&mut self, enc_event: &mut EncodedEvent) {
        let i = unsafe { enc_event.info() }.unwrap();

        // we don't handle our own events
        if i.process.tgid as u32 == std::process::id() {
            debug!("skipping our event");
            return;
        }

        let pid = i.process.tgid;
        let ns = i.process.namespaces.mnt;
        if let Err(e) = self.hcache.cache_ns(pid, ns) {
            debug!("failed to cache namespace pid={pid} ns={ns}: {e}");
        } else {
            debug!("successfully cached namespace pid={pid} ns={ns}");
        }

        let std_info = self.build_std_event_info(*i);

        let etype = std_info.info.etype;

        match etype {
            events::Type::Execve => match unsafe { enc_event.as_mut_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_execve(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::MmapExec => match unsafe { enc_event.as_mut_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_mmap_exec(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::MprotectExec => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_mprotect(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::Connect => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_connect(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::DnsQuery => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => {
                    for json in self.json_dns_queries(std_info, e) {
                        std::println!("{json}");
                    }
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::SendData => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_send_data(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::InitModule => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_init_module(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::WriteConfig | events::Type::ReadConfig => {
                match unsafe { enc_event.as_event_with_data() } {
                    Ok(e) => std::println!("{}", self.json_config_event(std_info, e)),
                    Err(e) => error!("failed to decode {} event: {:?}", etype, e),
                }
            }

            events::Type::Mount => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_mount_event(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::FileRename => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_file_rename(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::BpfProgLoad => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_bpf_prog_load(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::Exit | events::Type::ExitGroup => {
                match unsafe { enc_event.as_event_with_data() } {
                    Ok(e) => std::println!("{}", self.json_exit(std_info, e)),
                    Err(e) => error!("failed to decode {} event: {:?}", etype, e),
                }
            }

            events::Type::Correlation => match event!(enc_event) {
                Ok(e) => {
                    self.handle_correlation_event(std_info, e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::CacheHash => match event!(enc_event) {
                Ok(e) => {
                    self.handle_hash_event(std_info, e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            _ => {
                unimplemented!("event type not implemented")
            }
        }
    }
}

struct EventReader {
    batch: usize,
    pipe: VecDeque<EncodedEvent>,
    sender: Sender<EncodedEvent>,
}

impl EventReader {
    pub fn init(bpf: &mut Bpf, sender: Sender<EncodedEvent>) -> anyhow::Result<Arc<Mutex<Self>>> {
        let ep = EventReader {
            pipe: VecDeque::new(),
            batch: 0,
            sender,
        };

        let safe = Arc::new(Mutex::new(ep));
        Self::read_events(&safe, bpf);
        Ok(safe)
    }

    #[inline(always)]
    fn has_pending_events(&self) -> bool {
        !self.pipe.is_empty()
    }

    // Event ordering is a very important piece as it impacts on-host correlations.
    // Additionaly it is very useful as it guarantees events are printed/piped in to
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
        let mut count = self
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

        // processing count piped events, we need to pop front as events
        // are sorted ascending by timestamp
        while count > 0 {
            // at this point pop_front cannot fail as count takes account of the elements in the pipe
            let enc_evt = self
                .pipe
                .pop_front()
                .expect("pop_front should never fail here");

            // send event to event processor
            self.sender.send(enc_evt).unwrap();

            count -= 1;
        }
    }

    // The aim of this function is to be run as soon as the event gets available in userland.
    // So any processing on events that requires realtime properties must be done here. A direct
    // consequence of this is that anything that do not require realtime property should not
    // be done here as it may slow down the event processing.
    /*async fn pre_process_events(
        &mut self,
        enc_event: &mut EncodedEvent,
    ) -> Result<(), anyhow::Error> {
        let i = unsafe { enc_event.info_mut() }?;
        let etype = i.etype;

        match etype {
            Type::Execve => {
                let event = mut_event!(enc_event, ExecveEvent)?;
                let p = event.data.executable.to_path_buf();

                if let Some(hash) = self
                    .hcache
                    .get_or_cache_with_ns(event.info.process.namespaces.mnt, p)
                    .await
                {
                    info!("got hash from namespace: exe={:#?}", hash)
                }

                if event.data.executable != event.data.interpreter {
                    self.make_realpath_and_cache_hash(&mut event.data.interpreter)
                        .await;
                }
                self.make_realpath_and_cache_hash(&mut event.data.executable)
                    .await;
            }

            Type::MmapExec => {
                let event = mut_event!(enc_event, MmapExecEvent)?;

                self.make_realpath_and_cache_hash(&mut event.data.filename)
                    .await;
            }

            Type::Mount => {
                let event = mut_event!(enc_event, MountEvent)?;
                // we hook into those events in order to get superblock inode information
                self.mounts.insert(
                    event
                        .data
                        .path
                        .ino
                        .expect("path ino should never be missing"),
                    event.data.path.to_path_buf(),
                );
            }

            Type::ReadConfig | Type::WriteConfig => {
                let event = mut_event!(enc_event, ConfigEvent)?;
                self.make_realpath(&mut event.data.path);
            }

            Type::FileRename => {
                let event = mut_event!(enc_event, FileRenameEvent)?;
                self.make_realpath(&mut event.data.new_name);
                self.make_realpath(&mut event.data.old_name);
            }

            _ => {}
        }

        Ok(())
    }*/

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
            Type::BpfProgLoad => {
                let mut event = mut_event!(e, BpfProgLoadEvent).unwrap();

                // dumping eBPF program from userland
                match util::bpf::bpf_dump_xlated_by_id_and_tag(event.data.id, event.data.tag) {
                    Ok(insns) => {
                        let h = ProgHashes {
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
    fn pass_through_events(&self, e: &EncodedEvent) {
        let i = unsafe { e.info() }.unwrap();

        match i.etype {
            Type::Execve => {
                let execve = event!(e, ExecveEvent).unwrap();
                let c: CorrelationEvent = execve.into();
                self.send_event(c).unwrap();

                for h in HashEvent::all_from_execve(execve) {
                    self.send_event(h).unwrap();
                }
            }

            Type::MmapExec => {
                let event = event!(e, MmapExecEvent).unwrap();
                self.send_event(HashEvent::from(event)).unwrap();
            }

            Type::TaskSched => {
                let c: CorrelationEvent = event!(e, ScheduleEvent).unwrap().into();
                self.send_event(c).unwrap();
            }

            _ => {}
        }
    }

    fn read_events(ep: &Arc<Mutex<Self>>, bpf: &mut Bpf) {
        // try to convert the PERF_ARRAY map to an AsyncPerfEventArray
        let mut perf_array =
            AsyncPerfEventArray::try_from(bpf.take_map(events::EVENTS_MAP_NAME).unwrap()).unwrap();
        let online_cpus = online_cpus().expect("failed to get online cpus");
        let barrier = Arc::new(Barrier::new(online_cpus.len()));
        // we choose what task will handle the reduce process (handle piped events)
        let reducer_cpu_id = online_cpus[0];

        for cpu_id in online_cpus {
            // open a separate perf buffer for each cpu
            let mut buf = perf_array
                .open(
                    cpu_id,
                    Some(perf::optimal_page_count(
                        PAGE_SIZE,
                        MAX_EVENT_SIZE,
                        MAX_EVENT_COUNT,
                    )),
                )
                .unwrap();

            let event_proc = ep.clone();
            let bar = barrier.clone();

            // process each perf buffer in a separate task
            task::spawn(async move {
                // only the reducer thread will be allowed to switch between namespaces
                if cpu_id == reducer_cpu_id {}

                // the number of buffers we want to use gives us the number of events we can read
                // in one go in userland
                let mut buffers = perf::event_buffers(MAX_EVENT_SIZE, 64, MAX_EVENT_COUNT);

                // we need to be sure that the fast timeout is bigger than the slowest of
                // our probes to guarantee that we can correctly re-order events
                let fast_timeout_ms = 100;
                let slow_timeout_ms = 500;
                let mut timeout = fast_timeout_ms;

                loop {
                    // we time this out so that the barrier does not wait too long
                    let events = match time::timeout(
                        time::Duration::from_millis(timeout),
                        buf.read_events(&mut buffers),
                    )
                    .await
                    {
                        Ok(r) => {
                            timeout = fast_timeout_ms;
                            r?
                        }
                        _ => {
                            timeout = slow_timeout_ms;
                            Events { read: 0, lost: 0 }
                        }
                    };

                    // checking out lost events
                    if events.lost > 0 {
                        error!(
                            "some events have been lost in the way from kernel read={} lost={}",
                            events.read, events.lost
                        )
                    }

                    // events.read contains the number of events that have been read,
                    // and is always <= buffers.len()
                    for buf in buffers.iter().take(events.read) {
                        let mut dec = EncodedEvent::from_bytes(buf);
                        let mut ep = event_proc.lock().await;

                        // we make sure here that only events for which we can grab info for
                        // are pushed to the pipe. It is simplifying the error handling process
                        // in sorting the pipe afterwards
                        if let Ok(info) = unsafe { dec.info_mut() } {
                            info.batch = ep.batch;

                            /*let opt_evt = match CorrelationEvent::from_encoded(&dec) {
                                Ok(opt_evt) => opt_evt,
                                Err(e) => {
                                    error!("failed to transform event: {e}");
                                    None
                                }
                            };

                            if let Some(corr_event) = opt_evt {
                                if let Ok(enc) = EncodedEvent::from_event(corr_event) {
                                    ep.sender.send(enc);
                                } else {
                                    error!("failed to encode correlation event");
                                }
                            }*/
                        } else {
                            error!("failed to decode info");
                            continue;
                        }

                        let etype = unsafe { dec.info() }
                            .expect("info should not fail here")
                            .etype;

                        ep.pre_process_events(&mut dec);

                        ep.pass_through_events(&dec);

                        if matches!(etype, Type::TaskSched) {
                            continue;
                        }

                        ep.pipe.push_back(dec);
                    }

                    // all threads wait here after some events have been collected
                    bar.wait().await;

                    // only one task needs to reduce
                    if cpu_id == reducer_cpu_id {
                        let mut ep = event_proc.lock().await;
                        if ep.has_pending_events() {
                            ep.process_piped_events().await;
                            ep.batch += 1;
                        }
                    }

                    // all threads wait that piped events are processed so that the reducer does not
                    // handle events being piped in the same time by others
                    bar.wait().await;

                    if events.read == buffers.len() {
                        // increasing the size of the buffer used to read event
                        let new_size = buffers.len() * 2;
                        if new_size < MAX_EVENT_COUNT {
                            buffers =
                                perf::event_buffers(MAX_EVENT_SIZE, new_size, MAX_EVENT_COUNT);
                        }
                    }
                }

                #[allow(unreachable_code)]
                Ok::<_, PerfBufferError>(())
            });
        }
    }
}

// todo: make single-threaded / multi-threaded features
#[tokio::main(flavor = "current_thread")]
//#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    // checking that we are running as root
    if get_current_uid() != 0 {
        return Err(anyhow::Error::msg(
            "You need to be root to run this program, this is necessary to load eBPF programs",
        ));
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    /*#[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/aya-sysmon"
    ))?;*/
    //#[cfg(debug_assertions)]
    let verifier_level = match std::env::var("VERIFIER_LOG_LEVEL") {
        Ok(s) => match s.as_str() {
            "debug" => VerifierLogLevel::DEBUG,
            "verbose" => VerifierLogLevel::VERBOSE,
            "disable" => VerifierLogLevel::DISABLE,
            _ => VerifierLogLevel::STATS,
        },
        _ => VerifierLogLevel::STATS,
    };

    #[cfg(debug_assertions)]
    let mut bpf =
        BpfLoader::new()
            .verifier_log_level(verifier_level)
            .load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/debug/kunai-ebpf"
            ))?;

    #[cfg(not(debug_assertions))]
    let mut bpf =
        BpfLoader::new()
            .verifier_log_level(verifier_level)
            .load(include_bytes_aligned!(
                "../../target/bpfel-unknown-none/release/kunai-ebpf"
            ))?;

    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    BpfConfig::init_config_in_bpf(&mut bpf, Config {}.into());

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

    programs.expect_mut("execve.security_bprm_check").prio = 0;

    programs.expect_mut("execve.exit.bprm_execve").prio = 20;
    programs
        .expect_mut("execve.exit.bprm_execve")
        .min_kernel(kernel!(5, 9));

    programs.expect_mut("syscalls.sys_exit_execve").prio = 20;
    programs
        .expect_mut("syscalls.sys_exit_execve")
        .max_kernel(kernel!(5, 9));

    programs
        .expect_mut("syscalls.sys_exit_execveat")
        .max_kernel(kernel!(5, 9));

    // bpf probes
    programs.expect_mut("entry.security_bpf_prog").prio = 90;
    programs.expect_mut("exit.bpf_prog_load").prio = 100;

    // fd_install
    programs.expect_mut("fd.fd_install").prio = 0;
    programs.expect_mut("fd.entry.__fdget").prio = 0;
    programs.expect_mut("fd.exit.__fdget").prio = 10;

    // kernel function name changed above 5.9
    if current_kernel < kernel!(5, 9) {
        programs
            .expect_mut("fs.exit.path_mount")
            .rename("fs.exit.do_mount")
    }

    // mmap probe
    programs.expect_mut("syscalls.sys_enter_mmap").prio = 90;

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

    let (sender, receiver) = channel::<EncodedEvent>();

    EventReader::init(&mut bpf, sender)?;
    EventProcessor::init(receiver);

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
