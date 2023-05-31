mod compat;
mod hcache;
mod util;

use json::{object, JsonValue};

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use std::sync::Arc;
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

use chrono::prelude::*;

use log::{debug, error, info, warn};

use tokio::sync::{Barrier, Mutex};
use tokio::{signal, task, time};

use hcache::*;

use crate::compat::KernelVersion;

const PAGE_SIZE: usize = 4096;
const MAX_EVENT_SIZE: usize = core::mem::size_of::<Event<ExecveData>>();
const MAX_EVENT_COUNT: usize = 256;

#[derive(Debug, Clone)]
struct StdEventInfo {
    info: events::EventInfo,
    utc_timestamp: DateTime<Utc>,
}

impl StdEventInfo {
    fn correlation_key(&self) -> u128 {
        CorrInfo::corr_key(self.info.process.tg_uuid)
    }

    fn parent_correlation_key(&self) -> u128 {
        CorrInfo::corr_key(self.info.parent.tg_uuid)
    }

    fn from_event_info(mut i: EventInfo, rand: u32) -> Self {
        // we set the random part needed to generate uuids for events
        i.set_uuid_random(rand);
        StdEventInfo {
            info: i,
            // on older kernels bpf_ktime_get_boot_ns() is not available so it is not
            // easy to compute correct event timestamp from eBPF so utc_timestamp is
            // the time at which the event is processed.
            utc_timestamp: chrono::Utc::now(),
        }
    }
}

impl From<StdEventInfo> for JsonValue {
    fn from(value: StdEventInfo) -> Self {
        Self::from(&value)
    }
}

impl From<&StdEventInfo> for JsonValue {
    fn from(i: &StdEventInfo) -> Self {
        let ts = i.utc_timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true);
        let info = i.info;

        object! {
            event: object!{
                //id: info.etype.id(),
                name: info.etype.as_str(),
                uuid: info.uuid.into_uuid().hyphenated().to_string(),
                batch: info.batch,
            },
            // current task
            task: object!{
                name: info.process.comm_string(),
                // start_time
                // start_time: info.process.start_time,
                // task pid
                pid: info.process.pid,
                // task group id -> equals to pid when single threaded
                tgid: info.process.tgid,
                // group uuid
                guuid: info.process.tg_uuid.into_uuid().hyphenated().to_string(),
                uid: info.process.uid,
                gid: info.process.gid,
            },
            // parent task
            parent_task: object!{
                name: info.parent.comm_string(),
                // start_time
                // start_time: info.parent.start_time,
                // task pid
                pid: info.parent.pid,
                // task group id -> equals to pid when single threaded
                tgid: info.parent.tgid,
                // group uuid
                guuid: info.parent.tg_uuid.into_uuid().hyphenated().to_string(),
                uid: info.parent.uid,
                gid: info.parent.gid,
            },
            utc_time: ts,
        }
    }
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
    info: CorrInfo,
}

struct EventProcessor {
    random: u32,
    hcache: hcache::Hcache,
    batch: usize,
    //transfers: Arc<Mutex<TransferMap>>,
    pipe: VecDeque<EncodedEvent>,
    correlations: HashMap<u128, CorrelationData>,
}

macro_rules! format_ptr {
    ($value:expr) => {
        format!("{:p}", $value as *const u8)
    };
}

impl EventProcessor {
    #[inline]
    fn json_event(info: StdEventInfo, data: JsonValue) -> JsonValue {
        object! {data: data, info: info,}
    }

    #[inline]
    fn json_event_info_ref(info: &StdEventInfo, data: JsonValue) -> JsonValue {
        object! {data: data, info: info}
    }

    pub fn init(bpf: &mut Bpf) -> Arc<Mutex<Self>> {
        let mut ep = EventProcessor {
            random: util::getrandom::<u32>().unwrap(),
            hcache: hcache::Hcache::with_max_entries(0x1000),
            pipe: VecDeque::new(),
            batch: 0,
            correlations: HashMap::new(),
        };

        // should not raise any error, we just print it
        inspect_err! {
            ep.init_correlations_from_procfs(),
            |e: anyhow::Error| warn!("failed to initialize correlations with procfs: {}", e)
        };

        let safe = Arc::new(Mutex::new(ep));
        Self::read_events(&safe, bpf);
        safe
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

        // let std_info = StdEventInfo::from_event_info(i, self.random, self.utc_boot_time_sec);
        let ck = ci.correlation_key();

        if self.correlations.contains_key(&ck) {
            return Ok(());
        }

        let cor = CorrelationData {
            image: p.exe().unwrap_or("?".into()),
            command_line: p.cmdline().unwrap_or(vec!["?".into()]),
            resolved: HashMap::new(),
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
    async fn get_hashes<P: AsRef<Path> + Clone>(&mut self, p: P) -> Hashes {
        let cp = p.clone();
        self.hcache.get_or_cache(p).await.unwrap_or(Hashes {
            file: cp.as_ref().to_path_buf(),
            ..Default::default()
        })
    }

    #[inline]
    async fn json_execve(&mut self, mut info: StdEventInfo, event: &ExecveEvent) -> JsonValue {
        let ancestors = self.get_ancestors(&info);
        let executable = event.data.executable.to_path_buf();
        let interpreter = event.data.interpreter.to_path_buf();

        let mut data = object! {
            ancestors: ancestors.join("|"),
            parent_exe: self.get_parent_image(&info),
            command_line: event.data.argv.to_command_line(),
            exe: self.get_hashes(&executable).await,

        };

        // we check wether a script is being interpreted
        if executable != interpreter {
            info.info.etype = Type::ExecveScript;
            data["interpreter"] = self.get_hashes(&interpreter).await.into();
        }

        let out = Self::json_event_info_ref(&info, data);

        // updating correlations
        let corr_key = info.correlation_key();
        let correlations = CorrelationData {
            command_line: event.data.argv.to_argv(),
            image: event.data.executable.to_path_buf(),
            resolved: HashMap::new(),
            info: CorrInfo::Event(info),
        };

        self.correlations.insert(corr_key, correlations);

        out
    }

    #[inline]
    fn track_task(&mut self, info: StdEventInfo, event: &ScheduleEvent) {
        let ck = info.correlation_key();

        // we insert only if not existing
        self.correlations.entry(ck).or_insert(CorrelationData {
            image: event.data.exe.to_path_buf(),
            command_line: event.data.argv.to_argv(),
            resolved: HashMap::new(),
            info: CorrInfo::Event(info),
        });
    }

    #[inline]
    async fn json_mmap_exec(&mut self, info: StdEventInfo, event: &MmapExecEvent) -> JsonValue {
        let filename = event.data.filename.to_path_buf();

        let mmapped_hashes = self
            .hcache
            .get_or_cache(filename.clone())
            .await
            .unwrap_or_default();

        //let info = self.std_event_info(event.info);
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

        // dumping eBPF program from userland
        match util::bpf::bpf_dump_xlated_by_id_and_tag(event.data.id, event.data.tag) {
            Ok(insns) => {
                data["bpf_prog"]["md5"] = md5_data(insns.as_slice()).into();
                data["bpf_prog"]["sha1"] = sha1_data(insns.as_slice()).into();
                data["bpf_prog"]["sha256"] = sha256_data(insns.as_slice()).into();
                data["bpf_prog"]["sha512"] = sha512_data(insns.as_slice()).into();
                data["bpf_prog"]["size"] = insns.len().into();
            }
            Err(e) => {
                error!("failed to retrieve bpf_prog instructions: {:?}", e)
            }
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

    async fn handle_event(&mut self, enc_event: &EncodedEvent) {
        let i = unsafe { enc_event.info() }.unwrap();

        // we don't handle our own events
        if i.process.tgid as u32 == std::process::id() {
            debug!("skipping our event");
            return;
        }

        let std_info = StdEventInfo::from_event_info(*i, self.random);

        match i.etype {
            events::Type::Execve => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_execve(std_info, e).await),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::TaskSched => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => self.track_task(std_info, e),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::MmapExec => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_mmap_exec(std_info, e).await),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::MprotectExec => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_mprotect(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::Connect => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_connect(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::DnsQuery => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => {
                    for json in self.json_dns_queries(std_info, e) {
                        std::println!("{json}");
                    }
                }
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::SendData => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_send_data(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::InitModule => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_init_module(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::WriteConfig | events::Type::ReadConfig => {
                match unsafe { enc_event.as_event_with_data() } {
                    Ok(e) => std::println!("{}", self.json_config_event(std_info, e)),
                    Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
                }
            }

            events::Type::FileRename => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_file_rename(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::BpfProgLoad => match unsafe { enc_event.as_event_with_data() } {
                Ok(e) => std::println!("{}", self.json_bpf_prog_load(std_info, e)),
                Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
            },

            events::Type::Exit | events::Type::ExitGroup => {
                match unsafe { enc_event.as_event_with_data() } {
                    Ok(e) => std::println!("{}", self.json_exit(std_info, e)),
                    Err(e) => error!("failed to decode {} event: {:?}", i.etype, e),
                }
            }

            _ => {
                unimplemented!("event type not implemented")
            }
        }
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

            self.handle_event(&enc_evt).await;

            count -= 1;
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
                        match EncodedEvent::from_bytes(buf) {
                            Ok(dec) => {
                                let mut ep = event_proc.lock().await;

                                // we make sure here that only events for which we can grab info for
                                // are pushed to the pipe. It is simplifying the error handling process
                                // in sorting the pipe afterwards
                                if let Ok(info) = unsafe { dec.info_mut() } {
                                    info.batch = ep.batch;
                                } else {
                                    error!("failed to decode info");
                                    continue;
                                }

                                ep.pipe.push_back(dec);
                            }

                            Err(e) => error!("failed to decode event: {}", e),
                        };
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
//#[tokio::main(flavor = "multi_thread")]
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

    let btf = Btf::from_sys_fs()?;

    let current_kernel = KernelVersion::from_sys()?;

    // make possible probe selection in debug
    #[allow(unused_mut)]
    let mut en_probes: Vec<String> = vec![];
    #[cfg(debug_assertions)]
    if let Ok(enable) = std::env::var("PROBES") {
        enable.split(',').for_each(|s| en_probes.push(s.into()));
    }

    let mut programs = bpf
        .programs_mut()
        .map(|(name, p)| {
            let mut prog = compat::Program::from_program(name.to_string(), p);
            // disable debug probes by default
            if name.starts_with("debug.") {
                prog.disable();
            }
            (name.to_string(), prog)
        })
        .collect::<HashMap<String, compat::Program>>();

    programs.get_mut("execve.security_bprm_check").unwrap().prio = 0;

    programs.get_mut("execve.exit.bprm_execve").unwrap().prio = 20;
    programs
        .get_mut("execve.exit.bprm_execve")
        .unwrap()
        .set_compat(Some("5.9.0".try_into().unwrap()), None);

    programs.get_mut("syscalls.sys_exit_execve").unwrap().prio = 20;
    programs
        .get_mut("syscalls.sys_exit_execve")
        .unwrap()
        .set_compat(None, Some("5.9.0".try_into().unwrap()));
    programs
        .get_mut("syscalls.sys_exit_execveat")
        .unwrap()
        .set_compat(None, Some("5.9.0".try_into().unwrap()));

    // dns probes
    //programs.get_mut("dns.entry.sock_recvmsg").unwrap().prio = 90;
    //programs.get_mut("dns.exit.sock_recvmsg").unwrap().prio = 100;
    // bpf probes
    programs.get_mut("entry.security_bpf_prog").unwrap().prio = 90;
    programs.get_mut("exit.bpf_prog_load").unwrap().prio = 100;
    // fd_install
    programs.get_mut("fd.fd_install").unwrap().prio = 0;
    programs.get_mut("fd.entry.__fdget").unwrap().prio = 0;
    programs.get_mut("fd.exit.__fdget").unwrap().prio = 10;
    // mmap probe
    programs.get_mut("syscalls.sys_enter_mmap").unwrap().prio = 90;

    // we sort programs by their loading priority
    //programs.sort_unstable_by_key(|p| p.prio);
    let mut sorted: Vec<(String, compat::Program)> = programs.into_iter().collect();
    sorted.sort_unstable_by_key(|(_, p)| p.prio_by_prog());

    // generic program loader
    for (_, mut p) in sorted {
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

    //read_events(&mut bpf);
    EventProcessor::init(&mut bpf);

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    info!("Exiting...");

    Ok(())
}
