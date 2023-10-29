/*mod cache;
mod config;
mod info;
mod util;*/

use aya::maps::MapData;
use bytes::BytesMut;
use clap::Parser;
use env_logger::Builder;
use json::{object, JsonValue};
use kunai::info::{AdditionalFields, CorrInfo, ProcFsInfo, ProcFsTaskInfo, StdEventInfo};
use kunai::{cache, util};
use kunai_common::cgroup::Cgroup;
use kunai_common::config::{BpfConfig, Filter};
use kunai_common::events::{self, EncodedEvent, Event, *};
use kunai_common::inspect_err;

use log::LevelFilter;

use std::collections::{HashMap, VecDeque};

use std::io::Write;
use std::net::IpAddr;
use std::path::PathBuf;

use std::sync::mpsc::{channel, Receiver, SendError, Sender};
use std::sync::Arc;

use kunai::util::*;
use std::thread;
use users::get_current_uid;

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
use kunai::util::namespaces::unshare;

const PAGE_SIZE: usize = 4096;

macro_rules! format_ptr {
    ($value:expr) => {
        format!("{:p}", $value as *const u8)
    };
}

#[derive(Debug, Clone)]
struct CorrelationData {
    image: PathBuf,
    command_line: Vec<String>,
    resolved: HashMap<IpAddr, String>,
    container: Option<String>,
    info: CorrInfo,
}

impl CorrelationData {
    #[inline(always)]
    fn command_line_string(&self) -> String {
        self.command_line.join(" ")
    }

    fn free_memory(&mut self) {
        self.resolved = HashMap::new();
    }
}

struct EventProcessor {
    random: u32,
    hcache: cache::Cache,
    receiver: Receiver<EncodedEvent>,
    correlations: HashMap<u128, CorrelationData>,
    output: std::fs::File,
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
    fn container_type_from_ancestors(ancestors: Vec<String>) -> Option<String> {
        for a in ancestors {
            match a.as_str() {
                "/usr/bin/firejail" => return Some("firejail".into()),
                "/usr/bin/containerd-shim-runc-v2" => return Some("docker".into()),
                _ => {}
            };

            if a.starts_with("/snap/lxd/") && a.ends_with("/bin/lxd/") {
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

    pub fn init(config: Config, receiver: Receiver<EncodedEvent>) -> anyhow::Result<()> {
        let output = match config.output.as_str() {
            "stdout" => "/dev/stdout",
            "stderr" => "/dev/stderr",
            v => v,
        };

        let mut ep = Self {
            random: util::getrandom::<u32>().unwrap(),
            hcache: Cache::with_max_entries(10000),
            correlations: HashMap::new(),
            receiver,
            output: std::fs::OpenOptions::new()
                .append(true)
                .create(true)
                .open(output)?,
        };

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

        let ci = CorrInfo::from(ProcFsInfo::new(pi, ppi));

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
        let mut last_pid = -1;
        while let Some(cor) = self.correlations.get(&ck) {
            last_pid = cor.info.pid();

            ancestors.insert(0, cor.image.to_string_lossy().to_string());
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
    fn json_execve(&mut self, info: StdEventInfo, event: &ExecveEvent) -> JsonValue {
        let ancestors = self.get_ancestors(&info);

        let mnt_ns = event.info.process.namespaces.mnt;

        let mut data = object! {
            ancestors: ancestors.join("|"),
            parent_exe: self.get_parent_image(&info),
            command_line: event.data.argv.to_command_line(),
            exe: self.get_hashes_with_ns(mnt_ns, &event.data.executable),
        };

        // we check wether a script is being interpreted
        if event.data.executable != event.data.interpreter {
            data["interpreter"] = self
                .get_hashes_with_ns(mnt_ns, &event.data.interpreter)
                .into();
        }

        Self::json_event_info_ref(&info, data)
    }

    #[inline]
    fn json_clone(&mut self, info: StdEventInfo, event: &CloneEvent) -> JsonValue {
        let exe = event.data.executable.to_path_buf();
        let cmd_line = event.data.argv.to_command_line();

        let data = object! {
            exe: exe.to_string_lossy().as_ref(),
            command_line: cmd_line,
            flags: format!("0x{:08x}",event.data.flags),
        };

        Self::json_event_info_ref(&info, data)
    }

    #[inline]
    fn json_prctl(&mut self, info: StdEventInfo, event: &PrctlEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let opt = event.data.option;
        let opt_str = PrctlOption::try_from_uint(event.data.option)
            .and_then(|o| Ok(o.as_str().into()))
            .unwrap_or(format!("unknown({opt})"));

        let data = object! {
            exe: exe.to_string_lossy().as_ref(),
            command_line: cmd_line,
            option: opt_str,
            arg2: format!("0x{:x}", event.data.arg2),
            arg3: format!("0x{:x}", event.data.arg3),
            arg4: format!("0x{:x}", event.data.arg4),
            arg5: format!("0x{:x}", event.data.arg5),
            success: event.data.success,
        };

        Self::json_event_info_ref(&info, data)
    }

    #[inline]
    fn json_mmap_exec(&mut self, info: StdEventInfo, event: &MmapExecEvent) -> JsonValue {
        let filename = event.data.filename;
        let mnt_ns = event.info.process.namespaces.mnt;
        let mmapped_hashes = self.get_hashes_with_ns(mnt_ns, &filename);

        let ck = info.correlation_key();

        let exe = self.get_exe(ck);

        let data = object! {
            command_line: self.get_command_line(ck),
            exe: exe.to_string_lossy().as_ref(),
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
                    exe: exe.to_string_lossy().as_ref(),
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
    fn json_rw_event(&mut self, info: StdEventInfo, event: &ConfigEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        Self::json_event(
            info,
            object! {
                command_line: cmd_line,
                exe: exe.to_string_lossy().as_ref(),
                path: event.data.path.to_string(),
            },
        )
    }

    #[inline]
    fn json_mount_event(&mut self, info: StdEventInfo, event: &MountEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let mut data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().as_ref(),
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
            exe: exe.to_string_lossy().as_ref(),
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
    fn json_bpf_socket_filter(
        &mut self,
        info: StdEventInfo,
        event: &BpfSocketFilterEvent,
    ) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);

        let mut socket = object! {
            domain: event.data.socket_info.domain_to_string(),
        };
        socket["type"] = event.data.socket_info.type_to_string().into();

        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().as_ref(),
            socket: socket,
            filter: object!{
                md5: md5_data(event.data.filter.as_slice()),
                sha1: sha1_data(event.data.filter.as_slice()),
                sha256: sha256_data(event.data.filter.as_slice()),
                sha512: sha512_data(event.data.filter.as_slice()),
                len: event.data.filter_len, // size in filter sock_filter blocks
                size: event.data.filter.len(), // size in bytes
            },
            attached: event.data.attached,
        };

        Self::json_event(info, data)
    }

    #[inline]
    fn json_mprotect(&self, info: StdEventInfo, event: &MprotectEvent) -> JsonValue {
        let (exe, cmd_line) = self.get_exe_and_command_line(&info);
        let data = object! {
            command_line: cmd_line,
            exe: exe.to_string_lossy().as_ref(),
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
            exe: exe.to_string_lossy().as_ref(),
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
            exe: exe.to_string_lossy().as_ref(),
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
            ancestors: self.get_ancestors_string(&info),
            command_line: cmd_line,
            exe: exe.to_string_lossy().as_ref(),
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
            exe: exe.to_string_lossy().as_ref(),
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
            exe: exe.to_string_lossy().as_ref(),
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

        Self::json_event(info, data)
    }

    #[inline]
    fn handle_correlation_event(&mut self, info: StdEventInfo, event: &CorrelationEvent) {
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

        let mut container_type = Self::container_type_from_cgroup(&cgroup);

        if container_type.is_none() {
            let ancestors = self.get_ancestors(&info);
            container_type = Self::container_type_from_ancestors(ancestors);
        }

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

    #[inline(always)]
    fn output_json(&mut self, j: JsonValue) {
        writeln!(self.output, "{j}").expect("failed to write json event");
        std::io::stdout().flush().expect("failed to flush output");
    }

    fn handle_event(&mut self, enc_event: &mut EncodedEvent) {
        let i = unsafe { enc_event.info() }.unwrap();

        // we don't handle our own events
        if i.process.tgid as u32 == std::process::id() {
            debug!("skipping our event");
        }

        let pid = i.process.tgid;
        let ns = i.process.namespaces.mnt;
        if let Err(e) = self.hcache.cache_ns(pid, ns) {
            debug!("failed to cache namespace pid={pid} ns={ns}: {e}");
        }

        let std_info = self.build_std_event_info(*i);

        let etype = std_info.info.etype;

        match etype {
            events::Type::Execve | events::Type::ExecveScript => {
                match event!(enc_event, ExecveEvent) {
                    Ok(e) => {
                        // this event is used for correlation but cannot be processed
                        // asynchronously so we have to handle correlation here
                        self.handle_correlation_event(std_info.clone(), &CorrelationEvent::from(e));
                        // we have to rebuild std_info as it has it is uses correlation
                        // information
                        let std_info = self.build_std_event_info(*i);
                        let e = self.json_execve(std_info, e);
                        self.output_json(e);
                    }
                    Err(e) => error!("failed to decode {} event: {:?}", etype, e),
                }
            }

            events::Type::Clone => match event!(enc_event, CloneEvent) {
                Ok(e) => {
                    // this event is used for correlation but cannot be processed
                    // asynchronously so we have to handle correlation here
                    self.handle_correlation_event(std_info.clone(), &CorrelationEvent::from(e));
                    // we have to rebuild std_info as it has it is uses correlation
                    // information
                    let std_info = self.build_std_event_info(*i);
                    let e = self.json_clone(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::Prctl => match event!(enc_event, PrctlEvent) {
                Ok(e) => {
                    let e = self.json_prctl(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::MmapExec => match event!(enc_event, MmapExecEvent) {
                Ok(e) => {
                    let e = self.json_mmap_exec(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::MprotectExec => match event!(enc_event, MprotectEvent) {
                Ok(e) => {
                    let e = self.json_mprotect(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::Connect => match event!(enc_event, ConnectEvent) {
                Ok(e) => {
                    let e = self.json_connect(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::DnsQuery => match event!(enc_event, DnsQueryEvent) {
                Ok(e) => {
                    for e in self.json_dns_queries(std_info, e) {
                        self.output_json(e);
                    }
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::SendData => match event!(enc_event, SendEntropyEvent) {
                Ok(e) => {
                    let e = self.json_send_data(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::InitModule => match event!(enc_event, InitModuleEvent) {
                Ok(e) => {
                    let e = self.json_init_module(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::WriteConfig
            | events::Type::Write
            | events::Type::ReadConfig
            | events::Type::Read => match event!(enc_event, ConfigEvent) {
                Ok(e) => {
                    let e = self.json_rw_event(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::Mount => match event!(enc_event, MountEvent) {
                Ok(e) => {
                    let e = self.json_mount_event(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::FileRename => match event!(enc_event, FileRenameEvent) {
                Ok(e) => {
                    let e = self.json_file_rename(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::BpfProgLoad => match event!(enc_event, BpfProgLoadEvent) {
                Ok(e) => {
                    let e = self.json_bpf_prog_load(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::BpfSocketFilter => match event!(enc_event, BpfSocketFilterEvent) {
                Ok(e) => {
                    let e = self.json_bpf_socket_filter(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

            events::Type::Exit | events::Type::ExitGroup => match event!(enc_event, ExitEvent) {
                Ok(e) => {
                    let e = self.json_exit(std_info, e);
                    self.output_json(e);
                }
                Err(e) => error!("failed to decode {} event: {:?}", etype, e),
            },

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
    filter: Filter,
    stats: AyaHashMap<MapData, events::Type, u64>,
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
        let stats_map: AyaHashMap<_, events::Type, u64> =
            AyaHashMap::try_from(bpf.take_map(events::KUNAI_STATS_MAP).unwrap()).unwrap();

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
                let mut event = mut_event!(e, ExecveEvent).unwrap();
                if event.data.interpreter != event.data.executable {
                    event.info.etype = Type::ExecveScript
                }
            }
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
    /// only events that can be processed asynchronously should be passed through
    fn pass_through_events(&self, e: &EncodedEvent) {
        let i = unsafe { e.info() }.unwrap();

        match i.etype {
            Type::Execve | Type::ExecveScript => {
                let event = event!(e, ExecveEvent).unwrap();
                for e in HashEvent::all_from_execve(event) {
                    self.send_event(e).unwrap()
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

    fn read_events(er: &Arc<Mutex<Self>>, bpf: &mut Bpf, config: &Config) {
        // try to convert the PERF_ARRAY map to an AsyncPerfEventArray
        let mut perf_array =
            AsyncPerfEventArray::try_from(bpf.take_map(events::KUNAI_EVENTS_MAP).unwrap()).unwrap();

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
                            "some events have been lost in the way from kernel read={} lost={}: consider filtering out some events or increase the number of buffered events in configuration",
                            events.read, events.lost
                        );

                        {
                            let er = event_reader.lock().await;
                            for ty in events::Type::variants() {
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

    #[arg(short, long, action = clap::ArgAction::Count, help="Set verbosity level, repeat option for more verbosity.")]
    verbose: u8,

    #[arg(short, long)]
    silent: bool,
}

// todo: make single-threaded / multi-threaded available in configuration
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();
    let mut conf = Config {
        ..Default::default()
    };

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
        let conf = Config {
            ..Default::default()
        };
        println!("{}", conf.to_toml()?);
        return Ok(());
    }

    if let Some(conf_file) = cli.config {
        conf = Config::from_toml(std::fs::read_to_string(conf_file)?)?;
    }

    // command line superseeds configuration

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
