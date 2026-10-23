#![deny(unused_imports)]

use anyhow::anyhow;
use aya::maps::MapData;

use clap::builder::styling;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use env_logger::Builder;
use firo::Trigger;
use flate2::bufread::GzDecoder;
use fs_walk::WalkOptions;
use gene::rules::CompiledRule;
use gene::{Compiler, Engine};
use huby::ByteSize;
use kunai::containers::Container;
use kunai::events::{
    BpfProgLoadData, BpfProgTypeInfo, BpfSocketFilterData, CloneData, CommitCredsData, ConnectData,
    Creds, CredsTamperedData, DnsQueryData, ErrorData, EventInfo, ExecveData, ExitData, FileData,
    FileRenameData, FileScanData, FilterInfo, InitModuleData, KillData, KunaiEvent, LossData,
    MmapExecData, MprotectData, NetworkInfo, PrctlData, PtraceData, ScanResult, SendDataData,
    SockAddr, SocketInfo, TargetTask, TaskSection, UnlinkData, UserEvent, agent::AgentEventInfo,
};
use kunai::events::{IoUringOp, IoUringSqeData, StartData};
use kunai::info::{AdditionalInfo, ProcKey, StdEventInfo, TaskAdditionalInfo, TaskKey};
use kunai::ioc::IoC;
use kunai::kallsyms::KernelSymbols;
use kunai::util::uname::Utsname;
use kunai::util::uptime::Uptime;
use kunai::util::{
    ask_yes_no, get_current_uid, getrlimit, is_bpf_lsm_enabled, is_public_ip, kill, md5_data,
    setrlimit, sha1_data, sha256_data, sha512_data,
};

use kunai::yara::{Scanner, SourceCode};
use kunai::{cache, util};
use kunai_common::bpf_events::{
    self, DomainResponse, EbpfEvent, MAX_BPF_EVENT_SIZE, PrctlOption, Signal, TaskInfo, Type,
};
use kunai_common::config::Filter;
use kunai_common::consts::PF_KTHREAD;
use kunai_common::io_uring::io_uring_op;
use kunai_common::option::BpfOption;
use kunai_common::user_ns::{IdMap, UserNs};
use kunai_common::{creds, inspect_err, kernel};

use kunai::util::namespace::{Mnt, Namespace};
use kunai_macros::StrEnum;
use libc::{RLIM_INFINITY, RLIMIT_MEMLOCK};
use log::LevelFilter;
use lru_st::collections::LruHashSet;
use pure_magic::MagicDb;
use serde::{Deserialize, Serialize};

use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc::error::SendError;
use tokio::time::timeout;

use std::borrow::Cow;
use std::cmp::max;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};

use std::ffi::OsStr;
use std::fs::{self, DirBuilder, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::IpAddr;

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use std::str::FromStr;

use std::sync::Arc;

use std::time::Duration;
use std::{process, vec};

use aya::{Ebpf, maps::HashMap as AyaHashMap, maps::perf::PerfEventArray, util::online_cpus};

use aya::VerifierLogLevel;

use log::{debug, error, info, warn};

use tokio::sync::{Barrier, Mutex, mpsc};
use tokio::{task, time};

use kunai::cache::*;

use kunai::config::{self, Config};
use kunai::util::namespace::unshare;

use communityid::{Flow, Protocol};

mod process_table;
use process_table::{Process, ProcessTable, Processes, Task, task_is_dead};

const PAGE_SIZE: usize = 4096;
const KERNEL_IMAGE: &str = "kernel";
// largest event seen in real logs is ~1.8 KiB
const JSON_BUF_MAX_CAP: usize = 4 * 1024;

/// What execve and clone events carry to build a [`Process`] and its [`Task`].
struct ProcSeed<'a> {
    exe: &'a kunai_common::path::Path,
    argv: &'a kunai_common::buffer::Buffer<{ bpf_events::MAX_ARGV_SIZE }>,
    cgroup: &'a kunai_common::cgroup::Cgroup,
    nodename: Option<&'a bpf_events::Nodename>,
    // clone does not carry it: the child inherits its parent's namespace, or
    // a new one whose maps are not written yet
    user_ns: Option<&'a UserNs>,
}

impl ProcSeed<'_> {
    fn nodename(&self) -> Option<String> {
        let nn = self.nodename?;
        Some(
            core::ffi::CStr::from_bytes_until_nul(nn.as_slice())
                .ok()?
                .to_string_lossy()
                .to_string(),
        )
    }
}

impl<'a> From<&'a bpf_events::ExecveData> for ProcSeed<'a> {
    fn from(d: &'a bpf_events::ExecveData) -> Self {
        Self {
            exe: &d.executable,
            argv: &d.argv,
            cgroup: &d.cgroup,
            nodename: Some(&d.nodename),
            user_ns: Some(&d.user_ns),
        }
    }
}

impl<'a> From<&'a bpf_events::CloneData> for ProcSeed<'a> {
    fn from(d: &'a bpf_events::CloneData) -> Self {
        Self {
            exe: &d.executable,
            argv: &d.argv,
            cgroup: &d.cgroup,
            // nodename resolution might fail in clone
            nodename: (!d.nodename.is_empty()).then_some(&d.nodename),
            user_ns: None,
        }
    }
}

impl Processes {
    fn get_exe(&self, key: ProcKey) -> &Path {
        self.get(&key)
            .map(|t| t.image.as_path())
            .unwrap_or_else(|| Path::new("?"))
    }

    fn get_command_line(&self, key: ProcKey) -> Cow<'_, str> {
        self.get(&key)
            .map(|p| Cow::Borrowed(p.command_line.as_str()))
            .unwrap_or(Cow::Borrowed("?"))
    }

    fn get_exe_and_command_line(&self, i: &StdEventInfo) -> (&Path, Cow<'_, str>) {
        let ck = i.process_key();
        (self.get_exe(ck), self.get_command_line(ck))
    }

    fn get_task_ancestors(&self, i: &StdEventInfo) -> Vec<Cow<'_, str>> {
        self.get_all_ancestors(i.process_key(), 1)
    }

    fn get_parent_command_line(&self, i: &StdEventInfo) -> Cow<'_, str> {
        let ck = i.process_key();
        self.get(&ck)
            .and_then(|t| t.real_parent_key)
            .and_then(|ptk| self.get(&ptk))
            .map(|c| Cow::Borrowed(c.command_line.as_str()))
            .unwrap_or(Cow::Borrowed("?"))
    }

    fn get_parent_image(&self, i: &StdEventInfo) -> Cow<'_, str> {
        let ck = i.process_key();
        self.get(&ck)
            .and_then(|t| t.real_parent_key)
            .and_then(|ptk| self.get(&ptk))
            .map(|c| c.image.to_string_lossy())
            .unwrap_or(Cow::Borrowed("?"))
    }

    fn execve_event<'src>(
        &'src self,
        sink: &mut EventSink,
        info: &'src StdEventInfo,
        bpf_data: &bpf_events::ExecveData,
    ) -> UserEvent<'src, ExecveData<'src>> {
        let opt_mnt_ns = EventConsumer::task_mnt_ns(&info.bpf);

        let exe = sink.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&bpf_data.executable));

        let interpreter = if bpf_data.executable != bpf_data.interpreter {
            Some(sink.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&bpf_data.interpreter)))
        } else {
            None
        };

        let data = ExecveData {
            ancestors: self.get_task_ancestors(info),
            parent_command_line: self.get_parent_command_line(info),
            parent_exe: self.get_parent_image(info),
            command_line: self.get_command_line(info.process_key()),
            exe,
            interpreter,
        };

        UserEvent::new(data, info)
    }

    fn clone_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::CloneData,
    ) -> UserEvent<'src, CloneData<'src>> {
        let data = CloneData {
            ancestors: self.get_task_ancestors(info),
            exe: bpf_data.executable.to_path_buf().into(),
            command_line: self.get_command_line(info.process_key()),
            flags: bpf_data.flags,
        };
        UserEvent::new(data, info)
    }

    fn prctl_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::PrctlData,
    ) -> UserEvent<'src, PrctlData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let option = PrctlOption::try_from_uint(bpf_data.option)
            .map(|o| Cow::Borrowed(o.as_str()))
            .unwrap_or_else(|_| format!("unknown({})", bpf_data.option).into());

        let data = PrctlData {
            ancestors: self.get_task_ancestors(info),
            exe: exe.into(),
            command_line,
            option,
            arg2: bpf_data.arg2,
            arg3: bpf_data.arg3,
            arg4: bpf_data.arg4,
            arg5: bpf_data.arg5,
            success: bpf_data.success,
        };

        UserEvent::new(data, info)
    }

    fn commit_creds_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::CommitCredsData,
    ) -> UserEvent<'src, CommitCredsData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = CommitCredsData {
            ancestors: self.get_task_ancestors(info),
            exe: exe.into(),
            command_line,
            old: Creds::from_bpf_and_additions(bpf_data.old, &info.additional.task, false),
            new: Creds::from_bpf_and_additions(bpf_data.new, &info.additional.task, false),
        };

        UserEvent::new(data, info)
    }

    fn creds_tampered_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        baseline: creds::Creds,
    ) -> UserEvent<'src, CredsTamperedData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);
        // `baseline` carries the per-process values we previously recorded;
        // `info.task_info()` carries what the task is reporting right now.
        // A creds_tampered event is emitted precisely because the two differ
        // on at least one of (uid, gid, cap_effective).
        let actual = info.task_info();

        let data = CredsTamperedData {
            ancestors: self.get_task_ancestors(info),
            exe: exe.into(),
            command_line,
            actual: Creds::from_bpf_and_additions(actual.creds, &info.additional.task, false),
            expected: Creds::from_bpf_and_additions(baseline, &info.additional.task, false),
        };

        UserEvent::new(data, info).with_type(Type::CredsTampered)
    }

    fn file_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::FileData,
    ) -> UserEvent<'src, FileData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = FileData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            path: bpf_data.path.to_path_buf(),
        };

        UserEvent::new(data, info)
    }

    fn unlink_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::UnlinkData,
    ) -> UserEvent<'src, UnlinkData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = UnlinkData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            path: bpf_data.path.into(),
            success: bpf_data.success,
        };

        UserEvent::new(data, info)
    }

    fn bpf_prog_load_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::BpfProgData,
    ) -> UserEvent<'src, BpfProgLoadData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let mut data = BpfProgLoadData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            id: bpf_data.id,
            prog_type: BpfProgTypeInfo {
                id: bpf_data.prog_type,
                name: util::bpf::bpf_type_to_string(bpf_data.prog_type),
            },
            tag: hex::encode(bpf_data.tag),
            attached_func: bpf_data.attached_func_name.into(),
            name: bpf_data.name.into(),
            ksym: bpf_data.ksym.into(),
            bpf_prog: kunai::events::BpfProgInfo {
                md5: "?".into(),
                sha1: "?".into(),
                sha256: "?".into(),
                sha512: "?".into(),
                size: 0,
            },
            verified_insns: bpf_data.verified_insns.into(),
            loaded: bpf_data.loaded,
        };

        if let BpfOption::Some(h) = &bpf_data.hashes {
            data.bpf_prog.md5 = h.md5.into();
            data.bpf_prog.sha1 = h.sha1.into();
            data.bpf_prog.sha256 = h.sha256.into();
            data.bpf_prog.sha512 = h.sha512.into();
            data.bpf_prog.size = h.size;
        }

        UserEvent::new(data, info)
    }

    fn bpf_socket_filter_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::BpfSocketFilterData,
    ) -> UserEvent<'src, BpfSocketFilterData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = BpfSocketFilterData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            socket: SocketInfo::from(bpf_data.socket_info),
            filter: FilterInfo {
                md5: md5_data(bpf_data.filter.as_slice()),
                sha1: sha1_data(bpf_data.filter.as_slice()),
                sha256: sha256_data(bpf_data.filter.as_slice()),
                sha512: sha512_data(bpf_data.filter.as_slice()),
                len: bpf_data.filter_len, // size in filter sock_filter blocks
                size: bpf_data.filter.len(), // size in bytes
            },
            attached: bpf_data.attached,
        };

        UserEvent::new(data, info)
    }

    fn mprotect_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::MprotectData,
    ) -> UserEvent<'src, MprotectData<'src>> {
        let (exe, cmd_line) = self.get_exe_and_command_line(info);

        let data = MprotectData {
            ancestors: self.get_task_ancestors(info),
            command_line: cmd_line,
            exe: exe.into(),
            addr: bpf_data.start,
            prot: bpf_data.prot,
        };

        UserEvent::new(data, info)
    }

    fn init_module_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: &'src bpf_events::InitModuleData,
    ) -> UserEvent<'src, InitModuleData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = InitModuleData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            syscall: Cow::Borrowed(bpf_data.args.syscall_name()),
            module_name: Cow::Borrowed(bpf_data.name.as_str()),
            args: Cow::Borrowed(bpf_data.uargs.as_str()),
            loaded: bpf_data.loaded,
        };

        UserEvent::new(data, info)
    }

    fn file_rename_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::FileRenameData,
    ) -> UserEvent<'src, FileRenameData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = FileRenameData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            old: bpf_data.old_name.into(),
            new: bpf_data.new_name.into(),
        };

        UserEvent::new(data, info)
    }

    fn io_uring_sqe_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::IoUringSqeData,
    ) -> UserEvent<'src, IoUringSqeData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let opcode = io_uring_op::try_from_uint(bpf_data.opcode)
            .ok()
            .map(|o| o.as_str());

        let data = IoUringSqeData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            op: IoUringOp {
                code: bpf_data.opcode,
                name: String::from(opcode.unwrap_or("?")),
            },
        };

        UserEvent::new(data, info)
    }

    fn error_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::ErrorData,
    ) -> UserEvent<'src, ErrorData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let ti = info.task_info();
        // we always display a warning on stderr
        warn!(
            "comm={} pid={} tgid={} guuid={}: {}",
            ti.comm_str(),
            ti.pid,
            ti.tgid,
            ti.tg_uuid.into_uuid(),
            bpf_data.error.as_str(),
        );

        let data = ErrorData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            code: bpf_data.error as u64,
            message: String::from(bpf_data.error.as_str()),
        };

        UserEvent::new(data, info)
    }

    fn get_resolved<'s>(
        &'s self,
        global: &'s HashMap<IpAddr, String>,
        ip: IpAddr,
        i: &StdEventInfo,
    ) -> Cow<'s, str> {
        let ck = i.process_key();

        // we lookup in the local table
        if let Some(domain) = self
            .get(&ck)
            .and_then(|c| c.resolved.get(&ip).map(Cow::from))
        {
            return domain;
        }

        // we lookup in the global table
        if let Some(domain) = global.get(&ip) {
            return domain.into();
        }

        // default value
        "?".into()
    }

    fn kill_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::KillData,
        random: u32,
        target_tai: &'src TaskAdditionalInfo,
    ) -> UserEvent<'src, KillData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let signal = Signal::from_uint_to_string(bpf_data.signal);

        // we need to set uuid part of target task
        let mut target = bpf_data.target;
        target.set_uuid_random(random);

        // get the command line
        let tk = ProcKey::from(&target);

        let data = KillData {
            ancestors: self.get_task_ancestors(info),
            exe: exe.into(),
            command_line,
            signal,
            target: TargetTask {
                command_line: self.get_command_line(tk),
                exe: self.get_exe(tk).into(),
                task: TaskSection::from_task_info_with_addition(target, target_tai),
            },
        };

        UserEvent::new(data, info)
    }

    fn ptrace_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::PtraceData,
        random: u32,
        target_tai: &'src TaskAdditionalInfo,
    ) -> UserEvent<'src, PtraceData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        // we need to set uuid part of target task
        let mut target = bpf_data.target;
        target.set_uuid_random(random);

        // get the command line
        let tk = ProcKey::from(&target);

        let data = PtraceData {
            ancestors: self.get_task_ancestors(info),
            exe: exe.into(),
            command_line,
            mode: bpf_data.mode,
            target: TargetTask {
                command_line: self.get_command_line(tk),
                exe: self.get_exe(tk).into(),
                task: TaskSection::from_task_info_with_addition(target, target_tai),
            },
        };

        UserEvent::new(data, info)
    }

    fn mmap_exec_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::MmapExecData,
        sink: &mut EventSink,
    ) -> UserEvent<'src, kunai::events::MmapExecData<'src>> {
        let filename = bpf_data.filename;
        let opt_mnt_ns = EventConsumer::task_mnt_ns(&info.bpf);
        let mmapped_hashes = sink.get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&filename));

        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = kunai::events::MmapExecData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            mapped: mmapped_hashes,
        };

        UserEvent::new(data, info)
    }

    fn connect_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::ConnectData,
        glob_resolved: &HashMap<IpAddr, String>,
    ) -> UserEvent<'src, ConnectData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);
        let src: SockAddr = bpf_data.src.into();
        let dst: SockAddr = bpf_data.dst.into();

        let flow: Flow = Flow::new(
            Protocol::from(bpf_data.socket.proto as u8),
            src.ip,
            src.port,
            dst.ip,
            dst.port,
        );

        let data = ConnectData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            socket: SocketInfo::from(bpf_data.socket),
            src,
            dst: NetworkInfo {
                hostname: Some(self.get_resolved(glob_resolved, dst.ip, info).into()),
                ip: dst.ip,
                port: dst.port,
                public: is_public_ip(dst.ip),
                is_v6: dst.ip.is_ipv6(),
            },
            community_id: flow.community_id_v1(0).base64(),
            connected: bpf_data.connected,
        };

        UserEvent::new(data, info)
    }

    fn send_data_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::SendEntropyData,
        glob_resolved: &HashMap<IpAddr, String>,
    ) -> UserEvent<'src, SendDataData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);
        let dst: SockAddr = bpf_data.dst.into();
        let src: SockAddr = bpf_data.src.into();

        let flow = Flow::new(
            Protocol::from(bpf_data.socket.proto as u8),
            src.ip,
            src.port,
            dst.ip,
            dst.port,
        );

        let data = SendDataData {
            ancestors: self.get_task_ancestors(info),
            exe: exe.into(),
            command_line,
            socket: SocketInfo::from(bpf_data.socket),
            src: bpf_data.src.into(),
            dst: NetworkInfo {
                hostname: Some(self.get_resolved(glob_resolved, dst.ip, info).into()),
                ip: dst.ip,
                port: dst.port,
                public: is_public_ip(dst.ip),
                is_v6: dst.ip.is_ipv6(),
            },
            community_id: flow.community_id_v1(0).base64(),
            data_entropy: bpf_data.shannon_entropy(),
            data_size: bpf_data.real_data_size,
        };

        UserEvent::new(data, info)
    }

    fn dns_query_events<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::DnsQueryData,
        responses: Vec<DomainResponse>,
    ) -> Vec<UserEvent<'src, DnsQueryData<'src>>> {
        let mut out = vec![];
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let src: SockAddr = bpf_data.src.into();
        let dst: SockAddr = bpf_data.dst.into();
        let si = SocketInfo::from(bpf_data.socket);

        let community_id = Flow::new(
            // this is valid to cast as a u8
            Protocol::from(bpf_data.socket.proto as u8),
            src.ip,
            src.port,
            dst.ip,
            dst.port,
        )
        .community_id_v1(0)
        .base64();

        let ancestors = self.get_task_ancestors(info);

        for r in responses {
            let mut data = DnsQueryData::new();
            data.ancestors = ancestors.clone();
            data.command_line = command_line.clone();
            data.exe = exe.into();
            data.query = r.qname.clone();
            data.query_type = r.qtype;
            data.response = r.records;
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

            out.push(UserEvent::new(data, info));
        }

        out
    }

    fn exit_event<'src>(
        &'src self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::ExitData,
    ) -> UserEvent<'src, ExitData<'src>> {
        let (exe, command_line) = self.get_exe_and_command_line(info);

        let data = ExitData {
            ancestors: self.get_task_ancestors(info),
            command_line,
            exe: exe.into(),
            error_code: bpf_data.error_code,
        };

        UserEvent::new(data, info)
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
            hostname: fs::read_to_string("/etc/hostname")
                .map(|s| s.trim_end().to_string())
                .unwrap_or_else(|_| "?".into()),
            mount_ns: Mnt::from_pid(pid)
                .map_err(|e| anyhow!("cannot find mnt namespace of kunai: {e}"))?,
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
    GzipFile(Box<GzDecoder<BufReader<File>>>),
}

impl Input {
    fn from_file(f: fs::File) -> Self {
        Self::File(f)
    }

    fn from_gzip_file(f: File) -> Self {
        Self::GzipFile(Box::new(GzDecoder::new(BufReader::new(f))))
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
            Self::GzipFile(d) => d.read(buf),
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
    fn stdout() -> Self {
        Self::Stdout(std::io::stdout())
    }

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

/// State needed to scan, act on and print events, kept apart from
/// [`EventConsumer`] so that events borrowing process tracking state
/// can be processed while it is still borrowed.
struct EventSink<'s> {
    config: Config,
    json_buf: Vec<u8>,
    engine: gene::Engine,
    iocs: HashMap<String, u8>,
    caches: cache::Caches,
    killed_tasks: LruHashSet<uuid::Uuid>,
    output: Output,
    file_scanner: Option<Scanner<'s>>,
    magic_db: MagicDb,
    // used to check if we must generate FileScan events
    scan_events_enabled: bool,
}

struct EventConsumer<'s> {
    system_info: SystemInfo,
    filter: Filter,
    random: u32,
    table: ProcessTable,
    resolved: HashMap<IpAddr, String>,
    exited_tasks: u64,
    sink: EventSink<'s>,
}

/// True if `current` diverges from `baseline` and that divergence hasn't
/// already been reported as `last_reported`.
fn creds_diverged(
    baseline: creds::Creds,
    current: creds::Creds,
    last_reported: Option<creds::Creds>,
) -> bool {
    if baseline == current {
        return false;
    }
    !last_reported.is_some_and(|reported| reported == current)
}

impl EventSink<'_> {
    fn get_hashes_in_ns(&mut self, ns: Option<Mnt>, p: &cache::Path) -> Arc<Hashes> {
        if let Some(ns) = ns {
            match self.caches.get_hashes_in_ns(ns, p, &self.magic_db) {
                Ok(h) => h,
                Err(e) => {
                    let meta = FileMeta {
                        error: Some(format!("{e}")),
                        ..Default::default()
                    };
                    Arc::new(Hashes::with_meta(p.as_path().to_path_buf(), meta))
                }
            }
        } else {
            let meta = FileMeta {
                error: Some("unknown namespace".into()),
                ..Default::default()
            };
            Arc::new(Hashes::with_meta(p.as_path().to_path_buf(), meta))
        }
    }

    fn scan<T>(&mut self, event: &mut T) -> ScanResult
    where
        T: for<'e> KunaiEvent<'e>,
    {
        let mut scan_result = if !self.engine.is_empty() {
            match self.engine.scan(event) {
                Ok(sr) => ScanResult::from(sr),
                Err(b) => {
                    let (sr, e) = *b;
                    error!("event scanning error: {e}");
                    ScanResult::from(sr)
                }
            }
        } else {
            ScanResult::default()
        };

        // no need to scan for IoC if not necessary
        if !self.iocs.is_empty() {
            let iocs = event.iocs();

            let mut matching_iocs = iocs
                .iter()
                .flat_map(|ioc| {
                    self.iocs
                        .get_key_value(&ioc.to_string())
                        .map(|(i, s)| (i, *s))
                })
                .peekable();

            if matching_iocs.peek().is_some() {
                // we add ioc matching to the list of matching rules
                scan_result.update_iocs(matching_iocs);
            }
        }

        scan_result
    }

    fn handle_actions<T>(&mut self, event: &T, actions: &HashSet<String>, is_detection: bool)
    where
        T: for<'e> KunaiEvent<'e> + Serialize,
    {
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
                let guuid = event.info().task.guuid;
                // don't kill ourself: this check is redundant because kunai
                // events aren't supposed to arrive until here but it is a cheap test
                if pid as u32 != process::id() && !self.killed_tasks.contains(&guuid) {
                    // this is the kind of information we want to have
                    // at all time so we put this as a warning not to
                    // be disabled by the default logging policy
                    warn!("sending SIGKILL to PID={pid}");
                    if let Err(e) = kill(pid, libc::SIGKILL) {
                        error!("error sending SIGKILL to PID={pid}: {e}")
                    } else {
                        self.killed_tasks.insert(guuid);
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

    fn file_scan_event<'a, T>(
        &mut self,
        event: &'a T,
        ns: Mnt,
        p: &Path,
    ) -> UserEvent<'a, FileScanData>
    where
        T: for<'e> KunaiEvent<'e> + Serialize,
    {
        let cp = cache::Path::from(p.to_path_buf());
        // if the scanner is None, signatures stay at their (empty) default
        let (sigs, err) = match self.file_scanner.as_mut() {
            Some(s) => match self.caches.get_sig_in_ns(ns, &cp, s) {
                Ok((sigs, msg)) => (Some(sigs), msg),
                Err(e) => (None, Some(format!("{e}"))),
            },
            None => (None, None),
        };

        let mut data = FileScanData::from_hashes(self.get_hashes_in_ns(Some(ns), &cp));
        data.source_event = event.info().event.uuid;
        if let Some(sigs) = sigs {
            data.positives = sigs.len();
            data.signatures = sigs;
        }
        data.scan_error = err;

        let info = EventInfo::from_other_with_type(event.info().clone(), Type::FileScan);
        UserEvent::with_data_and_info(data, info)
    }

    fn action_scan_files<T>(&mut self, event: &T) -> anyhow::Result<()>
    where
        T: for<'e> KunaiEvent<'e> + Serialize,
    {
        // this check prevents infinite loop for FileScan events
        if event.info().event.id == Type::FileScan.id() {
            return Ok(());
        }

        let ns = match event.info().task.namespaces.mnt {
            Some(ns) => Mnt::from_inum(ns),
            None => return Err(anyhow!("namespace not found")),
        };

        for p in event
            .scannable_files()
            .iter()
            // we don't scan file paths being ?
            .filter(|p| p.as_ref() != Path::new("?"))
        {
            let mut event = self.file_scan_event(event, ns, p);
            // print a warning if a positive scan happens so that a trace
            // is kept in system logs
            if event.data.positives > 0 {
                warn!(
                    "file={} matches detection signatures={:?} triggered by event uuid={}",
                    p.to_string_lossy(),
                    event.data.signatures,
                    event.info().event.uuid,
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
                self.serialize_print(&event);
            }
        }

        Ok(())
    }

    fn serialize_print<T: Serialize>(&mut self, event: &T) -> bool {
        self.json_buf.clear();
        // a huge event must not pin its allocation for the whole run
        if self.json_buf.capacity() > JSON_BUF_MAX_CAP {
            self.json_buf.shrink_to(JSON_BUF_MAX_CAP);
        }

        match serde_json::to_writer(&mut self.json_buf, event) {
            Ok(()) => {
                self.json_buf.push(b'\n');
                self.output
                    .write_all(&self.json_buf)
                    .expect("failed to write json event");
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

    fn scan_and_print<T>(&mut self, event: &mut T) -> bool
    where
        T: for<'e> KunaiEvent<'e> + Serialize,
    {
        let mut printed = false;

        // default: we have neither rules nor iocs
        // to scan for so we print event
        if self.iocs.is_empty() && self.engine.is_empty() {
            return self.serialize_print(event);
        }

        // scan for iocs and filter/matching rules
        let sr = self.scan(event);
        if let Some(d) = sr.detection {
            let severity = d.severity;
            event.set_detection(d);

            // we print event only if needed
            printed = if severity >= self.config.scanner.min_severity {
                self.serialize_print(event)
            } else {
                false
            };

            // get_detection will always be false for filters
            if let Some(d) = event.get_detection() {
                self.handle_actions(event, &d.actions, true)
            }
        }
        if let Some(f) = sr.filter {
            event.set_filter(f);
            printed = self.serialize_print(event);
            if let Some(f) = event.get_filter() {
                self.handle_actions(event, &f.actions, false)
            }
        }

        printed
    }
}

impl EventConsumer<'_> {
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

                if let Some(parent) = path.parent()
                    && !parent.exists()
                {
                    // we only create parent directory
                    DirBuilder::new().mode(0o700).create(parent).map_err(|e| {
                        anyhow!("failed to create output directory {parent:?}: {e}")
                    })?;
                }

                let mut opts = firo::OpenOptions::new();

                opts.mode(0o600);

                if let Some(max_size) = config.output.max_size {
                    opts.max_size(max_size);
                }

                // we create optimal trigger and set it for the file rotation
                opts.opt_trigger(Trigger::from_options(
                    config.output.rotate_interval,
                    config.output.rotate_size,
                ));

                opts.compression(firo::Compression::Gzip)
                    .create_append(v)?
                    .into()
            }
        };
        Ok(out)
    }

    pub fn with_config(config: Config) -> anyhow::Result<Self> {
        // building up system information
        let system_info = SystemInfo::from_sys()?.with_host_uuid(config.host_uuid);

        let scan_events_enabled = config
            .events
            .iter()
            .any(|(&ty, e)| ty == Type::FileScan && e.is_enabled());

        let output = Self::prepare_output(&config)?;

        let filter = Filter::try_from(&config)?;

        let mut ep = Self {
            system_info,
            filter,
            random: util::getrandom::<u32>()?,
            table: ProcessTable::with_capacity(512),
            exited_tasks: 0,
            resolved: HashMap::new(),
            sink: EventSink {
                config,
                json_buf: Vec::new(),
                engine: Engine::new(),
                iocs: HashMap::new(),
                caches: Caches::with_max_entries(10000),
                killed_tasks: LruHashSet::with_max_entries(512),
                output,
                file_scanner: None,
                magic_db: magic_db::load().map_err(|e| anyhow!("failed to open magic-db: {e}"))?,
                scan_events_enabled,
            },
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
        for p in self.sink.config.scanner.yara.iter() {
            debug!("looking for yara rules in: {}", p.to_string_lossy());
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
        if files_loaded == 0 {
            return Ok(());
        }

        let scanner = Scanner::with_rules(c.build());
        if let Ok(mut s) = scanner.lock() {
            s.max_scan_size(FILE_SIZE_SCAN_LIMIT as usize);
        }
        self.sink.file_scanner = Some(scanner);

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
                .unwrap_or_else(|| String::from("unknown"));

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
                            let ty = Type::from_str(event_name).map_err(|_| {
                                anyhow!(
                                    "file={} rule={rule_name} parse error: unknown event name \
                                     {event_name}",
                                    rule_file.to_string_lossy()
                                )
                            })?;
                            -i64::from(ty as u32)
                        } else {
                            let ty = Type::from_str(event_name).map_err(|_| {
                                anyhow!(
                                    "file={} rule={rule_name} parse error: unknown event name \
                                     {event_name}",
                                    rule_file.to_string_lossy()
                                )
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
        if self.sink.config.scanner.rules.is_empty() {
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

        for p in self.sink.config.scanner.rules.clone().iter() {
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
                for t in tpl_wo.clone().walk(p) {
                    let p = t?;
                    info!("loading template: {}", p.to_string_lossy());
                    let reader = File::open(p)?;
                    compiler.load_templates_from_reader(reader)?;
                }

                // load rule files
                for r in rules_wo.clone().walk(p) {
                    self.load_kunai_rule_file(&mut compiler, r?)?;
                }
            }
        }

        Ok(compiler)
    }

    fn init_event_scanner(&mut self) -> anyhow::Result<()> {
        self.sink.engine = Engine::try_from(self.compile_kunai_rules()?)?;
        info!(
            "detection engine initialized rules={}",
            self.sink.engine.rules_count()
        );
        Ok(())
    }

    fn init_iocs(&mut self) -> anyhow::Result<()> {
        // loading iocs
        if self.sink.config.scanner.iocs.is_empty() {
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

        for p in self.sink.config.scanner.iocs.clone().iter() {
            if !p.exists() {
                error!(
                    "ioc file loader: no such file or directory {}",
                    p.to_string_lossy()
                )
            } else if p.is_file() {
                self.load_iocs(p)
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

        info!("number of IoCs loaded: {}", self.sink.iocs.len());

        Ok(())
    }

    fn load_iocs<P: AsRef<Path>>(&mut self, p: P) -> io::Result<()> {
        let p = p.as_ref();
        let f = io::BufReader::new(File::open(p)?);

        for line in f.lines() {
            let line = line?;
            let ioc: IoC = serde_json::from_str(&line)?;
            self.sink
                .iocs
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
            .table
            .processes
            .iter()
            .map(|(&k, v)| (k, v.real_parent_key))
            .collect::<Vec<(ProcKey, Option<ProcKey>)>>()
        {
            if let Some(parent) = pk {
                if let Some(t) = self.table.processes.get_mut(&tk) {
                    // trying to find container type in cgroups
                    t.container = self
                        .table
                        .tasks
                        .get(&t.leader)
                        .and_then(|l| Container::from_cgroups(&l.cgroups));
                    if t.container.is_some() {
                        // we don't need to do the ancestor's lookup
                        continue;
                    }
                }

                // lookup in ancestors
                // the borrow of processes must end before we update it
                let container =
                    Container::from_ancestors(&self.table.processes.get_all_ancestors(parent, 0));
                if let Some(c) = container {
                    self.table
                        .processes
                        .entry(tk)
                        .and_modify(|task| task.container = Some(c));
                }
            }
        }

        Ok(())
    }

    /// Same as what eBPF reads on execve. The maps list kernel ids
    /// as we read them from the initial user namespace.
    fn user_ns_from_procfs(p: &procfs::process::Process) -> Option<UserNs> {
        let id_map = |file: &str| -> Option<IdMap> {
            let path = format!("/proc/{}/{file}", p.pid);
            let map = fs::read_to_string(&path).ok()?.parse().ok();
            if map.is_none() {
                debug!("failed to parse {path}");
            }
            map
        };

        let inum = p.namespaces().ok()?.0.get(OsStr::new("user"))?.identifier;
        Some(UserNs {
            inum: inum as u32,
            uid_map: id_map("uid_map")?,
            gid_map: id_map("gid_map")?,
        })
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

        if self.table.processes.contains_key(&tk) {
            return Ok(());
        }

        let image = {
            if stat.flags & 0x200000 == 0x200000 {
                KERNEL_IMAGE.into()
            } else {
                p.exe().unwrap_or_else(|_| "?".into())
            }
        };

        // we gather cgroups
        let cgroups = p
            .cgroups()?
            .0
            .into_iter()
            .map(|cg| cg.pathname)
            .collect::<Arc<[String]>>();

        let user_ns =
            Self::user_ns_from_procfs(p).and_then(|ns| self.sink.caches.cache_user_ns(&ns));

        let leader = TaskKey::try_from(p)?;
        let mut threads = HashSet::new();

        // all threads must be registered, otherwise a leader exiting before
        // its siblings emit any event would leave the process seen as dead
        for t in p.tasks()?.flatten() {
            // threads may exit while we iterate
            let (Ok(stat), Ok(status), Ok(key)) = (t.stat(), t.status(), TaskKey::try_from(&t))
            else {
                continue;
            };

            // only the leader can be a zombie (other threads are reaped at once)
            self.table.track_procfs_task(
                &mut threads,
                key,
                stat.state,
                Task {
                    proc_key: tk,
                    tgid: p.pid,
                    pid: t.tid,
                    cgroups: Arc::clone(&cgroups),
                    nodename: None,
                    user_ns: user_ns.clone(),
                    expected_creds: creds::Creds {
                        uid: status.ruid,
                        gid: status.rgid,
                        euid: status.euid,
                        egid: status.egid,
                        suid: status.suid,
                        sgid: status.sgid,
                        fsuid: status.fuid,
                        fsgid: status.fgid,
                        cap_effective: status.capeff,
                        cap_permitted: status.capprm,
                        cap_inheritable: status.capinh,
                    },
                    reported_creds: None,
                    last_seen_alive: 0,
                },
            );
        }

        let task = Process {
            image,
            command_line: p
                .cmdline()
                .map(|c| c.join(" "))
                .unwrap_or_else(|_| "?".into()),
            pid: p.pid,
            leader,
            kthread: stat.flags & PF_KTHREAD == PF_KTHREAD,
            resolved: HashMap::new(),
            container: None,
            real_parent_key: parent_key,
            children: HashSet::new(),
            threads,
            parent_task_info: None,
            procfs: true,
            reparented: false,
        };

        self.table.processes.insert(tk, task);

        Ok(())
    }

    fn update_resolved(&mut self, ip: IpAddr, resolved: &str, i: &StdEventInfo) {
        // updating loopback resolution is not good
        if ip.is_loopback() {
            return;
        }

        let ck = i.process_key();

        // update local resolve table
        self.table.processes.get_mut(&ck).map(|c| {
            c.resolved
                .entry(ip)
                .and_modify(|r| *r = resolved.to_owned())
                .or_insert_with(|| resolved.to_owned())
        });

        // update global resolve table
        self.resolved
            .entry(ip)
            .and_modify(|r| *r = resolved.to_owned())
            .or_insert_with(|| resolved.to_owned());
    }

    fn mnt_ns_from_task(ti: &bpf_events::TaskInfo) -> Option<Mnt> {
        ti.namespaces.mnt.into_opt().map(Mnt::from_inum)
    }

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

    fn update_dns_resolved(&mut self, info: &StdEventInfo, responses: &[DomainResponse]) {
        for r in responses {
            for a in r.records.iter() {
                if let Ok(ip) = a.parse::<IpAddr>() {
                    self.update_resolved(ip, &r.qname, info);
                }
            }
        }
    }

    fn exit_cleanup(&mut self, info: &StdEventInfo) {
        let pk = info.process_key();
        let process_exited = self.table.untrack_task(
            info.task_info(),
            pk,
            matches!(info.bpf.etype, Type::ExitGroup),
        );

        if process_exited {
            self.on_process_exit(&pk);

            // we trigger some very specific cleanup
            if self.exited_tasks.is_multiple_of(1000) {
                self.sweep_stale_tasks(info.bpf.timestamp);
                let shadow_proc = self.find_shadow_procs();
                // we remove shadow processes
                self.table
                    .processes
                    .retain(|pk, _| !shadow_proc.contains(pk));
                self.table.shrink_to_cap();
            }

            self.exited_tasks = self.exited_tasks.wrapping_add(1);
        }
    }

    fn on_process_exit(&mut self, pk: &ProcKey) {
        self.sink.caches.untrack_mnt_ns(pk);

        if let Some(t) = self.table.processes.get(pk) {
            if !self.proc_has_running_descendent(pk) && !t.procfs {
                // if the task has no descendent and is not coming from procfs
                // we can remove it from the table.
                self.table.processes.remove(pk);
            } else {
                // the process has some running descendent, thus it needs to be
                // kept in the table to construct a sound ancestors list for descendent(s).
                // However we can free up some memory and tag the task as exited
                self.table.processes.entry(*pk).and_modify(|t| t.on_exit());
            }
        }
    }

    fn start_event<'src>(&self, info: &'src StdEventInfo) -> UserEvent<'src, StartData> {
        let mut data = StartData::new();

        // setting kunai related info
        data.kunai.version = env!("CARGO_PKG_VERSION").into();
        let self_exe = PathBuf::from("/proc/self/exe");
        data.kunai.exe = Hashes::from_path_ref(
            self_exe.clone().canonicalize().unwrap_or(self_exe),
            &self.sink.magic_db,
        );

        data.kunai.config.sha256 = self.sink.config.sha256().ok().unwrap_or_else(|| "?".into());

        // setting up uptime and boottime
        if let Ok(uptime) = Uptime::from_sys().inspect_err(|e| error!("failed to get uptime: {e}"))
        {
            data.system.uptime = Some(uptime.as_secs());
            data.system.boot_time = uptime.boot_time().ok();
        }

        // setting utsname info
        if let Ok(uts) = Utsname::from_sys() {
            data.system.sysname = uts.sysname().unwrap_or_else(|_| "?".into()).into();
            data.system.release = uts.release().unwrap_or_else(|_| "?".into()).into();
            data.system.version = uts.version().unwrap_or_else(|_| "?".into()).into();
            data.system.machine = uts.machine().unwrap_or_else(|_| "?".into()).into();
            data.system.domainname = uts.domainname().unwrap_or_else(|_| "?".into()).into();
        }

        UserEvent::new(data, info)
    }

    fn loss_event<'src>(
        &self,
        info: &'src StdEventInfo,
        bpf_data: bpf_events::LossData,
    ) -> UserEvent<'src, LossData> {
        UserEvent::new(LossData::from(&bpf_data), info)
    }

    // Lost exit events would otherwise keep tasks, and thus their process, alive
    // forever.
    fn sweep_stale_tasks(&mut self, now: u64) {
        for pk in self.table.sweep_stale_tasks(now, task_is_dead) {
            self.on_process_exit(&pk);
        }
    }

    // shadow processes are processes still in the hashmap but which have exited and
    // have all descendents exited. They are not useful anymore because they are not needed
    // to reconstruct ancestors.
    fn find_shadow_procs(&self) -> HashSet<ProcKey> {
        let mut no_running_desc = HashSet::with_capacity(self.table.processes.len());

        for pk in self
            .table
            .processes
            .iter()
            // we don't process collected from procfs
            .filter(|(_, p)| !p.procfs)
            // we don't want running processes
            .filter(|(_, p)| !p.is_alive())
            .map(|(k, _)| *k)
        {
            // if our parent has no running descendent we know we do too
            if let Some(rpk) = self
                .table
                .processes
                .get(&pk)
                .and_then(|p| p.real_parent_key)
                .as_ref()
                && no_running_desc.contains(rpk)
            {
                no_running_desc.insert(pk);
                continue;
            }

            if !self.proc_has_running_descendent(&pk) {
                no_running_desc.insert(pk);
            }
        }

        no_running_desc
    }

    fn proc_has_running_descendent(&self, pk: &ProcKey) -> bool {
        if let Some(p) = self.table.processes.get(pk) {
            for ck in p.children.iter() {
                if let Some(child) = self.table.processes.get(ck) {
                    // if we have one child that didn't exit
                    if child.is_alive() {
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

    // Takes the raw event info so that tables are updated before the
    // StdEventInfo of the event is built from them.
    fn on_execve(&mut self, i: &bpf_events::EventInfo, data: &bpf_events::ExecveData) {
        let seed = ProcSeed::from(data);
        let cgroups = self.update_task_from_seed(&i.process, &seed);

        // the process gets a new image, we start from scratch but
        // keep track of the real parent in case of zombie task
        let pk = ProcKey::from(&i.process);
        let old = self.table.untrack_exec_proc(pk);
        let parent_key = old
            .as_ref()
            .and_then(|p| p.real_parent_key)
            .unwrap_or_else(|| ProcKey::from(&i.parent));
        let parent_task_info = old.and_then(|p| p.parent_task_info).unwrap_or(i.parent);
        self.new_process(&i.process, &seed, &cgroups, parent_key, parent_task_info);
    }

    // Same as on_execve regarding raw event info.
    fn on_clone(&mut self, i: &bpf_events::EventInfo, data: &bpf_events::CloneData) {
        let seed = ProcSeed::from(data);
        let cgroups = self.update_task_from_seed(&i.process, &seed);

        // a new thread of a known process, track_task already registered it
        if self
            .table
            .processes
            .contains_key(&ProcKey::from(&i.process))
        {
            return;
        }
        // a fork, or a thread whose process we missed (lost events)
        self.new_process(
            &i.process,
            &seed,
            &cgroups,
            ProcKey::from(&i.parent),
            i.parent,
        );
    }

    fn resolve_cgroups(ti: &TaskInfo, seed: &ProcSeed) -> Vec<String> {
        let cgroup = seed.cgroup;

        // we encountered some cgroup parsing error in eBPF
        // so we need to resolve cgroup in userland
        match cgroup.error {
            BpfOption::None => vec![cgroup.to_string()],
            BpfOption::Some(_) => {
                if let Ok(cgroups) = procfs::process::Process::new(ti.pid).and_then(|p| p.cgroups())
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
                        ti.pid,
                        ti.tg_uuid.into_uuid().hyphenated()
                    );
                    // still get a chance to do something with cgroup
                    vec![cgroup.to_string()]
                }
            }
        }
    }

    /// Sets cgroups, nodename and user namespace of the emitting [`Task`] and
    /// returns its cgroups.
    fn update_task_from_seed(&mut self, ti: &TaskInfo, seed: &ProcSeed) -> Arc<[String]> {
        let tk = TaskKey::from(ti);
        let cgroups = Self::resolve_cgroups(ti, seed);

        // threads mostly share the leader's values, so we share its Arcs
        let leader = self
            .table
            .processes
            .get(&ProcKey::from(ti))
            .and_then(|p| self.table.tasks.get(&p.leader));
        let shared_cgroups = match leader {
            Some(l) if *l.cgroups == *cgroups => Arc::clone(&l.cgroups),
            _ => Arc::from(cgroups),
        };
        let nodename = seed.nodename();
        let shared_nodename = match leader.and_then(|l| l.nodename.as_ref()) {
            Some(n) if Some(n.as_ref()) == nodename.as_deref() => Some(Arc::clone(n)),
            _ => nodename.map(Arc::from),
        };
        let shared_user_ns = seed.user_ns.map(|ns| self.sink.caches.cache_user_ns(ns));

        let task = self.table.tasks.get_mut(&tk);
        debug_assert!(task.is_some(), "task must be tracked");
        if let Some(task) = task {
            task.cgroups = Arc::clone(&shared_cgroups);
            task.nodename = shared_nodename;
            // otherwise the inherited one is kept, see build_task_additional_info
            if let Some(user_ns) = shared_user_ns {
                task.user_ns = user_ns;
            }
        }
        shared_cgroups
    }

    fn new_process(
        &mut self,
        ti: &TaskInfo,
        seed: &ProcSeed,
        cgroups: &[String],
        parent_key: ProcKey,
        parent_task_info: TaskInfo,
    ) {
        let image = {
            if ti.is_kernel_thread() {
                KERNEL_IMAGE.into()
            } else {
                seed.exe.to_path_buf()
            }
        };

        let (command_line, opt_err) = seed.argv.to_argv();
        opt_err.inspect(|e| {
            error!(
                "utf8 decoding error while parsing argv for comm={} pid={} task={}: {e}",
                ti.comm_string(),
                ti.tgid,
                ti.tg_uuid.into_uuid()
            )
        });

        self.table.insert_process(
            ti,
            image,
            command_line.join(" "),
            cgroups,
            parent_key,
            parent_task_info,
        );
    }

    fn handle_hash_event(&mut self, info: StdEventInfo, bpf_data: bpf_events::HashData) {
        let opt_mnt_ns = Self::task_mnt_ns(&info.bpf);
        self.sink
            .get_hashes_in_ns(opt_mnt_ns, &cache::Path::from(&bpf_data.path));
    }

    fn build_task_additional_info(
        &mut self,
        mnt_ns: Mnt,
        ti: &bpf_events::TaskInfo,
    ) -> TaskAdditionalInfo {
        let host_ns = self.system_info.mount_ns;
        let mut tables = |ns: Mnt| {
            self.sink
                .caches
                .get_user_group_in_ns(ns)
                .inspect_err(|e| {
                    let mut ti = *ti;
                    // fixes the random part to have a searchable uuid for error investigation
                    ti.set_uuid_random(self.random);
                    // make this debug as it can be quite verbose in some cases
                    debug!(
                        "failed to get task guuid={} user/group in mnt_ns={}: {e}",
                        ti.tg_uuid.into_uuid(),
                        ns.inum
                    )
                })
                .unwrap_or_default()
        };

        let (users, groups) = tables(mnt_ns);
        let (host_users, host_groups) = if mnt_ns == host_ns {
            (users.clone(), groups.clone())
        } else {
            tables(host_ns)
        };

        // the task may have changed user namespace since its last execve or clone
        let user_ns = ti.namespaces.user.into_opt().and_then(|inum| {
            let caches = &mut self.sink.caches;
            self.table
                .task_user_ns(&TaskKey::from(ti), inum, |inum| caches.get_user_ns(inum))
        });

        TaskAdditionalInfo {
            users,
            groups,
            host_users,
            host_groups,
            user_ns,
        }
    }

    // Create tasks lazily, some never go through a clone
    // event (kernel threads, lost events). Exiting tasks must not be
    // resurrected, it would keep their process alive.
    fn track_task(&mut self, i: &bpf_events::EventInfo) {
        if matches!(i.etype, Type::Exit | Type::ExitGroup) {
            return;
        }
        self.table.track_task(&i.process, i.timestamp);
    }

    fn build_std_event_info(&mut self, i: bpf_events::EventInfo) -> StdEventInfo {
        let opt_mnt_ns = Self::task_mnt_ns(&i);

        let mut std_info = StdEventInfo::from_bpf(i, self.random);

        let tk = TaskKey::from(&i.process);

        let host = kunai::info::HostInfo {
            name: self.system_info.hostname.clone(),
            uuid: self.system_info.host_uuid,
        };

        let mut container = None;
        let mut task = None;
        let mut parent = None;

        if let Some(mnt_ns) = opt_mnt_ns {
            if mnt_ns != self.system_info.mount_ns {
                let t = self.table.processes.get(&std_info.process_key());
                container = Some(kunai::info::ContainerInfo {
                    name: self
                        .table
                        .tasks
                        .get(&tk)
                        .and_then(|t| t.nodename.as_deref())
                        .unwrap_or("?")
                        .into(),
                    ty: t.and_then(|cd| cd.container),
                });
            }
            // getting task additional info
            task = Some(self.build_task_additional_info(mnt_ns, &i.process));
        }

        // parent info must be derived after a possible re-parenting fix-up
        self.table.fixup_real_parent(&mut std_info);

        // getting user and group information for parent task
        if let Some(parent_ns) = Self::parent_mnt_ns(&std_info.bpf) {
            let pti = std_info.bpf.parent;
            parent = Some(self.build_task_additional_info(parent_ns, &pti));
        }

        std_info.with_additional_info(AdditionalInfo {
            host,
            container,
            task: task.unwrap_or_default(),
            parent: parent.unwrap_or_default(),
        })
    }

    fn cache_namespaces(&mut self, i: &bpf_events::EventInfo) {
        if let Some(t_mnt_ns) = Self::task_mnt_ns(i) {
            let pid = i.process.pid;
            // threads exiting after exit_group would track a dead process again
            let track = (!matches!(i.etype, Type::Exit | Type::ExitGroup))
                .then(|| ProcKey::from(&i.process));
            if let Err(e) = self.sink.caches.cache_mnt_ns(pid, t_mnt_ns, track) {
                debug!("failed to cache namespace pid={pid} ns={t_mnt_ns}: {e}");
            }
        }

        if let Some(p_mnt_ns) = Self::parent_mnt_ns(i) {
            let pid = i.parent.pid;
            let pk = ProcKey::from(&i.parent);
            // an already exited parent would never be untracked again and
            // would pin its namespace, the LRU takes care of those
            let track = self
                .table
                .processes
                .get(&pk)
                .is_some_and(|p| p.is_alive())
                .then_some(pk);
            if let Err(e) = self.sink.caches.cache_mnt_ns(pid, p_mnt_ns, track) {
                debug!("failed to cache namespace pid={pid} ns={p_mnt_ns}: {e}");
            }
        }
    }

    fn check_creds_baseline(&mut self, evt: &EbpfEvent) {
        if !self.filter.is_enabled(Type::CredsTampered) {
            return;
        }
        let info = evt.info();
        let tk = TaskKey::from(&info.process);
        // If we don't have a Task entry yet — silently no-op.
        let Some(task) = self.table.tasks.get(&tk) else {
            return;
        };
        let baseline = task.expected_creds;
        let current = info.process.creds;

        if !creds_diverged(baseline, current, task.reported_creds) {
            return;
        }

        let std_info = self.build_std_event_info(*info);
        let mut tampered = self
            .table
            .processes
            .creds_tampered_event(&std_info, baseline);
        self.sink.scan_and_print(&mut tampered);

        // we only keep track of what we reported so that we don't re-fire on
        // every subsequent event. The baseline is left untouched on purpose,
        // it must keep holding what commit_creds() last installed, otherwise
        // a single divergence poisons it and cascades into further events.
        if let Some(t) = self.table.tasks.get_mut(&tk) {
            t.reported_creds = Some(current);
        }
    }

    fn handle_event(&mut self, evt: EbpfEvent) {
        self.cache_namespaces(evt.info());
        self.track_task(evt.info());

        // check for credential tampering on every event except those which
        // cannot be compared against the baseline:
        //   - CommitCreds: refreshes the baseline, not compared against it
        //   - Execve:      commit_creds() just reported the real new creds
        //   - Clone:       carries the parent's creds, not this task's own
        //   - Hash:        copies an Execve/MmapExec event's info and skips
        //                  the ordered pipe (see pass_through_events()), so
        //                  it can race ahead of the commit_creds it depends on
        // For every other event the baseline must already match what the
        // task currently carries.
        if !matches!(
            evt,
            EbpfEvent::CommitCreds(_)
                | EbpfEvent::Execve(_)
                | EbpfEvent::Clone(_)
                | EbpfEvent::Hash(_)
        ) {
            self.check_creds_baseline(&evt);
        }

        match evt {
            EbpfEvent::Execve(e) => {
                self.on_execve(&e.info, &e.data);

                if self.filter.is_enabled(e.info.etype) {
                    let std_info = self.build_std_event_info(e.info);
                    let mut e =
                        self.table
                            .processes
                            .execve_event(&mut self.sink, &std_info, &e.data);

                    self.sink.scan_and_print(&mut e);
                }
            }

            EbpfEvent::Clone(e) => {
                self.on_clone(&e.info, &e.data);

                if self.filter.is_enabled(Type::Clone) {
                    let std_info = self.build_std_event_info(e.info);
                    let mut e = self.table.processes.clone_event(&std_info, e.data);
                    self.sink.scan_and_print(&mut e);
                }
            }

            EbpfEvent::Prctl(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.prctl_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Kill(e) => {
                let std_info = self.build_std_event_info(e.info);
                let target_tai = Self::mnt_ns_from_task(&e.data.target)
                    .map(|ns| self.build_task_additional_info(ns, &e.data.target))
                    .unwrap_or_default();
                let mut e =
                    self.table
                        .processes
                        .kill_event(&std_info, e.data, self.random, &target_tai);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Ptrace(e) => {
                let std_info = self.build_std_event_info(e.info);
                let target_tai = Self::mnt_ns_from_task(&e.data.target)
                    .map(|ns| self.build_task_additional_info(ns, &e.data.target))
                    .unwrap_or_default();
                let mut e =
                    self.table
                        .processes
                        .ptrace_event(&std_info, e.data, self.random, &target_tai);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::CommitCreds(e) => {
                let std_info = self.build_std_event_info(e.info);
                // update the creds baseline of the task that committed them, so
                // its next event doesn't incorrectly fire a creds_tampered event.
                // track_task created the task, so None is a bug.
                let t = self.table.tasks.get_mut(&TaskKey::from(&e.info.process));
                debug_assert!(t.is_some(), "commit_creds on untracked task");
                if let Some(t) = t {
                    t.expected_creds = e.data.new;
                    t.reported_creds = None;
                }
                let mut e = self.table.processes.commit_creds_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::MmapExec(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self
                    .table
                    .processes
                    .mmap_exec_event(&std_info, e.data, &mut self.sink);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Mprotect(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.mprotect_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Connect(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self
                    .table
                    .processes
                    .connect_event(&std_info, e.data, &self.resolved);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::DnsQuery(e) => {
                let std_info = self.build_std_event_info(e.info);
                // force typing here because of RA not detecting it properly
                let responses: Vec<DomainResponse> = e.data.domain_responses().unwrap_or_default();
                self.update_dns_resolved(&std_info, &responses);
                for e in self
                    .table
                    .processes
                    .dns_query_events(&std_info, e.data, responses)
                    .iter_mut()
                {
                    self.sink.scan_and_print(e);
                }
            }

            EbpfEvent::SendEntropy(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self
                    .table
                    .processes
                    .send_data_event(&std_info, e.data, &self.resolved);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::InitModule(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.init_module_event(&std_info, &e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::File(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.file_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Unlink(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.unlink_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::FileRename(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.file_rename_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::BpfProgLoad(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.bpf_prog_load_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::BpfSocketFilter(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self
                    .table
                    .processes
                    .bpf_socket_filter_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Exit(e) => {
                let std_info = self.build_std_event_info(e.info);
                // exit and exit_group will always reach consumer as they are used
                // to clean up the processes HashMap. So we need to check if we want
                // to display those only now.
                if self.filter.is_enabled(std_info.bpf.etype) {
                    let mut e = self.table.processes.exit_event(&std_info, e.data);
                    self.sink.scan_and_print(&mut e);
                }
                self.exit_cleanup(&std_info);
            }

            EbpfEvent::IoUringSqe(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.io_uring_sqe_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Error(e) => {
                let std_info = self.build_std_event_info(e.info);
                let mut e = self.table.processes.error_event(&std_info, e.data);
                self.sink.scan_and_print(&mut e);
            }

            EbpfEvent::Hash(e) => {
                let std_info = self.build_std_event_info(e.info);
                self.handle_hash_event(std_info, e.data);
            }

            EbpfEvent::Log(_) => {
                // only panic in debug
                #[cfg(debug_assertions)]
                panic!("log events should be processed earlier")
            }

            EbpfEvent::Start(e) => {
                let std_info = self.build_std_event_info(e.info);
                let se = self.start_event(&std_info);
                self.sink.serialize_print(&se);
            }

            EbpfEvent::Loss(e) => {
                let std_info = self.build_std_event_info(e.info);
                let evt = self.loss_event(&std_info, e.data);
                self.sink.serialize_print(&evt);
            }

            EbpfEvent::SysCoreResume(_) => { /*  just ignore it */ }

            EbpfEvent::UserNsMap(e) => {
                self.sink.caches.cache_user_ns(&e.data.user_ns);
            }
        }
    }
}

#[derive(Debug)]
struct Stats {
    read: u64,
    lost: u64,
    start: time::Instant,
}

impl Stats {
    fn new() -> Self {
        Self {
            read: 0,
            lost: 0,
            start: time::Instant::now(),
        }
    }

    fn update(&mut self, read: u64, lost: u64) {
        if self.is_empty() {
            self.start = time::Instant::now();
        }
        self.read = self.read.wrapping_add(read);
        self.lost = self.lost.wrapping_add(lost);
    }

    fn percent_loss(&self) -> f64 {
        self.lost as f64 * 100.0 / self.total() as f64
    }

    fn eps(&self) -> f64 {
        self.total() as f64
            / (time::Instant::now()
                .duration_since(self.start)
                .as_secs_f64())
    }

    fn total(&self) -> u64 {
        self.read.wrapping_add(self.lost)
    }

    fn is_empty(&self) -> bool {
        self.read == 0 && self.lost == 0
    }
}

struct EventProducer {
    config: Config,
    batch: u64,
    pipe: VecDeque<EbpfEvent>,
    sender: mpsc::Sender<EbpfEvent>,
    filter: Filter,
    ebpf_stats_map: AyaHashMap<MapData, Type, u64>,
    stats: Stats,
    ebpf_perf_array: PerfEventArray<MapData>,
    tasks: Vec<tokio::task::JoinHandle<Result<(), anyhow::Error>>>,
    stop: bool,
    agent_evt_info: AgentEventInfo,
    // flag to be set when the producer needs to reload
    reload: bool,
}

const fn optimal_page_count(page_size: usize, max_event_size: usize, n_events: usize) -> usize {
    // Aya's PerfBuffer expects a page_count being a power of two
    // this is something required by the linux kernel
    ((max_event_size * n_events) / page_size).next_power_of_two()
}

impl EventProducer {
    pub fn with_params(
        bpf: &mut Ebpf,
        config: Config,
        sender: mpsc::Sender<EbpfEvent>,
    ) -> anyhow::Result<Self> {
        let filter = (&config).try_into()?;
        let stats_map: AyaHashMap<_, Type, u64> = AyaHashMap::try_from(
            bpf.take_map(bpf_events::KUNAI_STATS_MAP)
                .expect("cannot take KUNAI_STATS_MAP"),
        )
        .map_err(|e| anyhow!("cannot convert KUNAI_STATS_MAP: {e}"))?;

        let perf_array = PerfEventArray::try_from(
            bpf.take_map(bpf_events::KUNAI_EVENTS_MAP)
                .expect("cannot take KUNAI_EVENTS_MAP"),
        )
        .map_err(|e| anyhow!("cannot convert KUNAI_EVENTS_MAP: {e}"))?;

        Ok(EventProducer {
            config,
            pipe: VecDeque::new(),
            batch: 0,
            sender,
            filter,
            ebpf_stats_map: stats_map,
            stats: Stats::new(),
            ebpf_perf_array: perf_array,
            agent_evt_info: AgentEventInfo::from_procfs()?,
            tasks: vec![],
            stop: false,
            reload: false,
        })
    }

    // Event ordering is a very important piece as it impacts on-host correlations.
    // Additionaly it is very useful as it guarantees events are printed/piped into
    // other tools in the damn good order.
    async fn process_piped_events(&mut self) -> Result<usize, SendError<EbpfEvent>> {
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
            .sort_unstable_by_key(|enc_evt| enc_evt.info().timestamp);

        let current_batch = self.batch.saturating_sub(1);

        while let Some(evt) = self.pipe.front() {
            let eb = evt.info().batch;
            // process all events but the current batch
            if eb >= current_batch {
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

    async fn send_event(&self, event: EbpfEvent) -> Result<(), SendError<EbpfEvent>> {
        self.sender.send(event).await
    }

    /// Set event batch number then pipe event
    fn pipe_event(&mut self, mut event: EbpfEvent) {
        event.set_batch(self.batch);
        self.pipe.push_back(event);
    }

    /// function used to pre-process some targetted events where time is critical and for which
    /// processing can be done in EventReader
    /// this function must return true if main processing loop has to pass to the next event
    /// after the call.
    fn process_time_critical(&mut self, e: &mut EbpfEvent) -> bool {
        match e {
            EbpfEvent::BpfProgLoad(e) => {
                // dumping eBPF program from userland
                match util::bpf::bpf_dump_xlated_by_id_and_tag(e.data.id, e.data.tag) {
                    Ok(insns) => {
                        let h = bpf_events::ProgHashes {
                            md5: md5_data(insns.as_slice()).try_into().unwrap(),
                            sha1: sha1_data(insns.as_slice()).try_into().unwrap(),
                            sha256: sha256_data(insns.as_slice()).try_into().unwrap(),
                            sha512: sha512_data(insns.as_slice()).try_into().unwrap(),
                            size: insns.len(),
                        };

                        e.data.hashes = BpfOption::Some(h);
                    }

                    Err(err) => {
                        if err.is_io_error_not_found() {
                            // It may happen that we do not manage to get program's metadata. This happens
                            // when programs gets loaded and very quickly unloaded. It seems a common
                            // practice to load a few eBPF instructions (Aya, Docker ...) to test eBPF features.
                            warn!(
                                "couldn't retrieve bpf program's metadata for event={}, it \
                                 probably got unloaded too quickly",
                                e.info.uuid.into_uuid().as_hyphenated()
                            );
                        } else {
                            error!(
                                "failed to retrieve bpf_prog instructions for event={}: {}",
                                e.info.uuid.into_uuid().as_hyphenated(),
                                err
                            );
                        }
                    }
                }
            }

            EbpfEvent::Log(e) => {
                match e.data.level {
                    bpf_events::log::Level::Info => info!("{}", e),
                    bpf_events::log::Level::Warn => warn!("{}", e),
                    bpf_events::log::Level::Error => error!("{}", e),
                }
                // we don't need to process such event further
                return true;
            }

            EbpfEvent::SysCoreResume(_) => {
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
    async fn pass_through_events(&self, e: &EbpfEvent) {
        match e {
            EbpfEvent::Execve(e) => {
                for e in bpf_events::HashEvent::all_from_execve(e) {
                    self.send_event(EbpfEvent::from(e))
                        .await
                        .expect("cannot send HashEvent to consumer");
                }
            }

            EbpfEvent::MmapExec(e) => {
                self.send_event(bpf_events::HashEvent::new(e.info, e.data.filename).into())
                    .await
                    .expect("cannot send MmapExecEvent to consumer");
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

        let event_producer = Arc::clone(&shared);

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
            let mut perf_array = shared
                .lock()
                .await
                .ebpf_perf_array
                .open(
                    cpu_id,
                    Some(optimal_page_count(
                        PAGE_SIZE,
                        MAX_BPF_EVENT_SIZE,
                        config.max_buffered_events as usize,
                    )),
                )
                .expect("cannot open perf event buffer");
            let event_producer = Arc::clone(&shared);
            let bar = Arc::clone(&barrier);
            let max_buffered_events = config.max_buffered_events as usize;

            // process each perf buffer in a separate task
            let t = task::spawn(async move {
                let mut queue = VecDeque::with_capacity(max_buffered_events);

                let timeout = time::Duration::from_millis(10);
                // serves as error display decision
                let mut last_lost_cnt = 0;
                // the barrier keeps readers in lockstep so this local counter
                // is the global round, unlike ep.batch which the leader may
                // not have updated yet when other readers start a new round
                let mut round = 0u64;

                loop {
                    let mut read_count = 0u64;
                    let mut lost_count = 0u64;

                    if perf_array.readable() {
                        perf_array.for_each(|event| match event {
                            aya::maps::perf::PerfEvent::Sample { head, tail } => {
                                if let Ok(evt) = EbpfEvent::from_sample(head, tail)
                                    .inspect_err(|e| error!("failed at decoding ebpf event: {e}"))
                                {
                                    queue.push_front(evt);
                                }

                                read_count += 1;
                            }
                            aya::maps::perf::PerfEvent::Lost { count } => {
                                lost_count += count;
                            }
                        });
                    }

                    // checking out lost events
                    if lost_count > 0 || read_count > 0 {
                        {
                            let mut ep = event_producer.lock().await;
                            // update event statistics
                            ep.stats.update(read_count, lost_count);
                            // borrow stats
                            let stats = &ep.stats;

                            // only show error in leader cpu if needed
                            if cpu_id == leader_cpu_id && stats.lost > last_lost_cnt {
                                // easy way to create a top most frequent
                                let mut tree = BTreeMap::new();
                                for ty in Type::variants() {
                                    if ty.is_configurable() {
                                        tree.insert(
                                            ep.ebpf_stats_map.get(&ty, 0).unwrap_or_default(),
                                            ty,
                                        );
                                    }
                                }
                                // take top 5 most frequent events
                                let top = tree
                                    .iter()
                                    .rev()
                                    .take(5)
                                    .map(|(c, t)| format!("{t}={c}"))
                                    .collect::<Vec<String>>()
                                    .join(", ");

                                error!(
                                    "some events have been lost in the way from kernel read={} \
                                     lost={} loss-ratio={:.2}% eps={:.2}: consider event \
                                     filtering out and/or increase the number of buffered events \
                                     in configuration. Filtering hints, most frequent events: \
                                     {top} ",
                                    stats.read,
                                    stats.lost,
                                    stats.percent_loss(),
                                    stats.eps()
                                );

                                // used to prevent borrow checker to
                                // kick in in next block
                                let lost = stats.lost;

                                // we pipe a data loss event to bubble up info in kunai logs
                                if let Ok(loss_evt) = ep
                                    .agent_evt_info
                                    .new_event_with_data(
                                        Type::Loss,
                                        bpf_events::LossData {
                                            read: stats.read,
                                            lost: stats.lost,
                                            eps: stats.eps(),
                                        },
                                    )
                                    .inspect_err(|e| {
                                        error!("failed to create data loss event: {e}")
                                    })
                                {
                                    // we pipe data loss event
                                    let mut loss_evt = EbpfEvent::from(loss_evt);
                                    loss_evt.set_batch(round);
                                    ep.pipe.push_back(loss_evt);
                                }

                                // update last_lost for future error display decision
                                last_lost_cnt = lost;
                                // drop producer
                            }
                        }
                    }

                    while let Some(mut evt) = queue.pop_back() {
                        let mut ep = event_producer.lock().await;

                        // we set the proper batch number
                        evt.set_batch(round);

                        // verify that we filter properly kunai events in eBPF
                        // eBPF logs are not filtered and may come from kunai
                        debug_assert!(
                            evt.info().etype == Type::Log
                                || evt.info().process.tgid as u32 != process::id(),
                            "kunai event should not reach userland"
                        );

                        // pre-processing events
                        // we eventually change event type in this function
                        // example: Execve -> ExecveScript if necessary
                        // when the function returns true event doesn't need to go further
                        if ep.process_time_critical(&mut evt) {
                            continue;
                        }

                        // passing through some events directly to the consumer
                        // this is mostly usefull for correlation purposes
                        ep.pass_through_events(&evt).await;

                        // we must get the event type here because we eventually changed it
                        // info_unchecked can be used here as we are sure info is valid
                        let etype = evt.info().etype;

                        // filtering out unwanted events but let Execve/Clone go as those are used
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

                        ep.pipe.push_back(evt);
                    }

                    // all threads wait here after some events have been collected
                    bar.wait().await;
                    round += 1;

                    // publishing completed rounds for the flush task, lagging is harmless
                    if cpu_id == leader_cpu_id {
                        event_producer.lock().await.batch = round;
                    }

                    // we break the loop if processor is stopped
                    if event_producer.lock().await.stop {
                        break;
                    }

                    if read_count == 0 {
                        time::sleep(timeout).await;
                    }

                    if queue.capacity() > max_buffered_events {
                        queue.shrink_to(max_buffered_events);
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
const DEFAULT_FILENAME: &str = "kunai";
const DEFAULT_CONFIG_DIR: &str = "/etc/kunai/";
const DEFAULT_INSTALL_DIR: &str = "/usr/bin";
const DEFAULT_LOG_DIR: &str = "/var/log/kunai";
const DEFAULT_UNIT_NAME: &str = "00-kunai";

fn default_unit_path() -> PathBuf {
    PathBuf::from("/lib/systemd/system").join(format!("{DEFAULT_UNIT_NAME}.service"))
}

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

    /// Prints all events
    #[arg(long)]
    all: bool,

    /// Benchmark scanning engine
    #[arg(long)]
    bench: bool,

    /// Detection/filtering rule file or directory. Directories are scanned for files with
    /// extensions: .kun, .kunai, .gen, .gene. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE|DIR")]
    rules: Option<Vec<PathBuf>>,

    /// File or directory containing IoC definitions (json line format). Directories are scanned
    /// for files with extension: .ioc. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE|DIR")]
    iocs: Option<Vec<PathBuf>>,

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
        if let Some(rules) = opt.rules {
            conf.scanner.rules = rules;
        }

        // supersedes configuration
        if let Some(iocs) = opt.iocs {
            conf.scanner.iocs = iocs;
        }

        // supersedes configuration
        if let Some(min_severity) = opt.min_severity {
            conf.scanner.min_severity = min_severity;
        }

        Ok(conf)
    }
}

#[derive(Debug, Parser, Clone)]
struct TestOpt {
    /// Paths to the rules we want to test
    #[arg(short, long, value_name = "PATH")]
    rules: Option<Vec<PathBuf>>,

    /// Paths to a test directory
    #[arg(short, long, value_name = "DIR")]
    test_dir: Vec<String>,

    /// Paths to files containing baseline activity logs
    #[arg(short, long, value_name = "PATH")]
    baseline: Vec<String>,

    /// The minimum severity a rule must have to trigger false-positive
    /// when running on baseline
    #[arg(short, long, default_value_t = 6)]
    min_severity_fp: u8,
}

impl From<TestOpt> for Config {
    fn from(opt: TestOpt) -> Self {
        let mut conf = Self::default();

        // supersedes configuration
        if let Some(rules) = opt.rules {
            conf.scanner.rules = rules;
        }

        conf
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

    /// Force Kunai eBPF probes loading by bypassing any panic due to load failure.
    #[arg(long)]
    force_load: bool,

    /// Exclude events by name (comma separated).
    #[arg(long)]
    exclude: Option<String>,

    /// Include events by name (comma separated). Supersedes any exclude filter.
    #[arg(long)]
    include: Option<String>,

    /// Increase the size of the buffer shared between eBPF probes and userland.
    #[arg(long)]
    max_buffered_events: Option<u16>,

    /// Set a maximum number of events per seconds and per CPU for file system events
    #[arg(long)]
    max_eps_fs: Option<u64>,

    /// Minimum amount of data sent to trigger a send_data event,
    /// set it to 0 to get all send_data events.
    #[arg(long)]
    send_data_min_len: Option<u64>,

    /// Detection/filtering rule file or directory. Directories are scanned for files with
    /// extensions: .kun, .kunai, .gen, .gene. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE|DIR")]
    rules: Option<Vec<PathBuf>>,

    /// File or directory containing IoC definitions (json line format). Directories are scanned
    /// for files with extension: .ioc. Supersedes configuration file.
    #[arg(short, long, value_name = "FILE|DIR")]
    iocs: Option<Vec<PathBuf>>,

    /// Yara rule file or directory. Directories are scanned for files with extensions: .yar, .yara.
    /// Supersedes configuration file.
    #[arg(short, long, value_name = "FILE|DIR")]
    yara: Option<Vec<PathBuf>>,

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
        if let Some(rules) = opt.rules {
            conf.scanner.rules = rules;
        }

        // supersedes configuration
        if let Some(iocs) = opt.iocs {
            conf.scanner.iocs = iocs;
        }

        // supersedes configuration
        if let Some(yara_rules) = opt.yara {
            conf.scanner.yara = yara_rules;
        }

        // supersedes configuration if true
        if opt.harden {
            conf.harden = opt.harden
        }

        // supersedes configuration if true
        if opt.force_load {
            conf.force_load = opt.force_load
        }

        // we want to increase max_buffered_events
        if let Some(max_buffered_events) = opt.max_buffered_events {
            conf.max_buffered_events = max_buffered_events;
        }

        // we want to increase max_buffered_events
        if let Some(max_eps_io) = opt.max_eps_fs {
            conf.max_eps_fs = Some(max_eps_io);
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
            if exclude.contains(&"all") {
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
            if include.contains(&"all") {
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

    /// Path to the configuration file
    #[arg(long, exclusive = true)]
    validate: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct InstallOpt {
    /// Install in harden mode. First verify that
    /// /sys/kernel/security/lsm contains bpf
    #[arg(long)]
    harden: bool,

    /// Set a custom installation directory
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_INSTALL_DIR))]
    install_dir: PathBuf,

    /// Log file where kunai logs will be written
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_LOG_DIR).join("events.log"))]
    log_file: PathBuf,

    /// Where to write the configuration file. Any intermediate directory
    /// will be created if needed.
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_CONFIG_DIR).join("config.yaml"))]
    config: PathBuf,

    /// Make a systemd unit installation
    #[arg(long)]
    systemd: bool,

    /// Install a systemd unit but do not enable it
    #[arg(short, long = "systemd-unit", default_value_os_t = default_unit_path())]
    unit: PathBuf,

    /// Enable Kunai unit (kunai will start at boot)
    #[arg(long)]
    enable_unit: bool,

    /// Overwrite existing files
    #[arg(short, long)]
    force: bool,
}

#[derive(Debug, Args)]
struct UninstallOpt {
    /// Path to the installed kunai binary
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_INSTALL_DIR).join(DEFAULT_FILENAME))]
    bin: PathBuf,

    /// Directory containing kunai configuration files
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_CONFIG_DIR))]
    config_dir: PathBuf,

    /// Directory containing kunai log files
    #[arg(long, default_value_os_t = PathBuf::from(DEFAULT_LOG_DIR))]
    log_dir: PathBuf,

    /// Path to the installed systemd service unit file
    #[arg(short, long = "systemd-unit", default_value_os_t = default_unit_path())]
    unit: PathBuf,

    /// Remove all kunai files including configuration and logs
    #[arg(long)]
    all: bool,

    /// Skip confirmation prompt before uninstallation
    #[arg(short, long)]
    force: bool,
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
    /// Install Kunai on the system
    Install(InstallOpt),
    /// Uninstall Kunai from the system
    /// Note: Default behaviour only removes the binary and service. Logs and configuration files are preserved.
    Uninstall(UninstallOpt),
    /// Run kunai with custom options
    Run(RunOpt),
    /// Replay logs into detection / filtering engine (useful to test rules and IoC based detection)
    Replay(ReplayOpt),
    /// Test kunai detection rules
    Test(TestOpt),
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

// Enum used to deserialize and process events for
// replay and test commands.
enum ReplayEvent {
    Execve(UserEvent<'static, ExecveData<'static>>),
    Clone(UserEvent<'static, CloneData<'static>>),
    Prctl(UserEvent<'static, PrctlData<'static>>),
    Kill(UserEvent<'static, KillData<'static>>),
    Ptrace(UserEvent<'static, PtraceData<'static>>),
    CommitCreds(UserEvent<'static, CommitCredsData<'static>>),
    CredsTampered(UserEvent<'static, CredsTamperedData<'static>>),
    MmapExec(UserEvent<'static, MmapExecData<'static>>),
    MprotectExec(UserEvent<'static, MprotectData<'static>>),
    Connect(UserEvent<'static, ConnectData<'static>>),
    DnsQuery(UserEvent<'static, DnsQueryData<'static>>),
    SendData(UserEvent<'static, SendDataData<'static>>),
    InitModule(UserEvent<'static, InitModuleData<'static>>),
    File(UserEvent<'static, FileData<'static>>),
    FileUnlink(UserEvent<'static, UnlinkData<'static>>),
    FileRename(UserEvent<'static, FileRenameData<'static>>),
    BpfProgLoad(UserEvent<'static, BpfProgLoadData<'static>>),
    BpfSocketFilter(UserEvent<'static, BpfSocketFilterData<'static>>),
    Exit(UserEvent<'static, ExitData<'static>>),
    IoUringSqe(UserEvent<'static, IoUringSqeData<'static>>),
    FileScan(UserEvent<'static, FileScanData>),
    Error(UserEvent<'static, ErrorData<'static>>),
    #[allow(dead_code)]
    Start(UserEvent<'static, StartData>),
    #[allow(dead_code)]
    Loss(UserEvent<'static, LossData>),
}

impl ReplayEvent {
    #[inline]
    fn scan(&mut self, c: &mut EventConsumer) -> ScanResult {
        match self {
            Self::Execve(u) => c.sink.scan(u),
            Self::Clone(u) => c.sink.scan(u),
            Self::Prctl(u) => c.sink.scan(u),
            Self::Kill(u) => c.sink.scan(u),
            Self::Ptrace(u) => c.sink.scan(u),
            Self::CommitCreds(u) => c.sink.scan(u),
            Self::CredsTampered(u) => c.sink.scan(u),
            Self::MmapExec(u) => c.sink.scan(u),
            Self::MprotectExec(u) => c.sink.scan(u),
            Self::Connect(u) => c.sink.scan(u),
            Self::DnsQuery(u) => c.sink.scan(u),
            Self::SendData(u) => c.sink.scan(u),
            Self::InitModule(u) => c.sink.scan(u),
            Self::File(u) => c.sink.scan(u),
            Self::FileUnlink(u) => c.sink.scan(u),
            Self::FileRename(u) => c.sink.scan(u),
            Self::BpfProgLoad(u) => c.sink.scan(u),
            Self::BpfSocketFilter(u) => c.sink.scan(u),
            Self::Exit(u) => c.sink.scan(u),
            Self::IoUringSqe(u) => c.sink.scan(u),
            Self::FileScan(u) => c.sink.scan(u),
            Self::Error(u) => c.sink.scan(u),
            // not scannable events
            Self::Start(_) | Self::Loss(_) => ScanResult::default(),
        }
    }

    #[inline]
    fn scan_and_print(&mut self, c: &mut EventConsumer) -> bool {
        match self {
            Self::Execve(u) => c.sink.scan_and_print(u),
            Self::Clone(u) => c.sink.scan_and_print(u),
            Self::Prctl(u) => c.sink.scan_and_print(u),
            Self::Kill(u) => c.sink.scan_and_print(u),
            Self::Ptrace(u) => c.sink.scan_and_print(u),
            Self::CommitCreds(u) => c.sink.scan_and_print(u),
            Self::CredsTampered(u) => c.sink.scan_and_print(u),
            Self::MmapExec(u) => c.sink.scan_and_print(u),
            Self::MprotectExec(u) => c.sink.scan_and_print(u),
            Self::Connect(u) => c.sink.scan_and_print(u),
            Self::DnsQuery(u) => c.sink.scan_and_print(u),
            Self::SendData(u) => c.sink.scan_and_print(u),
            Self::InitModule(u) => c.sink.scan_and_print(u),
            Self::File(u) => c.sink.scan_and_print(u),
            Self::FileUnlink(u) => c.sink.scan_and_print(u),
            Self::FileRename(u) => c.sink.scan_and_print(u),
            Self::BpfProgLoad(u) => c.sink.scan_and_print(u),
            Self::BpfSocketFilter(u) => c.sink.scan_and_print(u),
            Self::Exit(u) => c.sink.scan_and_print(u),
            Self::IoUringSqe(u) => c.sink.scan_and_print(u),
            Self::FileScan(u) => c.sink.scan_and_print(u),
            Self::Error(u) => c.sink.scan_and_print(u),
            // not scannable events
            Self::Start(_) | Self::Loss(_) => false,
        }
    }
}

impl TryFrom<serde_json::Value> for ReplayEvent {
    type Error = anyhow::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, anyhow::Error> {
        let name = value
            .get("info")
            .and_then(|info| info.get("event"))
            .and_then(|event| event.get("name"))
            .and_then(|name| name.as_str())
            .ok_or_else(|| anyhow!("failed to deserialize event"))?;

        macro_rules! event_enum {
            ($from:ty, $into:expr) => {{
                let name = String::from(name);
                let e = serde_json::from_value::<UserEvent<$from>>(value)
                    .map_err(|e| anyhow!("failed to deserialize event {name}: {e}"))?;

                Ok($into(e))
            }};
        }

        let t = Type::from_str(name).map_err(|e| anyhow!("{e}"))?;

        // exhaustive pattern matching so that we don't miss new events
        match t {
            Type::Execve | Type::ExecveScript => event_enum!(ExecveData, ReplayEvent::Execve),
            Type::Clone => event_enum!(CloneData, ReplayEvent::Clone),
            Type::Prctl => event_enum!(PrctlData, ReplayEvent::Prctl),
            Type::Kill => event_enum!(KillData, ReplayEvent::Kill),
            Type::Ptrace => event_enum!(PtraceData, ReplayEvent::Ptrace),
            Type::CommitCreds => event_enum!(CommitCredsData, ReplayEvent::CommitCreds),
            Type::CredsTampered => event_enum!(CredsTamperedData, ReplayEvent::CredsTampered),
            Type::MmapExec => event_enum!(MmapExecData, ReplayEvent::MmapExec),
            Type::MprotectExec => event_enum!(MprotectData, ReplayEvent::MprotectExec),
            Type::Connect => event_enum!(ConnectData, ReplayEvent::Connect),
            Type::DnsQuery => event_enum!(DnsQueryData, ReplayEvent::DnsQuery),
            Type::SendData => event_enum!(SendDataData, ReplayEvent::SendData),
            Type::InitModule => event_enum!(InitModuleData, ReplayEvent::InitModule),
            Type::WriteConfig
            | Type::Write
            | Type::ReadConfig
            | Type::Read
            | Type::WriteClose
            | Type::FileCreate => {
                event_enum!(FileData, ReplayEvent::File)
            }
            Type::FileUnlink => event_enum!(UnlinkData, ReplayEvent::FileUnlink),
            Type::FileRename => event_enum!(FileRenameData, ReplayEvent::FileRename),
            Type::BpfProgLoad => event_enum!(BpfProgLoadData, ReplayEvent::BpfProgLoad),
            Type::BpfSocketFilter => {
                event_enum!(BpfSocketFilterData, ReplayEvent::BpfSocketFilter)
            }
            Type::Exit | Type::ExitGroup => event_enum!(ExitData, ReplayEvent::Exit),
            Type::IoUringSqe => event_enum!(IoUringSqeData, ReplayEvent::IoUringSqe),
            Type::FileScan => event_enum!(FileScanData, ReplayEvent::FileScan),
            Type::Error => event_enum!(ErrorData, ReplayEvent::Error),
            Type::Start => event_enum!(StartData, ReplayEvent::Start),
            Type::Loss => event_enum!(LossData, ReplayEvent::Loss),

            // internal types
            Type::Unknown
            | Type::CacheHash
            | Type::Log
            | Type::EndConfigurable
            | Type::SyscoreResume
            | Type::UserNsMap
            | Type::Max => Err(anyhow!("event type={t} not handled")),
        }
    }
}

impl Command {
    fn test(o: TestOpt) -> anyhow::Result<()> {
        let conf = Config::from(o.clone());
        let mut c = EventConsumer::with_config(conf.stdout_output())?;
        let mut baselined = false;

        // we then test on baseline
        let wo = WalkOptions::new()
            .files()
            .extension("json")
            .extension("jsonl")
            // supports for gzipped content
            .ends_with(".json.gz")
            .ends_with(".jsonl.gz");

        let mut rule_names = c
            .sink
            .engine
            .compiled_rules()
            .iter()
            .filter(|r| r.is_detection() | r.is_filter())
            .map(|r| {
                (
                    String::from(r.name()),
                    (r.clone(), Ok::<_, anyhow::Error>(())),
                )
            })
            .collect::<HashMap<String, (CompiledRule, Result<(), anyhow::Error>)>>();

        let mut res = Ok(());

        // loop testing rules on test files
        for (rule_name, (rule, rule_res)) in rule_names.iter_mut() {
            // test the rule on a test file
            for tp in o.test_dir.iter().map(PathBuf::from) {
                // the test file must be named $RULE_NAME.json
                let test_file = tp.join(format!("{}.json", rule_name));

                if test_file.is_file() {
                    let reader = std::io::BufReader::new(Input::from_file(
                        fs::File::open(test_file)
                            .map_err(|e| anyhow!("failed to open test file: {e}"))?,
                    ));

                    let mut de = serde_json::Deserializer::from_reader(reader);

                    while let Ok(v) = serde_json::Value::deserialize(&mut de) {
                        let mut e = ReplayEvent::try_from(v.clone())?;
                        let sr = e.scan(&mut c);
                        if rule.is_detection() && !sr.contains_detection(rule_name) {
                            debug!(
                                "false negative for detection rule={} on event={v}",
                                rule_name
                            );
                            *rule_res = Err(anyhow!("detection rule has false negatives"));
                        }
                        if rule.is_filter() && !sr.contains_filter(rule.name()) {
                            debug!("false negative for filter rule={} on event={v}", rule_name);
                            *rule_res = Err(anyhow!("filter rule has false negatives"));
                        }
                    }
                } else {
                    *rule_res = Err(anyhow!("rule is untested"))
                }
            }
        }

        // we test the rules against baseline
        for tp in o.baseline.iter() {
            for f in wo.clone().walk(tp) {
                let bf = f.map_err(|e| anyhow!("failed to list baseline file: {e}"))?;

                let file = fs::File::open(&bf)
                    .map_err(|e| anyhow!("failed to open baseline file: {e}"))?;

                // we handle compressed files
                let input = {
                    if bf.extension() == Some(OsStr::new("gz")) {
                        Input::from_gzip_file(file)
                    } else {
                        Input::from_file(file)
                    }
                };

                let reader = std::io::BufReader::new(input);

                let mut de = serde_json::Deserializer::from_reader(reader);

                debug!("reading baseline file: {}", bf.to_string_lossy());

                while let Ok(v) = serde_json::Value::deserialize(&mut de) {
                    let mut e = ReplayEvent::try_from(v.clone())?;

                    let sr = e.scan(&mut c);
                    for (rule_name, (rule, rule_res)) in rule_names.iter_mut() {
                        if rule.severity() >= o.min_severity_fp && sr.contains_detection(rule_name)
                        {
                            debug!("false positive for rule={} on event={v}", rule_name);
                            *rule_res = Err(anyhow!("rule has false positives"));
                        }
                    }
                }

                baselined = true;
            }
        }

        // printing out rule testing output
        rule_names
            .iter()
            .for_each(|(rule_name, (_, rule_res))| match rule_res {
                Ok(_) => info!("rule={rule_name} test successful"),
                Err(e) => {
                    error!("rule={rule_name} {e}");
                    res = Err(anyhow!("test failure"))
                }
            });

        if !baselined {
            warn!("rules were not tested against any baseline")
        }

        res
    }

    fn replay(o: ReplayOpt) -> anyhow::Result<()> {
        let bench = o.bench;
        let all = o.all;
        let log_files = o.log_files.clone();
        let conf: Config = o.try_into()?;
        let mut kunai_scan_time = Duration::new(0, 0);
        let mut data_size = ByteSize::from_bytes(0);

        let mut c = EventConsumer::with_config(conf.stdout_output())?;
        for f in log_files {
            let reader = if f == "-" {
                std::io::BufReader::new(Input::from_stdin())
            } else {
                std::io::BufReader::new(Input::from_file(fs::File::open(f)?))
            };

            let mut de = serde_json::Deserializer::from_reader(reader);

            while let Ok(mut v) = serde_json::Value::deserialize(&mut de) {
                // we need to know the size of the data we scan to compute throughput
                if bench {
                    data_size += ByteSize::from_bytes(serde_json::to_string(&v)?.len() as u64);
                }

                // we remove any prior filter/detection sections
                if let serde_json::Value::Object(map) = &mut v {
                    map.remove("filter");
                    map.remove("detection");
                };

                let mut e = ReplayEvent::try_from(v.clone())?;
                if bench {
                    kunai_scan_time += time_it(|| {
                        let _ = e.scan(&mut c);
                    });
                } else if !e.scan_and_print(&mut c) && all {
                    println!("{v}");
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

        // we set RLIMIT_MEMLOCK programmatically otherwise kunai fails at starting
        // as a service on old kernels, even though securityfs has been set properly.
        // This is very likely because securityfs isn't mounted yet when kunai starts
        let mut rlimit =
            getrlimit(RLIMIT_MEMLOCK).map_err(|e| anyhow!("failed to get RLIMIT_MEMLOCK: {e}"))?;
        rlimit.rlim_cur = RLIM_INFINITY;
        rlimit.rlim_max = RLIM_INFINITY;
        setrlimit(RLIMIT_MEMLOCK, rlimit)
            .map_err(|e| anyhow!("failed to set RLIMIT_MEMLOCK: {e}"))?;

        let kernel_syms = KernelSymbols::from_sys()
            .map_err(|e| anyhow!("failed to build kernel symbols: {e}"))?;

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
            .on_thread_start(|| {
                unshare(libc::CLONE_FS).expect("cannot initialize thread with unshare(CLONE_FS)")
            })
            .enable_all()
            .build()
            .expect("cannot build tokio runtime");

        // we start event reader and event processor before loading the programs
        // if we load the programs first we might have some event lost errors
        let (sender, mut receiver) = mpsc::channel::<EbpfEvent>(512);

        // we start consumer
        let mut cons = EventConsumer::with_config(conf.clone())?;
        let mut cons_task = runtime.spawn(async move {
            #[cfg(debug_assertions)]
            let mut last_ts = 0;
            #[cfg(debug_assertions)]
            let mut hist = vec![];
            #[cfg(debug_assertions)]
            let mut last_batch = 0;

            while let Some(evt) = receiver.recv().await {
                // this is a debug_assertion testing that events arrive in
                // the order they were generated in eBPF. At this time
                // encoded event's timestamp is the one generated in eBPF
                #[cfg(debug_assertions)]
                {
                    let info = evt.info();
                    // we skip correlation (passe through events)
                    if !matches!(info.etype, Type::CacheHash) {
                        let evt_ts = info.timestamp;
                        let batch = info.batch;
                        debug_assert!(
                            evt_ts >= last_ts,
                            "last={last_ts} (batch={last_batch}) > current={evt_ts} \
                             (batch={batch}) event={}",
                            info.etype.as_str()
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

                cons.handle_event(evt);
            }

            Ok::<(), anyhow::Error>(())
        });

        runtime.block_on(async move {
            // we spawn a task to reload producer when needed
            let main = async move {
                loop {
                    info!("Starting event producer");
                    // we start producer
                    let mut bpf = kunai::prepare_bpf(current_kernel, &kernel_syms, &conf, vll)?;
                    let mut prod =
                        EventProducer::with_params(&mut bpf, conf.clone(), sender.clone())?;

                    // we create and pipe a start event
                    if let Ok(start) = prod
                        .agent_evt_info
                        .new_event_with_data(Type::Start, ())
                        .inspect_err(|e| error!("failed at generating start event: {e}"))
                    {
                        prod.pipe_event(EbpfEvent::Start(Box::new(start)));
                    }

                    let arc_prod = prod.produce().await;

                    // we load and attach bpf programs
                    kunai::load_and_attach_bpf(&conf, &kernel_syms, current_kernel, &mut bpf)?;

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

            // SIGTERM (e.g. systemctl stop) must end like Ctrl-C so that
            // Drop runs and buffered output gets flushed
            let mut sigterm = signal(SignalKind::terminate())?;

            info!("Waiting for Ctrl-C...");
            tokio::select! {
                _ = tokio::signal::ctrl_c() => Ok(()),
                _ = sigterm.recv() => Ok(()),
                res = main => res
            }
        })
    }

    fn run(opt_ro: Option<RunOpt>, vll: VerifierLogLevel) -> anyhow::Result<()> {
        // checking that we are running as root
        if get_current_uid() != 0 {
            return Err(anyhow::Error::msg(
                "root privileges are required to monitor system events (default behavior). Some \
                 commands do not require root. Use 'kunai help' to see available commands.",
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
            let conf = Config::default();
            // do not use println because to_string already includes a
            // trailing newline. Using print! allow one to easily compute
            // config hash as the one found in start event.
            print!("{}", serde_yaml::to_string(&conf)?);
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

        if let Some(p) = co.validate {
            EventConsumer::with_config(
                serde_yaml::from_str(
                    &std::fs::read_to_string(p)
                        .map_err(|e| anyhow!("failed at reading configuration: {e}"))?,
                )
                .map_err(|e| anyhow!("failed at deserializing YAML configuration: {e}"))?,
            )
            .map_err(|e| anyhow!("failed at initializing event consumer: {e}"))?;
        }

        Ok(())
    }

    fn run_command(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
        let output = process::Command::new(cmd).args(args).output()?;

        if !output.status.success() {
            std::io::stdout().write_all(&output.stderr)?;
            std::io::stderr().write_all(&output.stderr)?;
            return Err(anyhow::format_err!(
                "command failed: {cmd} {}",
                args.join(" ")
            ));
        }

        Ok(())
    }

    fn systemd_install(
        o: &InstallOpt,
        install_bin: &Path,
        config_path: &Path,
    ) -> anyhow::Result<()> {
        // we proceed with systemd installation
        let unit_path = &o.unit;
        let unit_name = unit_path
            .file_name()
            .ok_or_else(|| anyhow!("unknown unit name: {}", unit_path.to_string_lossy()))?
            .to_string_lossy();
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
            harden = o.harden,
            install_bin = install_bin.to_string_lossy(),
            config_path = config_path.to_string_lossy(),
        );

        let mut overwrite_unit = !unit_path.exists();

        if unit_path.exists() && !o.force {
            overwrite_unit = ask_yes_no(
                "Systemd unit file already exists, do you want to overwrite it?",
                false,
            )?;
        }

        if unit_path.exists() {
            println!("Stopping existing kunai service");
            Self::run_command("systemctl", &["stop", &unit_name])?;
        }

        if overwrite_unit || o.force {
            println!(
                "Writing systemd unit file to: {}",
                unit_path.to_string_lossy()
            );
            fs::write(unit_path, unit)?;
        } else {
            return Ok(());
        }

        // we want to enable systemd unit
        if o.enable_unit {
            let unit_name = unit_path
                .file_name()
                .ok_or_else(|| anyhow!("unknown unit name: {}", unit_path.to_string_lossy()))?
                .to_string_lossy();
            println!("Enabling kunai systemd unit");
            // we first need to run daemon-reload because we added a new unit
            Self::run_command("systemctl", &["daemon-reload"])?;
            // then we can enable the unit
            Self::run_command("systemctl", &["enable", &unit_name])?;
        }

        Ok(())
    }

    fn install(o: InstallOpt) -> anyhow::Result<()> {
        let current_kernel = Utsname::kernel_version()
            .map_err(|e| anyhow!("cannot retrieve kernel version: {e}"))?;
        let log_path = &o.log_file;
        let log_dir = log_path.parent().ok_or_else(|| {
            anyhow!(
                "cannot find dirname for log path: {}",
                log_path.to_string_lossy()
            )
        })?;

        // checks on harden mode
        if o.harden {
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

        let config_path = &o.config;
        let config_dir = config_path.parent().ok_or_else(|| {
            anyhow!(
                "cannot find dirname for config path: {}",
                config_path.to_string_lossy()
            )
        })?;
        println!(
            "Creating configuration directory: {}",
            config_dir.to_string_lossy()
        );
        // we create the directory where to store configuration
        fs::create_dir_all(config_dir)?;

        // create configuration for installation
        let conf = Config::default().harden(o.harden).output(config::Output {
            path: log_path.to_string_lossy().to_string(),
            rotate_size: Some(huby::ByteSize::from_mb(10)),
            rotate_interval: Some(Duration::from_mins(15)),
            max_size: Some(huby::ByteSize::from_gb(1)),
            buffered: false,
        });

        let mut overwrite_config = !config_path.exists();
        // we write configuration file
        if config_path.exists() && !o.force {
            overwrite_config = ask_yes_no(
                "Configuration file already exists, do you want to overwrite it?",
                false,
            )?;
        }

        if overwrite_config || o.force {
            println!(
                "Writing configuration file: {}",
                config_path.to_string_lossy()
            );
            fs::write(config_path, serde_yaml::to_string(&conf)?)?;
        }

        // we read our own binary
        let self_bin = fs::read("/proc/self/exe")?;
        let install_bin = PathBuf::from(&o.install_dir).join(DEFAULT_FILENAME);
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

        if !o.systemd {
            return Ok(());
        }

        Self::systemd_install(&o, &install_bin, config_path)
    }

    fn uninstall(o: UninstallOpt) -> anyhow::Result<()> {
        let mut to_rm = vec![&o.bin];
        let unit_name = o
            .unit
            .file_name()
            .map(|s| s.to_string_lossy())
            .unwrap_or_default();

        if o.all {
            to_rm.push(&o.config_dir);
            to_rm.push(&o.log_dir);
        }

        to_rm.push(&o.unit);

        println!("Following files and directory will be deleted: ");
        for p in to_rm.iter() {
            if p.exists() {
                println!("\t{}", p.to_string_lossy())
            }
        }

        if o.unit.exists() {
            println!(
                "Following service will be stopped and uninstalled: {} -> {}",
                unit_name,
                o.unit.to_string_lossy()
            );
        }

        if !o.force {
            println!("\nThis action cannot be undone.");
            print!("Do you want to continue? [y/N] ");
            std::io::stdout().flush()?;

            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;

            if !input.trim().eq_ignore_ascii_case("y") {
                println!("Uninstall cancelled.");
                return Ok(());
            }
        }

        // if any we must stop service first
        if o.unit.exists() {
            println!("Uninstall systemd service: {}", unit_name);

            // stop and disable unit
            Self::run_command("systemctl", &["stop", &unit_name])?;
            Self::run_command("systemctl", &["disable", &unit_name])?;

            // delete unit file
            let _ =
                fs::remove_file(&o.unit).inspect_err(|e| error!("failed to remove unit file: {e}"));

            // leave systemd in a consistent state
            // Note: error does not abort uninstall process
            let _ =
                Self::run_command("systemctl", &["daemon-reload"]).inspect_err(|e| error!("{e}"));
        }

        // we finally delete files / directories
        for p in to_rm.iter() {
            println!("removing: {}", p.to_string_lossy());
            if p.is_dir() {
                fs::remove_dir_all(p).map_err(|e| {
                    anyhow!("failed to delete directory {}: {e}", p.to_string_lossy())
                })?;
            } else if p.is_file() {
                fs::remove_file(p)
                    .map_err(|e| anyhow!("failed to delete file {}: {e}", p.to_string_lossy()))?;
            }
        }

        Ok(())
    }

    fn logs(o: LogsOpt) -> anyhow::Result<()> {
        let output = o.log_file.unwrap_or({
            let config: Config = serde_yaml::from_reader(
                File::open(o.config).map_err(|e| anyhow!("failed to read config file: {e}"))?,
            )
            .map_err(|e| anyhow!("failed to parse config file: {e}"))?;

            PathBuf::from(config.output.path)
        });

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
        Some(Command::Uninstall(o)) => Command::uninstall(o),
        Some(Command::Config(o)) => Command::config(o),
        Some(Command::Replay(o)) => Command::replay(o),
        Some(Command::Test(o)) => Command::test(o),
        Some(Command::Logs(o)) => Command::logs(o),
        Some(Command::Run(o)) => Command::run(Some(o), verifier_level),
        None => Command::run(None, verifier_level),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn creds(uid: u32) -> creds::Creds {
        creds::Creds {
            uid,
            ..Default::default()
        }
    }

    #[test]
    fn no_divergence_never_fires() {
        assert!(!creds_diverged(creds(0), creds(0), None));
        assert!(!creds_diverged(creds(0), creds(0), Some(creds(1000))));
    }

    #[test]
    fn new_divergence_fires_when_nothing_reported_yet() {
        assert!(creds_diverged(creds(0), creds(1000), None));
    }

    #[test]
    fn same_divergence_does_not_refire() {
        assert!(!creds_diverged(creds(0), creds(1000), Some(creds(1000))));
    }

    #[test]
    fn different_divergence_fires_again() {
        // previously reported uid=1000, task has since drifted to uid=1001:
        // a new divergence, must fire even though one was already reported
        assert!(creds_diverged(creds(0), creds(1001), Some(creds(1000))));
    }

    #[test]
    fn reported_value_equal_to_baseline_still_fires() {
        // last_reported happens to equal the baseline itself (not current):
        // still a live divergence, must fire
        assert!(creds_diverged(creds(0), creds(1000), Some(creds(0))));
    }
}
