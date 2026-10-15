use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;

use kunai::containers::Container;
use kunai::info::{KeyError, ProcKey, StdEventInfo, TaskKey};
use kunai_common::bpf_events::TaskInfo;
use kunai_common::creds;

const MAX_ANCESTORS: usize = 1024;

/// Per-process state (a thread group in kernel terms).
#[derive(Debug, Clone)]
pub(crate) struct Process {
    pub(crate) image: PathBuf,
    pub(crate) command_line: String,
    pub(crate) pid: i32,
    pub(crate) leader: TaskKey,
    // PF_KTHREAD is uniform across a process
    pub(crate) kthread: bool,
    pub(crate) resolved: HashMap<IpAddr, String>,
    pub(crate) container: Option<Container>,
    // ProcKey rather than TaskKey because the kernel silently re-parents
    // children to a sibling thread when the parent thread exits.
    pub(crate) real_parent_key: Option<ProcKey>,
    // children processes
    pub(crate) children: HashSet<ProcKey>,
    // keys of the threads of this process
    pub(crate) threads: HashSet<TaskKey>,
    // last parent task info seen before a re-parenting, reported in place of
    // the new parent once re-parented
    pub(crate) parent_task_info: Option<TaskInfo>,
    // flag telling if this process comes from procfs
    // parsing at kunai start
    pub(crate) procfs: bool,
    // set when the stored parent differs from the one seen in events
    pub(crate) reparented: bool,
}

impl Process {
    // A process is alive as long as one of its tasks is, the leader
    // exiting alone does not kill the process.
    #[inline(always)]
    pub(crate) fn is_alive(&self) -> bool {
        !self.threads.is_empty()
    }

    // run when the last task of the process exits
    pub(crate) fn on_exit(&mut self) {
        // this does not allocate the new map
        self.resolved.clear();
        self.resolved.shrink_to_fit();
    }
}

/// Per-task (as opposed to per-process) state.
#[derive(Debug, Clone)]
pub(crate) struct Task {
    pub(crate) proc_key: ProcKey,
    pub(crate) tgid: i32,
    pub(crate) pid: i32,
    // shared with the leader task when equal, replaced wholesale on change
    pub(crate) cgroups: Arc<[String]>,
    pub(crate) nodename: Option<Arc<str>>,
    // Baseline credentials used to detect out-of-band tampering. Only ever set
    // from what commit_creds() installs, it is our ground truth.
    pub(crate) expected_creds: creds::Creds,
    // Credentials of the last creds_tampered event reported, used not to
    // re-fire on every subsequent event while a divergence lasts.
    pub(crate) reported_creds: Option<creds::Creds>,
}

/// Process map, kept apart from [`crate::EventConsumer`] so that events can
/// borrow from it while [`crate::EventSink`] is mutably borrowed.
#[derive(Default)]
pub(crate) struct Processes(HashMap<ProcKey, Process>);

impl Deref for Processes {
    type Target = HashMap<ProcKey, Process>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Processes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Processes {
    /// get the list of ancestors given a [ProcKey]. If skip is 0 the last
    /// item is the image of the task referenced by `k`. One can skip ancestors
    /// by setting `skip` > 0.
    pub(crate) fn get_all_ancestors(&self, mut k: ProcKey, mut skip: u16) -> Vec<Cow<'_, str>> {
        let mut ancestors = vec![];
        let mut last = None;

        while let Some(task) = self.get(&k) {
            last = Some(task);
            if skip == 0 {
                ancestors.push(task.image.to_string_lossy());
            } else {
                skip -= 1;
            }

            if ancestors.len() >= MAX_ANCESTORS - 1 {
                break;
            }

            k = match task.real_parent_key {
                Some(v) => v,
                None => {
                    break;
                }
            };
        }

        if ancestors.len() >= MAX_ANCESTORS - 1 {
            ancestors.push("(truncated)".into());
        } else if let Some(last) = last
            && last.pid != 1
            && !last.kthread
            && skip == 0
        {
            ancestors.push("?".into());
        }

        ancestors.reverse();
        ancestors
    }
}

/// Transient procfs errors keep the task, only a vanished or reused tid is stale.
pub(crate) fn task_is_stale(tk: &TaskKey, t: &Task) -> bool {
    match procfs::process::Process::new(t.tgid)
        .and_then(|p| p.task_from_tid(t.pid))
        .map_err(KeyError::from)
        .and_then(|pt| TaskKey::try_from(&pt))
    {
        Ok(k) => k != *tk,
        Err(KeyError::ProcFs(procfs::ProcError::NotFound(_))) => true,
        Err(_) => false,
    }
}

/// Processes and their tasks, kept consistent with each other.
#[derive(Default)]
pub(crate) struct ProcessTable {
    pub(crate) processes: Processes,
    pub(crate) tasks: HashMap<TaskKey, Task>,
}

impl ProcessTable {
    pub(crate) fn with_capacity(cap: usize) -> Self {
        Self {
            processes: Processes(HashMap::with_capacity(cap)),
            tasks: HashMap::with_capacity(cap),
        }
    }

    pub(crate) fn track_task(&mut self, ti: &TaskInfo) {
        let tk = TaskKey::from(ti);
        let pk = ProcKey::from(ti);
        let process = self.processes.get_mut(&pk);
        if !self.tasks.contains_key(&tk) {
            let leader = process.as_ref().and_then(|p| self.tasks.get(&p.leader));
            let task = Task {
                proc_key: pk,
                tgid: ti.tgid,
                pid: ti.pid,
                cgroups: leader.map(|l| Arc::clone(&l.cgroups)).unwrap_or_default(),
                nodename: leader.and_then(|l| l.nodename.clone()),
                expected_creds: ti.creds,
                reported_creds: None,
            };
            self.tasks.insert(tk, task);
        }
        if let Some(p) = process {
            p.threads.insert(tk);
        }
    }

    /// Returns true if this exit ended the whole process, false for
    /// late exits of an already exited process.
    pub(crate) fn untrack_task(&mut self, ti: &TaskInfo, pk: ProcKey, exit_group: bool) -> bool {
        let tk = TaskKey::from(ti);
        self.tasks.remove(&tk);

        match self.processes.get_mut(&pk) {
            Some(p) => {
                if !p.is_alive() {
                    return false;
                }
                p.threads.remove(&tk);
                if exit_group {
                    for t in p.threads.drain() {
                        self.tasks.remove(&t);
                    }
                }
                !p.is_alive()
            }
            // unknown process, we can only rely on what the event tells us
            None => exit_group || ti.is_thread_leader(),
        }
    }

    /// Removes the process `pk` after a successful execve and drops the
    /// [`Task`]s of all its threads but the one that exec'd.
    ///
    /// Mirrors the kernel's `de_thread()`: other threads are killed and the
    /// exec'ing one takes over the leader identity, i.e. `pk.to_thread_leader_key()`.
    ///
    /// Returns the removed [`Process`], if it was tracked.
    pub(crate) fn untrack_exec_proc(&mut self, pk: ProcKey) -> Option<Process> {
        self.processes.remove(&pk).inspect(|p| {
            let tk = pk.to_thread_leader_key();
            for t in p.threads.iter().filter(|&&t| t != tk) {
                self.tasks.remove(t);
            }
        })
    }

    /// Drops the tasks `is_stale` reports and returns the processes it left
    /// without threads.
    pub(crate) fn sweep_stale_tasks(
        &mut self,
        is_stale: impl Fn(&TaskKey, &Task) -> bool,
    ) -> Vec<ProcKey> {
        let stale = self
            .tasks
            .iter()
            .filter(|&(tk, t)| is_stale(tk, t))
            .map(|(k, _)| *k)
            .collect::<Vec<TaskKey>>();

        let mut exited = vec![];
        for tk in stale {
            if let Some(t) = self.tasks.remove(&tk)
                && let Some(p) = self.processes.get_mut(&t.proc_key)
                && p.threads.remove(&tk)
                && !p.is_alive()
            {
                exited.push(t.proc_key);
            }
        }
        exited
    }

    /// Registers a thread read from procfs. A zombie thread is kept in `tasks`
    /// but not in `threads`: we will never see its exit, so it must not keep
    /// the process alive.
    pub(crate) fn track_procfs_task(
        &mut self,
        threads: &mut HashSet<TaskKey>,
        key: TaskKey,
        state: char,
        task: Task,
    ) {
        if state != 'Z' {
            threads.insert(key);
        }
        self.tasks.insert(key, task);
    }

    /// Registers the process `ti` belongs to and links it to its parent.
    pub(crate) fn insert_process(
        &mut self,
        ti: &TaskInfo,
        image: PathBuf,
        command_line: String,
        cgroups: &[String],
        parent_key: ProcKey,
        parent_task_info: TaskInfo,
    ) {
        let pk = ProcKey::from(ti);
        let tk = TaskKey::from(ti);

        let container = Container::from_cgroups(cgroups).or_else(|| {
            Container::from_ancestors(&self.processes.get_all_ancestors(parent_key, 0))
        });

        // we track children processes, not tasks
        self.processes.entry(parent_key).and_modify(|e| {
            e.children.insert(pk);
        });

        self.processes.insert(
            pk,
            Process {
                image,
                command_line,
                pid: ti.tgid,
                // the process may first be seen from a non-leader thread
                leader: pk.to_thread_leader_key(),
                kthread: ti.is_kernel_thread(),
                resolved: HashMap::new(),
                container,
                real_parent_key: Some(parent_key),
                children: HashSet::new(),
                threads: HashSet::from([tk]),
                parent_task_info: Some(parent_task_info),
                procfs: false,
                reparented: false,
            },
        );
    }

    /// Replaces the parent of a re-parented process with the last one seen
    /// before re-parenting, and flags zombies.
    pub(crate) fn fixup_real_parent(&mut self, std_info: &mut StdEventInfo) {
        if let Some(p) = self.processes.get_mut(&std_info.process_key())
            && let Some(rpk) = p.real_parent_key
        {
            if !p.reparented && rpk == std_info.parent_key() {
                // keep the last parent state seen before a re-parenting
                p.parent_task_info = Some(std_info.bpf.parent);
            } else {
                p.reparented = true;
                if let Some(pti) = p.parent_task_info {
                    std_info.bpf.parent = pti;
                    std_info.bpf.process.zombie = true
                }
            }
        }

        // we must set the zombie flag of the parent if needed
        if self
            .processes
            .get(&std_info.parent_key())
            .map(|t| t.reparented)
            .unwrap_or_default()
        {
            std_info.bpf.parent.zombie = true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kunai_common::bpf_events;

    fn pkey(pid: u32) -> ProcKey {
        ProcKey::from_proc_uuid(kunai_common::uuid::ProcUuid {
            leader_start_time_ns: 0,
            random: 0,
            tgid: pid,
        })
    }

    fn process(pid: i32, image: &str, parent: Option<u32>) -> Process {
        let leader = TaskKey::from(&TaskInfo {
            pid,
            tgid: pid,
            ..Default::default()
        });
        Process {
            image: image.into(),
            command_line: String::new(),
            pid,
            leader,
            kthread: false,
            resolved: HashMap::new(),
            container: None,
            real_parent_key: parent.map(pkey),
            children: HashSet::new(),
            threads: HashSet::from([leader]),
            parent_task_info: None,
            procfs: false,
            reparented: false,
        }
    }

    fn thread(tgid: i32, pid: i32) -> TaskInfo {
        TaskInfo {
            pid,
            tgid,
            tg_uuid: kunai_common::uuid::ProcUuid {
                leader_start_time_ns: 0,
                random: 0,
                tgid: tgid as u32,
            },
            ..Default::default()
        }
    }

    /// process 100 with threads 100 (leader), 101 and 102
    fn threaded() -> ProcessTable {
        let mut t = ProcessTable::default();
        t.processes
            .insert(pkey(100), process(100, "/bin/app", None));
        for pid in [100, 101, 102] {
            t.track_task(&thread(100, pid));
        }
        t
    }

    fn exit(t: &mut ProcessTable, pid: i32, exit_group: bool) -> bool {
        t.untrack_task(&thread(100, pid), pkey(100), exit_group)
    }

    #[test]
    fn track_task_registers_threads() {
        let t = threaded();
        assert_eq!(t.tasks.len(), 3);
        assert_eq!(t.processes[&pkey(100)].threads.len(), 3);
    }

    #[test]
    fn leader_exit_with_live_sibling_keeps_group() {
        let mut t = threaded();
        assert!(!exit(&mut t, 100, false));
        assert!(t.processes[&pkey(100)].is_alive());
        assert!(!t.tasks.contains_key(&TaskKey::from(&thread(100, 100))));
        assert_eq!(t.tasks.len(), 2);
    }

    #[test]
    fn sibling_exit_keeps_group() {
        let mut t = threaded();
        assert!(!exit(&mut t, 101, false));
        assert_eq!(t.processes[&pkey(100)].threads.len(), 2);
    }

    #[test]
    fn last_thread_exit_ends_group() {
        let mut t = threaded();
        assert!(!exit(&mut t, 100, false));
        assert!(!exit(&mut t, 101, false));
        assert!(exit(&mut t, 102, false));
        assert!(!t.processes[&pkey(100)].is_alive());
        assert!(t.tasks.is_empty());
    }

    #[test]
    fn exit_group_drains_all_threads() {
        let mut t = threaded();
        assert!(exit(&mut t, 101, true));
        assert!(!t.processes[&pkey(100)].is_alive());
        assert!(t.tasks.is_empty());
    }

    #[test]
    fn unknown_group_exit() {
        let mut t = ProcessTable::default();
        let mut untrack = |pid, eg| t.untrack_task(&thread(7, pid), pkey(7), eg);
        assert!(!untrack(8, false));
        assert!(untrack(8, true));
        assert!(untrack(7, false));
    }

    #[test]
    fn exit_events_do_not_resurrect_tasks() {
        let mut t = threaded();
        assert!(exit(&mut t, 101, true));
        // a late exit from an already drained thread
        assert!(!exit(&mut t, 102, false));
        assert!(t.tasks.is_empty());
    }

    #[test]
    fn sweep_keeps_process_with_live_threads() {
        let mut t = threaded();
        let app = pkey(100);
        let stale = TaskKey::from(&thread(100, 101));

        assert!(t.sweep_stale_tasks(|tk, _| *tk == stale).is_empty());
        assert!(!t.tasks.contains_key(&stale));
        assert!(!t.processes[&app].threads.contains(&stale));
        assert!(t.processes[&app].is_alive());
    }

    #[test]
    fn sweep_reports_process_without_threads() {
        let mut t = threaded();
        let app = pkey(100);

        assert_eq!(t.sweep_stale_tasks(|_, _| true), [app]);
        assert!(t.tasks.is_empty());
        assert!(!t.processes[&app].is_alive());
    }

    #[test]
    fn procfs_zombie_leader_does_not_keep_process_alive() {
        let app = pkey(100);
        let leader = thread(100, 100);
        let sibling = thread(100, 101);
        let mut proc = process(100, "/bin/app", None);
        proc.threads.clear();

        let mut t = ProcessTable::default();
        for (ti, state) in [(leader, 'Z'), (sibling, 'S')] {
            let task = Task {
                proc_key: app,
                tgid: ti.tgid,
                pid: ti.pid,
                cgroups: Arc::from([]),
                nodename: None,
                expected_creds: creds::Creds::default(),
                reported_creds: None,
            };
            t.track_procfs_task(&mut proc.threads, TaskKey::from(&ti), state, task);
        }

        // the leader task is kept, startup container detection reads its cgroups
        assert!(t.tasks.contains_key(&TaskKey::from(&leader)));
        assert_eq!(proc.threads, HashSet::from([TaskKey::from(&sibling)]));

        // so the sibling exit ends the process
        t.processes.insert(app, proc);
        assert!(t.untrack_task(&sibling, app, false));
    }

    #[test]
    fn process_seen_from_non_leader_has_leader_key() {
        let init = pkey(1);
        let app = pkey(100);
        let sibling = thread(100, 101);
        let mut t = ProcessTable::default();
        t.processes.insert(init, process(1, "/sbin/init", None));

        t.insert_process(
            &sibling,
            "/bin/app".into(),
            String::new(),
            &[],
            init,
            thread(1, 1),
        );

        let p = &t.processes;
        assert_eq!(p[&app].leader, TaskKey::from(&thread(100, 100)));
        assert_eq!(p[&app].threads, HashSet::from([TaskKey::from(&sibling)]));
        assert!(p[&init].children.contains(&app));
    }

    fn std_info(process: TaskInfo, parent: TaskInfo) -> StdEventInfo {
        StdEventInfo::from_bpf(
            bpf_events::EventInfo {
                process,
                parent,
                ..Default::default()
            },
            0,
        )
    }

    #[test]
    fn reparented_process_uses_last_parent_seen() {
        let mut t = ProcessTable {
            processes: rooted_chain(),
            ..Default::default()
        };
        let init = thread(1, 1);
        let ls = thread(20, 20);
        // start_time tells this bash state apart from a fresh thread(10, 10)
        let mut bash = thread(10, 10);
        bash.start_time = 42;

        let mut i = std_info(ls, bash);
        t.fixup_real_parent(&mut i);
        let saved = t.processes[&ProcKey::from(&ls)].parent_task_info.unwrap();
        assert_eq!((saved.pid, saved.start_time), (bash.pid, bash.start_time));
        assert!(!i.bpf.process.zombie);

        // bash exited, ls got re-parented to init
        let mut i = std_info(ls, init);
        t.fixup_real_parent(&mut i);
        assert!(t.processes[&ProcKey::from(&ls)].reparented);
        assert!(i.bpf.process.zombie);
        assert_eq!(
            (i.bpf.parent.pid, i.bpf.parent.start_time),
            (bash.pid, bash.start_time)
        );
    }

    #[test]
    fn execve_from_non_leader_keeps_only_exec_task() {
        let mut t = threaded();
        // the execing thread takes over the leader pid and start_time
        let tk = TaskKey::from(&thread(100, 100));
        assert!(t.untrack_exec_proc(pkey(100)).is_some());
        assert!(!t.processes.contains_key(&pkey(100)));
        assert_eq!(t.tasks.keys().collect::<Vec<_>>(), [&tk]);
    }

    /// init(1) -> bash(10) -> ls(20)
    fn rooted_chain() -> Processes {
        let mut p = Processes::default();
        p.insert(pkey(1), process(1, "/sbin/init", None));
        p.insert(pkey(10), process(10, "/bin/bash", Some(1)));
        p.insert(pkey(20), process(20, "/bin/ls", Some(10)));
        p
    }

    #[test]
    fn ancestors_rooted_at_init() {
        let p = rooted_chain();
        assert_eq!(
            p.get_all_ancestors(pkey(20), 0),
            ["/sbin/init", "/bin/bash", "/bin/ls"]
        );
    }

    #[test]
    fn ancestors_skip() {
        let p = rooted_chain();
        assert_eq!(
            p.get_all_ancestors(pkey(20), 1),
            ["/sbin/init", "/bin/bash"]
        );
        // skipping past the root leaves nothing, and no "?" marker
        assert!(p.get_all_ancestors(pkey(20), 5).is_empty());
    }

    #[test]
    fn ancestors_unknown_key() {
        assert!(rooted_chain().get_all_ancestors(pkey(99), 0).is_empty());
    }

    #[test]
    fn ancestors_broken_chain() {
        let mut p = Processes::default();
        p.insert(pkey(42), process(42, "/usr/bin/sshd", None));
        p.insert(pkey(43), process(43, "/bin/sh", Some(42)));
        assert_eq!(
            p.get_all_ancestors(pkey(43), 0),
            ["?", "/usr/bin/sshd", "/bin/sh"]
        );
    }

    #[test]
    fn ancestors_kthread_root() {
        let mut kthreadd = process(2, "kthreadd", None);
        kthreadd.kthread = true;
        let mut p = Processes::default();
        p.insert(pkey(2), kthreadd);
        p.insert(pkey(50), process(50, "/bin/sh", Some(2)));
        assert_eq!(p.get_all_ancestors(pkey(50), 0), ["kthreadd", "/bin/sh"]);
    }

    #[test]
    fn ancestors_cycle_is_truncated() {
        let mut p = Processes::default();
        p.insert(pkey(100), process(100, "/a", Some(101)));
        p.insert(pkey(101), process(101, "/b", Some(100)));
        let a = p.get_all_ancestors(pkey(100), 0);
        assert_eq!(a.len(), MAX_ANCESTORS);
        assert_eq!(a[0], "(truncated)");
        assert_eq!(a[MAX_ANCESTORS - 1], "/a");
    }
}
