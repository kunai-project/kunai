use super::Error;
use super::Event;
use super::EventInfo;
use super::Namespaces;
use super::TaskInfo;
use super::Type;
use crate::co_re::core_read_kernel;
use crate::co_re::task_struct;
use crate::helpers::{bpf_get_current_task, bpf_ktime_get_ns};
use crate::uuid::Uuid;

impl<T> Event<T> {
    #[inline(always)]
    pub unsafe fn init_from_current_task(&mut self, ty: Type) -> Result<(), Error> {
        self.init_from_task(
            ty,
            task_struct::from_ptr(bpf_get_current_task() as *const _),
        )
    }

    #[inline(always)]
    pub unsafe fn init_from_task(&mut self, ty: Type, ts: task_struct) -> Result<(), Error> {
        self.info.init(ty, ts)?;
        Ok(())
    }
}

impl EventInfo {
    #[inline(always)]
    pub(crate) unsafe fn init(&mut self, t: Type, task: task_struct) -> Result<(), Error> {
        self.etype = t;

        // create a new Uuid for event
        self.uuid = Uuid::new_random();

        if !task.is_null() {
            self.process.from_task(task)?;
            self.parent
                .from_task(task.real_parent().ok_or(Error::RealParentFieldMissing)?)?;
        }

        self.timestamp = bpf_ktime_get_ns();

        Ok(())
    }
}

impl TaskInfo {
    /// # Safety
    /// * task must be a pointer to a valid task_struct
    #[inline(always)]
    pub unsafe fn from_task(&mut self, task: task_struct) -> Result<(), Error> {
        // flags
        self.flags = task.flags().ok_or(Error::FlagFieldMissing)?;

        // process start time
        self.start_time = task.start_boottime().ok_or(Error::BootTimeMissing)?;
        self.tgid = task.tgid().ok_or(Error::TgidFieldMissing)?;
        self.pid = task.pid().ok_or(Error::PidFieldMissing)?;

        // the leader structure member points to the task leader of the thread group
        let leader = task.group_leader().ok_or(Error::GroupLeaderMissing)?;

        // start_time is the time in jiffies and is contained in /proc/$pid/stat
        // file -> this way we can also compute unique ID from procfs
        self.tg_uuid.init(
            leader.start_boottime().ok_or(Error::BootTimeMissing)?,
            self.tgid as u32,
        );

        // copy comm
        self.comm = task.comm_array().ok_or(Error::CommMissing)?;

        // if task_struct is valid cannot be null
        self.uid = task.cred().ok_or(Error::CredFieldMissing)?.uid();
        self.gid = task.cred().ok_or(Error::CredFieldMissing)?.gid();

        if let Some(nsproxy) = core_read_kernel!(task, nsproxy) {
            // it may happen that under some very specific conditions nsproxy
            // gets null (see https://github.com/kunai-project/kunai/issues/34)
            if !nsproxy.is_null() {
                self.namespaces = Some(Namespaces {
                    mnt: core_read_kernel!(nsproxy, mnt_ns, ns, inum)
                        .ok_or(Error::MntNamespaceFailure)?,
                });
            }
        }

        Ok(())
    }
}
