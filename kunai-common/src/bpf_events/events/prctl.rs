use crate::bpf_events::Event;
use kunai_macros::StrEnum;

pub type PrctlEvent = Event<PrctlData>;

#[repr(C)]
pub struct PrctlData {
    pub option: u64,
    pub arg2: u64,
    pub arg3: u64,
    pub arg4: u64,
    pub arg5: u64,
    pub success: bool,
}

#[allow(non_camel_case_types)]
#[derive(StrEnum, Debug, PartialEq, Eq, PartialOrd, Ord)]
/// Values to pass as first argument to prctl()
pub enum PrctlOption {
    PR_SET_PDEATHSIG = 1, /* Second arg is a signal */
    PR_GET_PDEATHSIG = 2, /* Second arg is a ptr to return the signal */

    /* Get/set current->mm->dumpable */
    PR_GET_DUMPABLE = 3,
    PR_SET_DUMPABLE = 4,

    /* Get/set unaligned access control bits (if meaningful) */
    PR_GET_UNALIGN = 5,
    PR_SET_UNALIGN = 6,

    /* Get/set whether or not to drop capabilities on setuid() away from
     * uid 0 (as per security/commoncap.c) */
    PR_GET_KEEPCAPS = 7,
    PR_SET_KEEPCAPS = 8,

    /* Get/set floating-point emulation control bits (if meaningful) */
    PR_GET_FPEMU = 9,
    PR_SET_FPEMU = 10,

    /* Get/set floating-point exception mode (if meaningful) */
    PR_GET_FPEXC = 11,
    PR_SET_FPEXC = 12,

    /* Get/set whether we use statistical process timing or accurate timestamp
     * based process timing */
    PR_GET_TIMING = 13,
    PR_SET_TIMING = 14,
    /* statistical = process timing */
    /* process = timing */
    PR_SET_NAME = 15, /* Set process name */
    PR_GET_NAME = 16, /* Get process name */

    /* Get/set process endian */
    PR_GET_ENDIAN = 19,
    PR_SET_ENDIAN = 20,

    /* Get/set process seccomp mode */
    PR_GET_SECCOMP = 21,
    PR_SET_SECCOMP = 22,

    /* Get/set the capability bounding set (as per security/commoncap.c) */
    PR_CAPBSET_READ = 23,
    PR_CAPBSET_DROP = 24,

    /* Get/set the process' ability to use the timestamp counter instruction */
    PR_GET_TSC = 25,
    PR_SET_TSC = 26,

    /* Get/set securebits (as per security/commoncap.c) */
    PR_GET_SECUREBITS = 27,
    PR_SET_SECUREBITS = 28,

    /*
     * Get/set the timerslack as used by poll/select/nanosleep
     * A value of 0 means "use default"
     */
    PR_SET_TIMERSLACK = 29,
    PR_GET_TIMERSLACK = 30,

    PR_TASK_PERF_EVENTS_DISABLE = 31,
    PR_TASK_PERF_EVENTS_ENABLE = 32,

    /*
     * Set early/late kill mode for hwpoison memory corruption.
     * This influences when the process gets killed on a memory corruption.
     */
    PR_MCE_KILL = 33,

    PR_MCE_KILL_GET = 34,

    /*
     * Tune up process memory map specifics.
     */
    PR_SET_MM = 35,

    /*
     * Set specific pid that is allowed to ptrace the current task.
     * A value of 0 mean "no process".
     */
    PR_SET_PTRACER = 0x59616d61,

    PR_SET_CHILD_SUBREAPER = 36,
    PR_GET_CHILD_SUBREAPER = 37,

    /*
     * If no_new_privs is set, then operations that grant new privileges (i.e.
     * execve) will either fail or not grant them.  This affects suid/sgid,
     * file capabilities, and LSMs.
     *
     * Operations that merely manipulate or drop existing privileges (setresuid,
     * capset, etc.) will still work.  Drop those privileges if you want them gone.
     *
     * Changing LSM security domain is considered a new privilege.  So, for example,
     * asking selinux for a specific new context (e.g. with runcon) will result
     * in execve returning -EPERM.
     *
     * See Documentation/userspace-api/no_new_privs.rst for more details.
     */
    PR_SET_NO_NEW_PRIVS = 38,
    PR_GET_NO_NEW_PRIVS = 39,

    PR_GET_TID_ADDRESS = 40,

    PR_SET_THP_DISABLE = 41,
    PR_GET_THP_DISABLE = 42,

    /*
     * No longer implemented, but left here to ensure the numbers stay reserved:
     */
    PR_MPX_ENABLE_MANAGEMENT = 43,
    PR_MPX_DISABLE_MANAGEMENT = 44,

    PR_SET_FP_MODE = 45,
    PR_GET_FP_MODE = 46,

    /* Control the ambient capability set */
    PR_CAP_AMBIENT = 47,

    /* arm64 Scalable Vector Extension controls */
    /* Flag values must be kept in sync with ptrace NT_ARM_SVE interface */
    PR_SVE_SET_VL = 50, /* set task vector length */
    PR_SVE_GET_VL = 51, /* get task vector length */
    /* Bits common to PR_SVE_SET_VL and PR_SVE_GET_VL */

    /* Per task speculation control */
    PR_GET_SPECULATION_CTRL = 52,
    PR_SET_SPECULATION_CTRL = 53,
    /* Speculation control variants */
    /* Return and control values for PR_SET/GET_SPECULATION_CTRL */

    /* Reset arm64 pointer authentication keys */
    PR_PAC_RESET_KEYS = 54,

    /* Tagged user address controls for arm64 */
    PR_SET_TAGGED_ADDR_CTRL = 55,
    PR_GET_TAGGED_ADDR_CTRL = 56,
    /* MTE tag check fault modes */
    /* MTE tag inclusion mask */
    /* Unused; kept only for source compatibility */

    /* Control reclaim behavior when allocating memory */
    PR_SET_IO_FLUSHER = 57,
    PR_GET_IO_FLUSHER = 58,

    /* Dispatch syscalls to a userspace handler */
    PR_SET_SYSCALL_USER_DISPATCH = 59,
    /* The control values for the user space selector when dispatch is enabled */

    /* Set/get enabled arm64 pointer authentication keys */
    PR_PAC_SET_ENABLED_KEYS = 60,
    PR_PAC_GET_ENABLED_KEYS = 61,

    /* Request the scheduler to share a core */
    PR_SCHED_CORE = 62,

    /* arm64 Scalable Matrix Extension controls */
    /* Flag values must be in sync with SVE versions */
    PR_SME_SET_VL = 63, /* set task vector length */
    PR_SME_GET_VL = 64, /* get task vector length */
    /* Bits common to PR_SME_SET_VL and PR_SME_GET_VL */

    /* Memory deny write / execute */
    PR_SET_MDWE = 65,

    PR_GET_MDWE = 66,

    PR_SET_VMA = 0x53564d41,

    PR_GET_AUXV = 0x41555856,

    PR_SET_MEMORY_MERGE = 67,
    PR_GET_MEMORY_MERGE = 68,

    PR_RISCV_V_SET_CONTROL = 69,
    PR_RISCV_V_GET_CONTROL = 70,
}

#[cfg(test)]
mod test {
    use super::*;
    use core::str::FromStr;

    #[test]
    fn test() {
        // test that all values in prctl syscall are in enum
        assert_eq!(
            PrctlOption::from_str("PR_SET_PDEATHSIG"),
            Ok(PrctlOption::PR_SET_PDEATHSIG)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_PDEATHSIG"),
            Ok(PrctlOption::PR_GET_PDEATHSIG)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_DUMPABLE"),
            Ok(PrctlOption::PR_GET_DUMPABLE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_DUMPABLE"),
            Ok(PrctlOption::PR_SET_DUMPABLE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_UNALIGN"),
            Ok(PrctlOption::PR_SET_UNALIGN)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_UNALIGN"),
            Ok(PrctlOption::PR_GET_UNALIGN)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_FPEMU"),
            Ok(PrctlOption::PR_SET_FPEMU)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_FPEMU"),
            Ok(PrctlOption::PR_GET_FPEMU)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_FPEXC"),
            Ok(PrctlOption::PR_SET_FPEXC)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_FPEXC"),
            Ok(PrctlOption::PR_GET_FPEXC)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_TIMING"),
            Ok(PrctlOption::PR_GET_TIMING)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_TIMING"),
            Ok(PrctlOption::PR_SET_TIMING)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_NAME"),
            Ok(PrctlOption::PR_SET_NAME)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_NAME"),
            Ok(PrctlOption::PR_GET_NAME)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_ENDIAN"),
            Ok(PrctlOption::PR_GET_ENDIAN)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_ENDIAN"),
            Ok(PrctlOption::PR_SET_ENDIAN)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_SECCOMP"),
            Ok(PrctlOption::PR_GET_SECCOMP)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_SECCOMP"),
            Ok(PrctlOption::PR_SET_SECCOMP)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_TSC"),
            Ok(PrctlOption::PR_GET_TSC)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_TSC"),
            Ok(PrctlOption::PR_SET_TSC)
        );
        assert_eq!(
            PrctlOption::from_str("PR_TASK_PERF_EVENTS_DISABLE"),
            Ok(PrctlOption::PR_TASK_PERF_EVENTS_DISABLE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_TASK_PERF_EVENTS_ENABLE"),
            Ok(PrctlOption::PR_TASK_PERF_EVENTS_ENABLE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_TIMERSLACK"),
            Ok(PrctlOption::PR_GET_TIMERSLACK)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_TIMERSLACK"),
            Ok(PrctlOption::PR_SET_TIMERSLACK)
        );
        assert_eq!(
            PrctlOption::from_str("PR_MCE_KILL"),
            Ok(PrctlOption::PR_MCE_KILL)
        );

        assert_eq!(
            PrctlOption::from_str("PR_MCE_KILL_GET"),
            Ok(PrctlOption::PR_MCE_KILL_GET)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_MM"),
            Ok(PrctlOption::PR_SET_MM)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_TID_ADDRESS"),
            Ok(PrctlOption::PR_GET_TID_ADDRESS)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_CHILD_SUBREAPER"),
            Ok(PrctlOption::PR_SET_CHILD_SUBREAPER)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_CHILD_SUBREAPER"),
            Ok(PrctlOption::PR_GET_CHILD_SUBREAPER)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_NO_NEW_PRIVS"),
            Ok(PrctlOption::PR_SET_NO_NEW_PRIVS)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_NO_NEW_PRIVS"),
            Ok(PrctlOption::PR_GET_NO_NEW_PRIVS)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_THP_DISABLE"),
            Ok(PrctlOption::PR_GET_THP_DISABLE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_THP_DISABLE"),
            Ok(PrctlOption::PR_SET_THP_DISABLE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_MPX_ENABLE_MANAGEMENT"),
            Ok(PrctlOption::PR_MPX_ENABLE_MANAGEMENT)
        );
        assert_eq!(
            PrctlOption::from_str("PR_MPX_DISABLE_MANAGEMENT"),
            Ok(PrctlOption::PR_MPX_DISABLE_MANAGEMENT)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_FP_MODE"),
            Ok(PrctlOption::PR_SET_FP_MODE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_FP_MODE"),
            Ok(PrctlOption::PR_GET_FP_MODE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SVE_SET_VL"),
            Ok(PrctlOption::PR_SVE_SET_VL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SVE_GET_VL"),
            Ok(PrctlOption::PR_SVE_GET_VL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SME_SET_VL"),
            Ok(PrctlOption::PR_SME_SET_VL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SME_GET_VL"),
            Ok(PrctlOption::PR_SME_GET_VL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_SPECULATION_CTRL"),
            Ok(PrctlOption::PR_GET_SPECULATION_CTRL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_SPECULATION_CTRL"),
            Ok(PrctlOption::PR_SET_SPECULATION_CTRL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_PAC_RESET_KEYS"),
            Ok(PrctlOption::PR_PAC_RESET_KEYS)
        );
        assert_eq!(
            PrctlOption::from_str("PR_PAC_SET_ENABLED_KEYS"),
            Ok(PrctlOption::PR_PAC_SET_ENABLED_KEYS)
        );
        assert_eq!(
            PrctlOption::from_str("PR_PAC_GET_ENABLED_KEYS"),
            Ok(PrctlOption::PR_PAC_GET_ENABLED_KEYS)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_TAGGED_ADDR_CTRL"),
            Ok(PrctlOption::PR_SET_TAGGED_ADDR_CTRL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_TAGGED_ADDR_CTRL"),
            Ok(PrctlOption::PR_GET_TAGGED_ADDR_CTRL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_IO_FLUSHER"),
            Ok(PrctlOption::PR_SET_IO_FLUSHER)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_IO_FLUSHER"),
            Ok(PrctlOption::PR_GET_IO_FLUSHER)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_SYSCALL_USER_DISPATCH"),
            Ok(PrctlOption::PR_SET_SYSCALL_USER_DISPATCH)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SCHED_CORE"),
            Ok(PrctlOption::PR_SCHED_CORE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_MDWE"),
            Ok(PrctlOption::PR_SET_MDWE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_MDWE"),
            Ok(PrctlOption::PR_GET_MDWE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_VMA"),
            Ok(PrctlOption::PR_SET_VMA)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_AUXV"),
            Ok(PrctlOption::PR_GET_AUXV)
        );
        assert_eq!(
            PrctlOption::from_str("PR_SET_MEMORY_MERGE"),
            Ok(PrctlOption::PR_SET_MEMORY_MERGE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_GET_MEMORY_MERGE"),
            Ok(PrctlOption::PR_GET_MEMORY_MERGE)
        );
        assert_eq!(
            PrctlOption::from_str("PR_RISCV_V_SET_CONTROL"),
            Ok(PrctlOption::PR_RISCV_V_SET_CONTROL)
        );
        assert_eq!(
            PrctlOption::from_str("PR_RISCV_V_GET_CONTROL"),
            Ok(PrctlOption::PR_RISCV_V_GET_CONTROL)
        );
    }
}
