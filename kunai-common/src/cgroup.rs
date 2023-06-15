use crate::{bpf_target_code, not_bpf_target_code};
use kunai_macros::BpfError;

const MAX_CGROUP_TYPE_NAMELEN: usize = 32;
const MAX_CFTYPE_NAME: usize = 64;

pub const CGROUP_FILE_NAME_MAX: usize = MAX_CGROUP_TYPE_NAMELEN + MAX_CFTYPE_NAME + 2;

const CGROUP_STRING_LEN: usize = CGROUP_FILE_NAME_MAX * 2;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Cgroup {
    path: crate::string::String<CGROUP_STRING_LEN>,
}

#[derive(BpfError)]
pub enum Error {
    #[error("failed to read cgroup.kn")]
    Kn,
    #[error("failed to read kn.name")]
    KnName,
    #[error("failed to read kn.parent")]
    KnParent,
    #[error("failed appending to path")]
    Append,
}

not_bpf_target_code! {
    use std::fmt;

    impl Cgroup {
        pub fn to_vec(&self) -> Vec<String> {
            self.path.to_string().split('/').map(|s| s.to_string()).rev().collect()
        }
    }

    impl fmt::Display for Cgroup {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "{}", self.to_vec().join("/"))
        }
    }
}

bpf_target_code! {
    use crate::co_re::{self, core_read_kernel};
    const MAX_CGROUP_DEPTH: usize = 32;


    impl Cgroup {
        /// Resolve the cgroup path. The algorithm resolves the path in reverse order
        /// to minimize the number of instructions.
        #[inline(always)]
        pub unsafe fn resolve(&mut self, cgroup: co_re::cgroup) -> Result<(), Error> {
            if cgroup.is_null(){
                return Ok(());
            }

            let mut kn = core_read_kernel!(cgroup, kn).ok_or(Error::Kn)?;

            for _ in 0..MAX_CGROUP_DEPTH {
                let kn_name = core_read_kernel!(kn, name).ok_or(Error::KnName)?;
                self.path
                .append_kernel_str_bytes(kn_name)
                .map_err(|_| Error::Append)?;

                kn = core_read_kernel!(kn, parent).ok_or(Error::KnParent)?;
                if kn.is_null() {
                    break;
                }

                self.path.push_byte(b'/');
            }

            Ok(())
        }
    }

}
