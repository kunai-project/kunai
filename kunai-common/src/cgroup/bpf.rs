use crate::co_re::{self, core_read_kernel};

use super::{Cgroup, Error};

const MAX_CGROUP_DEPTH: usize = 32;

impl Cgroup {
    /// Resolve the cgroup path. The algorithm resolves the path in reverse order
    /// to minimize the number of instructions.
    #[inline(always)]
    pub unsafe fn resolve(&mut self, cgroup: co_re::cgroup) -> Result<(), Error> {
        // initialize error
        self.error = None;

        if cgroup.is_null() {
            return Ok(());
        }

        let mut kn = core_read_kernel!(cgroup, kn).ok_or(Error::Kn)?;

        for _ in 0..MAX_CGROUP_DEPTH {
            let kn_name = core_read_kernel!(kn, name).ok_or(Error::KnName)?;
            self.path.append_kernel_str_bytes(kn_name).map_err(|_| {
                self.error = Some(Error::Append);
                Error::Append
            })?;

            kn = core_read_kernel!(kn, parent).ok_or(Error::KnParent)?;
            if kn.is_null() {
                break;
            }

            self.path.push_byte(b'/').map_err(|_| {
                self.error = Some(Error::Append);
                Error::Append
            })?;
        }

        Ok(())
    }
}
