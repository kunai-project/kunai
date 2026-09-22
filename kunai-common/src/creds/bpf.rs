use crate::co_re::{self, core_read_kernel};

use super::{Creds, Error};

impl Creds {
    #[inline]
    pub unsafe fn from_cred(&mut self, c: co_re::cred) -> Result<(), Error> {
        self.uid = core_read_kernel!(c, uid).ok_or(Error::Uid)?;
        self.gid = core_read_kernel!(c, gid).ok_or(Error::Gid)?;
        self.euid = core_read_kernel!(c, euid).ok_or(Error::EUid)?;
        self.egid = core_read_kernel!(c, egid).ok_or(Error::EGid)?;
        self.suid = core_read_kernel!(c, suid).ok_or(Error::SUid)?;
        self.sgid = core_read_kernel!(c, sgid).ok_or(Error::SGid)?;
        self.fsuid = core_read_kernel!(c, fsuid).ok_or(Error::FSUid)?;
        self.fsgid = core_read_kernel!(c, fsgid).ok_or(Error::FSGid)?;
        self.cap_effective = core_read_kernel!(c, cap_effective).ok_or(Error::CapEffective)?;
        self.cap_permitted = core_read_kernel!(c, cap_permitted).ok_or(Error::CapPermitted)?;
        self.cap_inheritable =
            core_read_kernel!(c, cap_inheritable).ok_or(Error::CapInheritable)?;
        Ok(())
    }
}
