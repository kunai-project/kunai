use aya_ebpf::helpers::bpf_probe_read_kernel;

use crate::co_re::{self, core_read_kernel};

use super::{IdExtent, IdMap, MAX_BASE_EXTENTS, UserNs};

impl IdMap {
    #[inline(always)]
    unsafe fn read_uid_gid_map(&mut self, m: co_re::uid_gid_map) -> Option<()> {
        unsafe {
            self.nr_extents = m.nr_extents()?;
            let nr = self.nr_extents as usize;
            // out of line extents are not supported, no need to copy
            if nr > MAX_BASE_EXTENTS {
                return Some(());
            }
            // same layout as kernel's uid_gid_extent
            let ext = m.extent()? as *const IdExtent;
            for (i, e) in self.extents.iter_mut().enumerate().take(nr) {
                *e = bpf_probe_read_kernel(ext.add(i)).ok()?;
            }
            Some(())
        }
    }
}

impl UserNs {
    /// Fills `self` in place (it is too big to be built on the stack). On
    /// failure `self` is left invalid, see [UserNs::is_valid].
    #[inline(always)]
    pub unsafe fn from_user_namespace(&mut self, ns: co_re::user_namespace) {
        unsafe {
            if self.try_from_user_namespace(ns).is_none() {
                self.inum = 0;
            }
        }
    }

    #[inline(always)]
    unsafe fn try_from_user_namespace(&mut self, ns: co_re::user_namespace) -> Option<()> {
        unsafe {
            self.uid_map.read_uid_gid_map(ns.uid_map()?)?;
            self.gid_map.read_uid_gid_map(ns.gid_map()?)?;
            // set last so that a partial copy stays invalid
            self.inum = core_read_kernel!(ns, ns, inum)?;
            Some(())
        }
    }
}
