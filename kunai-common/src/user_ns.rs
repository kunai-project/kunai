#[cfg(target_arch = "bpf")]
mod bpf;

/// Kernel `UID_GID_MAP_MAX_BASE_EXTENTS`: maps with more extents store them
/// out of line and are not supported.
pub const MAX_BASE_EXTENTS: usize = 5;

/// Kernel `uid_gid_extent`: ids `first..first + count` of the namespace are
/// kernel ids `lower_first..lower_first + count`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IdExtent {
    pub first: u32,
    pub lower_first: u32,
    pub count: u32,
}

/// Copy of the inline extents of a kernel `uid_gid_map`.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct IdMap {
    /// may exceed [MAX_BASE_EXTENTS], the map is then unsupported
    pub nr_extents: u32,
    pub extents: [IdExtent; MAX_BASE_EXTENTS],
}

impl IdMap {
    /// Translates a kernel (host) id into the id seen from the map's user
    /// namespace, like the kernel's `from_kuid`. Returns `None` if the id is
    /// unmapped or the map unsupported.
    pub fn map_id_up(&self, id: u32) -> Option<u32> {
        let nr = self.nr_extents as usize;
        if nr > MAX_BASE_EXTENTS {
            return None;
        }
        self.extents[..nr]
            .iter()
            // subtracting lower_first avoids overflowing lower_first + count
            .find(|e| id >= e.lower_first && id - e.lower_first < e.count)
            .and_then(|e| e.first.checked_add(id - e.lower_first))
    }
}

/// Parses the content of `/proc/<pid>/{uid,gid}_map`.
#[cfg(not(target_arch = "bpf"))]
impl core::str::FromStr for IdMap {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut map = IdMap::default();
        for line in s.lines() {
            let mut fields = line.split_whitespace().map(|f| f.parse::<u32>());
            let (Some(Ok(first)), Some(Ok(lower_first)), Some(Ok(count))) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(());
            };
            // past the inline extents the map is unsupported, we only count
            if let Some(e) = map.extents.get_mut(map.nr_extents as usize) {
                *e = IdExtent {
                    first,
                    lower_first,
                    count,
                };
            }
            map.nr_extents += 1;
        }
        Ok(map)
    }
}

/// User namespace of a task, identified by its inode number, with its id maps.
#[repr(C)]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UserNs {
    /// 0 if the namespace could not be read (not a valid inode number)
    pub inum: u32,
    pub uid_map: IdMap,
    pub gid_map: IdMap,
}

impl UserNs {
    /// False if the namespace could not be read or if its maps are not
    /// written yet: a child of clone(CLONE_NEWUSER) is seen before its parent
    /// writes them, and they would stay empty until its next execve.
    pub fn is_valid(&self) -> bool {
        self.inum != 0 && self.uid_map.nr_extents != 0 && self.gid_map.nr_extents != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // rootless podman default: container root is the user, then subuids
    fn rootless() -> IdMap {
        let mut m = IdMap {
            nr_extents: 2,
            ..Default::default()
        };
        m.extents[0] = IdExtent {
            first: 0,
            lower_first: 1000,
            count: 1,
        };
        m.extents[1] = IdExtent {
            first: 1,
            lower_first: 524288,
            count: 65536,
        };
        m
    }

    #[test]
    fn maps_ids_in_extents() {
        let m = rootless();
        assert_eq!(m.map_id_up(1000), Some(0));
        assert_eq!(m.map_id_up(524288), Some(1));
        assert_eq!(m.map_id_up(524288 + 65535), Some(65536));
    }

    #[test]
    fn unmapped_ids() {
        let m = rootless();
        assert_eq!(m.map_id_up(0), None);
        assert_eq!(m.map_id_up(1001), None);
        assert_eq!(m.map_id_up(524288 + 65536), None);
    }

    #[test]
    fn full_range_does_not_overflow() {
        let mut m = IdMap {
            nr_extents: 1,
            ..Default::default()
        };
        m.extents[0] = IdExtent {
            first: 0,
            lower_first: 0,
            count: u32::MAX,
        };
        assert_eq!(m.map_id_up(u32::MAX - 1), Some(u32::MAX - 1));
    }

    #[test]
    fn invalid_extent_does_not_overflow() {
        let mut m = IdMap {
            nr_extents: 1,
            ..Default::default()
        };
        m.extents[0] = IdExtent {
            first: u32::MAX,
            lower_first: 0,
            count: 2,
        };
        assert_eq!(m.map_id_up(0), Some(u32::MAX));
        assert_eq!(m.map_id_up(1), None);
    }

    #[test]
    fn out_of_line_maps_unsupported() {
        let mut m = rootless();
        m.nr_extents = MAX_BASE_EXTENTS as u32 + 1;
        assert_eq!(m.map_id_up(1000), None);
    }

    #[test]
    fn parse_init_map() {
        let m: IdMap = "         0          0 4294967295\n".parse().unwrap();
        assert_eq!(m.nr_extents, 1);
        assert_eq!(
            m.extents[0],
            IdExtent {
                first: 0,
                lower_first: 0,
                count: u32::MAX
            }
        );
    }

    #[test]
    fn parse_rootless_map() {
        let m: IdMap = "0 1000 1\n1 524288 65536\n".parse().unwrap();
        assert_eq!(m, rootless());
    }

    #[test]
    fn parse_out_of_line_map() {
        let s: String = (0..MAX_BASE_EXTENTS as u32 + 1)
            .map(|i| format!("{i} {} 1\n", 1000 + i))
            .collect();
        let m: IdMap = s.parse().unwrap();
        assert_eq!(m.nr_extents, MAX_BASE_EXTENTS as u32 + 1);
        assert_eq!(m.map_id_up(1000), None);
    }

    #[test]
    fn parse_empty_map() {
        let m: IdMap = "".parse().unwrap();
        assert_eq!(m.nr_extents, 0);
        let ns = UserNs {
            inum: 1,
            uid_map: m,
            gid_map: rootless(),
        };
        assert!(!ns.is_valid());
    }

    #[test]
    fn parse_malformed_map() {
        assert!("0 1000\n".parse::<IdMap>().is_err());
        assert!("0 x 1\n".parse::<IdMap>().is_err());
        assert!("0 1000 1\n-1 0 1\n".parse::<IdMap>().is_err());
    }
}
