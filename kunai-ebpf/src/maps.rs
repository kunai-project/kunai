use aya_bpf::{macros::map, maps::LruHashMap};
use kunai_common::{bpf_utils::bpf_task_tracking_id, co_re};
use kunai_macros::BpfError;

use crate::error::ProbeError;

const MAP_ENTRIES: u32 = 0x1ffff;

#[map]
// tracks last fd inserted for task
static mut LAST_FD: LruHashMap<u64, i64> = LruHashMap::with_max_entries(MAP_ENTRIES, 0);

#[map]
// key: fd identifier value: randomid used in paths_db
static mut FDS_MAP: LruHashMap<u128, co_re::file> = LruHashMap::with_max_entries(MAP_ENTRIES, 0);

pub struct FdMap {
    last: &'static mut LruHashMap<u64, i64>,
    fds: &'static mut LruHashMap<u128, co_re::file>,
}

#[derive(BpfError)]
pub enum Error {
    #[error("failed to insert last fd into map")]
    LastFdInsertion,
    #[error("failed to insert fd into map")]
    FdInsertion,
    #[error("failed to delete fd from map")]
    FdDeletion,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::FdMapError(value)
    }
}

impl FdMap {
    pub fn attach() -> Self {
        FdMap {
            last: unsafe { &mut LAST_FD },
            fds: unsafe { &mut FDS_MAP },
        }
    }

    fn key_from_fd(&self, fd: i64) -> u128 {
        ((fd as u128) << 64) | (bpf_task_tracking_id() as u128)
    }

    pub fn get(&mut self, fd: i64) -> Option<&co_re::file> {
        unsafe { self.fds.get(&self.key_from_fd(fd)) }
    }

    #[allow(dead_code)]
    pub fn contains(&mut self, fd: i64) -> bool {
        self.get(fd).is_some()
    }

    pub fn insert(&mut self, fd: i64, file: &co_re::file) -> Result<(), Error> {
        let fd_key = self.key_from_fd(fd);

        //let path_key = self.paths.insert(&path);
        self.fds
            .insert(&fd_key, file, 0)
            .map_err(|_| Error::FdInsertion)?;

        self.last
            .insert(&bpf_task_tracking_id(), &fd, 0)
            .map_err(|_| Error::LastFdInsertion)
    }

    #[allow(dead_code)]
    pub fn last_used_fd(&mut self) -> Option<i64> {
        unsafe { self.last.get(&bpf_task_tracking_id()).copied() }
    }

    #[allow(dead_code)]
    pub fn delete(&mut self, fd: i64) -> Result<(), Error> {
        self.fds
            .remove(&self.key_from_fd(fd))
            .map_err(|_| Error::FdDeletion)
    }
}
