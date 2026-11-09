use chrono::{DateTime, Utc};
use gene::{FieldGetter, FieldNameIterator, FieldValue};
use gene_derive::FieldGetter;

use huby::ByteSize;
use kunai_common::time::Time;
use kunai_common::user_ns::UserNs;
use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use pure_magic::{DataReader, MagicDb, readers::DataRead};

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{self, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::PathBuf,
    sync::Arc,
    time::SystemTime,
};
use thiserror::Error;

use crate::{
    info::ProcKey,
    util::{
        account::{self, AccountTable, Groups, Users},
        namespace::{self, Mnt, SelfNs, Switcher},
    },
    yara::Scanner,
};

pub const FILE_SIZE_SCAN_LIMIT: u64 = ByteSize::from_mb(100).in_bytes();

struct OpenedFile {
    file: File,
    meta: fs::Metadata,
}

impl OpenedFile {
    fn new(path: &std::path::Path) -> io::Result<Self> {
        // O_PATH never calls the driver's open, which may have side effects (e.g. watchdog)
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_PATH)
            .open(path)?;
        let meta = file.metadata()?;
        if !meta.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "not a regular file",
            ));
        }
        Ok(Self { file, meta })
    }

    // Call it from our own mount namespace, whose /proc belongs to us.
    fn reopen(&self) -> io::Result<File> {
        // reopening the descriptor through procfs targets the checked inode, not the path
        OpenOptions::new()
            .read(true)
            .open(format!("/proc/self/fd/{}", self.file.as_raw_fd()))
            .map_err(|e| io::Error::new(e.kind(), format!("failed to reopen file: {e}")))
    }

    // Reads and allocates, so only call it once a cache lookup missed.
    fn reader(self) -> io::Result<DataReader<'static>> {
        DataReader::from_file(self.reopen()?)
            .map_err(|e| io::Error::new(e.kind(), format!("failed to create lazy cache: {e}")))
    }
}

fn scan_signatures(
    reader: &mut DataReader<'_>,
    size: u64,
    scanner: &mut Scanner<'_>,
) -> Result<Arc<[String]>, Error> {
    // Cap reads at the opened length so concurrent growth cannot extend the budget.
    let len = size.min(FILE_SIZE_SCAN_LIMIT);
    let data = reader.read_range(0..len)?;
    if data.len() as u64 != len {
        return Err(
            io::Error::new(io::ErrorKind::UnexpectedEof, "file shrank while reading").into(),
        );
    }
    // yara-x resets its state on every scan, so a poisoned scanner is still usable
    let scanner = scanner
        .get_mut()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let results = scanner.scan(data)?;
    Ok(results
        .matching_rules()
        .map(|rule| rule.identifier().to_string())
        .collect())
}

/// Result of [Caches::get_scan_in_ns].
pub struct ScanOutcome {
    pub hashes: Arc<Hashes>,
    /// `None` without a scanner or if scanning failed
    pub signatures: Option<Arc<[String]>>,
    pub scan_error: Option<String>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown namespace {0}")]
    UnknownMntNs(Mnt),
    #[error("{0}")]
    Namespace(#[from] namespace::Error),
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("file changed since kernel event: {0}")]
    FileModSinceKernelEvent(FileMod),
    #[error("metadata is needed for ebpf path")]
    MetadataRequired,
    #[error("yara scan error: {0}")]
    ScanError(#[from] yara_x::errors::ScanError),
    #[error("file size exceeds scan limit")]
    FileSizeScanLimit,
}

#[derive(Error, Debug)]
pub enum FileMod {
    #[error("size changed: kernel={kernel} userland={userland}")]
    Size { kernel: u64, userland: u64 },
    #[error("inode changed: kernel={kernel} userland={userland}")]
    Inode { kernel: u64, userland: u64 },
    #[error("mtime changed: kernel={kernel} userland={userland}")]
    Mtime {
        kernel: DateTime<Utc>,
        userland: DateTime<Utc>,
    },
    #[error("ctime changed: kernel={kernel} userland={userland}")]
    Ctime {
        kernel: DateTime<Utc>,
        userland: DateTime<Utc>,
    },
}

impl Error {
    pub fn is_unknown_ns(&self) -> bool {
        matches!(self, Error::UnknownMntNs(_))
    }
}

#[derive(Debug, Default, Clone, FieldGetter, Serialize, Deserialize)]
pub struct FileMeta {
    pub magic: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub size: u64,
    pub error: Option<String>,
}

impl From<&Hashes> for FileMeta {
    fn from(value: &Hashes) -> Self {
        Self {
            magic: value.magic.clone(),
            md5: value.md5.clone(),
            sha1: value.sha1.clone(),
            sha256: value.sha256.clone(),
            sha512: value.sha512.clone(),
            size: value.size,
            error: value.error.clone(),
        }
    }
}

impl FileMeta {
    #[inline]
    pub(crate) fn iocs(&self) -> Vec<Cow<'_, str>> {
        vec![
            self.md5.as_str().into(),
            self.sha1.as_str().into(),
            self.sha256.as_str().into(),
            self.sha512.as_str().into(),
        ]
    }
}

#[derive(Debug, Clone, FieldGetter, Serialize, Deserialize)]
pub struct Hashes {
    pub path: PathBuf,
    pub magic: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub size: u64,
    pub error: Option<String>,
}

impl Default for Hashes {
    fn default() -> Self {
        Self {
            path: PathBuf::default(),
            magic: "?".into(),
            md5: "?".into(),
            sha1: "?".into(),
            sha256: "?".into(),
            sha512: "?".into(),
            size: 0,
            error: None,
        }
    }
}

impl Hashes {
    pub fn with_meta(p: PathBuf, meta: FileMeta) -> Self {
        Self {
            path: p,
            magic: meta.magic,
            md5: meta.md5,
            sha1: meta.sha1,
            sha256: meta.sha256,
            sha512: meta.sha512,
            size: meta.size,
            error: meta.error,
        }
    }

    pub fn from_path_ref<T: AsRef<std::path::Path>>(p: T, magic_db: &MagicDb) -> Self {
        let path = p.as_ref();
        match OpenedFile::new(path) {
            Ok(file) => Self::from_file(path.to_path_buf(), file, magic_db),
            Err(e) => Self {
                path: path.to_path_buf(),
                error: Some(format!("failed to open file: {e}")),
                ..Self::default()
            },
        }
    }

    fn from_file(path: PathBuf, file: OpenedFile, magic_db: &MagicDb) -> Self {
        let size = file.meta.len();
        match file.reader() {
            Ok(mut f) => Self::from_reader(path, size, &mut f, magic_db),
            Err(e) => Self::with_error(path, size, e.to_string()),
        }
    }

    fn with_error(path: PathBuf, size: u64, error: String) -> Self {
        Self {
            path,
            size,
            error: Some(error),
            ..Self::default()
        }
    }

    fn from_reader(path: PathBuf, size: u64, f: &mut DataReader<'_>, magic_db: &MagicDb) -> Self {
        let mut h = Self {
            path,
            size,
            ..Self::default()
        };

        if h.size > FILE_SIZE_SCAN_LIMIT {
            h.error = Some(Error::FileSizeScanLimit.to_string());
        } else if let Err(e) = f.seek(SeekFrom::Start(0)) {
            h.error = Some(format!("failed to read: {e}"));
        } else {
            let mut md5 = Md5::new();
            let mut sha1 = Sha1::new();
            let mut sha256 = Sha256::new();
            let mut sha512 = Sha512::new();
            let mut remaining = h.size;

            while let Ok(buf) = f.read_count(remaining.min(4096)).inspect_err(|e| {
                h.error = Some(format!("failed to read: {e}"));
            }) {
                if buf.is_empty() {
                    if remaining != 0 {
                        h.error = Some(String::from("failed to read: file shrank while reading"));
                    }

                    break;
                }
                remaining -= buf.len() as u64;
                md5.update(buf);
                sha1.update(buf);
                sha256.update(buf);
                sha512.update(buf);
            }

            if h.error.is_none() {
                h.md5 = hex::encode(md5.finalize());
                h.sha1 = hex::encode(sha1.finalize());
                h.sha256 = hex::encode(sha256.finalize());
                h.sha512 = hex::encode(sha512.finalize());
            }
        }

        h.magic = magic_db
            .first_magic(f, None)
            .inspect_err(|e| {
                h.error = Some(format!("failed to find magic: {e}"));
            })
            .map(|m| m.message())
            .unwrap_or_else(|_| "?".into());

        h
    }

    pub(crate) fn iocs(&self) -> Vec<Cow<'_, str>> {
        vec![
            self.path.to_string_lossy(),
            self.md5.as_str().into(),
            self.sha1.as_str().into(),
            self.sha256.as_str().into(),
            self.sha512.as_str().into(),
        ]
    }
}

/// Path enum used as a generic interface to handle both
/// path comming from eBPF and path comming from std lib
#[derive(Debug)]
pub enum Path {
    Bpf {
        path: std::path::PathBuf,
        ebpf_meta: Option<kunai_common::path::Metadata>,
    },
    Std(std::path::PathBuf),
}

impl From<std::path::PathBuf> for Path {
    fn from(value: std::path::PathBuf) -> Self {
        Self::Std(value)
    }
}

impl From<&str> for Path {
    fn from(value: &str) -> Self {
        Self::Std(PathBuf::from(value))
    }
}

impl From<&kunai_common::path::Path> for Path {
    fn from(value: &kunai_common::path::Path) -> Self {
        Self::Bpf {
            path: value.to_path_buf(),
            ebpf_meta: value.metadata.into(),
        }
    }
}

impl Path {
    #[inline]
    pub fn as_path(&self) -> &std::path::Path {
        match self {
            Self::Bpf { path, ebpf_meta: _ } => path,
            Self::Std(p) => p,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Key {
    mnt_namespace: Mnt,
    path: PathBuf,
    dev: u64,
    ino: u64,
    size: u64,
    modified: SystemTime,
    // unlike mtime, users cannot set ctime and rewrites update it
    changed: SystemTime,
}

pub type AccountTables = (Option<Arc<Users>>, Option<Arc<Groups>>);

/// Opens `path` of the current mount namespace `ns`, see [OpenedFile::new].
fn open_keyed(ns: Mnt, path: &Path) -> Result<(OpenedFile, Key), Error> {
    let file = OpenedFile::new(path.as_path())?;
    let key = Key::from_path_and_meta(ns, path, &file.meta)?;
    Ok((file, key))
}

/// Gets the table of `file`, [open_keyed] as `key`, parsing it on a cache
/// miss. Must be called from our own mount namespace, see [OpenedFile::reopen].
fn ns_account_table<T: AccountTable>(
    file: OpenedFile,
    key: Key,
    cache: &mut LruHashMap<Key, Arc<T>>,
) -> Option<Arc<T>> {
    if let Some(t) = cache.get(&key) {
        return Some(Arc::clone(t));
    }

    let t = Arc::new(
        file.reopen()
            .map_err(account::Error::from)
            .and_then(T::from_reader)
            .inspect_err(|e| {
                log::debug!(
                    "failed to parse {} in mnt_ns={}: {e}",
                    key.path.display(),
                    key.mnt_namespace.inum
                )
            })
            .ok()?,
    );
    cache.insert(key, Arc::clone(&t));
    Some(t)
}

impl Key {
    // production keys come from an opened descriptor, see open_keyed
    #[cfg(test)]
    fn from_path_in_ns(ns: Mnt, path: &Path) -> Result<Self, Error> {
        let meta = path.as_path().metadata()?;
        Self::from_path_and_meta(ns, path, &meta)
    }

    /// Builds the key of `path` in mount namespace `ns` from its [fs::Metadata].
    fn from_path_and_meta(ns: Mnt, path: &Path, meta: &fs::Metadata) -> Result<Self, Error> {
        let k = Key {
            mnt_namespace: ns,
            path: path.as_path().to_path_buf(),
            dev: meta.dev(),
            ino: meta.ino(),
            size: meta.size(),
            modified: SystemTime::from(&Time::new(meta.mtime(), meta.mtime_nsec())),
            changed: SystemTime::from(&Time::new(meta.ctime(), meta.ctime_nsec())),
        };

        // we do extra checks if it is a Path comming from our probes
        // this way we can catch eventual file tampering attempts
        if let Path::Bpf { path: _, ebpf_meta } = path {
            // we don't have to switch to ns here as it is done in caller
            let ebpf_meta = ebpf_meta.ok_or(Error::MetadataRequired)?;

            if ebpf_meta.size as u64 != k.size {
                return Err(Error::FileModSinceKernelEvent(FileMod::Size {
                    kernel: ebpf_meta.size as u64,
                    userland: k.size,
                }));
            }

            if ebpf_meta.ino != k.ino {
                return Err(Error::FileModSinceKernelEvent(FileMod::Inode {
                    kernel: ebpf_meta.ino,
                    userland: k.ino,
                }));
            }

            let kernel_mtime = SystemTime::from(&ebpf_meta.mtime);
            if kernel_mtime != k.modified {
                return Err(Error::FileModSinceKernelEvent(FileMod::Mtime {
                    kernel: kernel_mtime.into(),
                    userland: k.modified.into(),
                }));
            }

            let kernel_ctime = SystemTime::from(&ebpf_meta.ctime);
            if kernel_ctime != k.changed {
                return Err(Error::FileModSinceKernelEvent(FileMod::Ctime {
                    kernel: kernel_ctime.into(),
                    userland: k.changed.into(),
                }));
            }
        }

        Ok(k)
    }
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

/// Counts live processes per mount namespace, so that a namespace cache
/// entry can be released as soon as its last process exits.
#[derive(Default)]
struct MntNsRefs {
    // mount namespace each live process was last seen in
    procs: HashMap<ProcKey, Mnt>,
    refs: HashMap<Mnt, usize>,
}

impl MntNsRefs {
    /// Records that process `pk` lives in mount namespace `ns`. A process
    /// may change namespace (setns, unshare), in which case the reference
    /// on the previous namespace is dropped. Returns the namespace left
    /// without any process, if any.
    fn track(&mut self, pk: ProcKey, ns: Mnt) -> Option<Mnt> {
        let unused = match self.procs.insert(pk, ns) {
            // process is already referenced
            Some(old) if old == ns => return None,
            // ns changed -> unref old mnt ns
            Some(old) => self.unref(old),
            // process newly tracked
            None => None,
        };
        *self.refs.entry(ns).or_default() += 1;
        unused
    }

    /// Forgets process `pk`. Returns its namespace if it was the last
    /// process in it.
    fn untrack(&mut self, pk: &ProcKey) -> Option<Mnt> {
        let ns = self.procs.remove(pk)?;
        self.unref(ns)
    }

    fn unref(&mut self, ns: Mnt) -> Option<Mnt> {
        let refs = self.refs.get_mut(&ns)?;
        *refs -= 1;
        if *refs == 0 {
            self.refs.remove(&ns);
            return Some(ns);
        }
        None
    }
}

/// Mount namespaces handles, released as soon as the last process living in
/// a namespace exits, as an open handle keeps the namespace (and any
/// filesystem mounted in it, like a tmpfs) alive. The LRU bound only acts as
/// a safety net against missed exits.
struct MntNsCache {
    switchers: LruHashMap<Mnt, Switcher<Mnt>>,
    refs: MntNsRefs,
    // shared by all switchers so that each entry holds a single fd
    self_ns: Option<SelfNs<Mnt>>,
}

impl MntNsCache {
    fn with_max_entries(cap: usize) -> Self {
        Self {
            switchers: LruHashMap::with_max_entries(cap),
            refs: MntNsRefs::default(),
            self_ns: None,
        }
    }

    fn cache(&mut self, pid: i32, ns: Mnt, track: Option<ProcKey>) -> Result<(), Error> {
        if let Some(unused) = track.and_then(|pk| self.refs.track(pk, ns)) {
            self.switchers.remove(&unused);
        }

        if !self.switchers.contains_key(&ns) {
            let self_ns = match self.self_ns.as_ref() {
                Some(s) => s,
                None => self.self_ns.insert(SelfNs::open()?),
            };
            self.switchers
                .insert(ns, Switcher::new(pid as u32, self_ns)?);
            debug_assert!(self.switchers.contains_key(&ns));
        }
        Ok(())
    }

    fn untrack(&mut self, pk: &ProcKey) {
        if let Some(unused) = self.refs.untrack(pk) {
            self.switchers.remove(&unused);
        }
    }

    fn get(&mut self, ns: &Mnt) -> Option<&Switcher<Mnt>> {
        self.switchers.get(ns)
    }
}

pub struct Caches {
    mnt_namespaces: MntNsCache,
    hashes: LruHashMap<Key, Arc<Hashes>>,
    users: LruHashMap<Key, Arc<Users>>,
    groups: LruHashMap<Key, Arc<Groups>>,
    // valid user namespaces by inode, tasks keep theirs alive past eviction
    user_namespaces: LruHashMap<u32, Arc<UserNs>>,
    // warn only once, users may want a bigger cache
    user_ns_evicted_in_use: bool,
    // since hashes and signatures are not computed
    // at the same time. It seems a better option
    // to separate into two HashMaps to prevent
    // any race
    signatures: LruHashMap<Key, Arc<[String]>>,
}

const NS_CACHE_SIZE: usize = 256;

impl Caches {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        Caches {
            mnt_namespaces: MntNsCache::with_max_entries(NS_CACHE_SIZE),
            users: LruHashMap::with_max_entries(NS_CACHE_SIZE),
            groups: LruHashMap::with_max_entries(NS_CACHE_SIZE),
            user_namespaces: LruHashMap::with_max_entries(NS_CACHE_SIZE),
            user_ns_evicted_in_use: false,
            hashes: LruHashMap::with_max_entries(cap),
            signatures: LruHashMap::with_max_entries(cap),
        }
    }

    /// Returns the shared instance of `ns`, or `None` if it is not valid.
    pub fn cache_user_ns(&mut self, ns: &UserNs) -> Option<Arc<UserNs>> {
        if !ns.is_valid() {
            return None;
        }
        // maps are written once, a difference means the inode was reused
        if let Some(cached) = self.user_namespaces.get(&ns.inum)
            && **cached == *ns
        {
            return Some(Arc::clone(cached));
        }
        let ns = Arc::new(*ns);
        // evicting namespaces no task holds is the LRU's normal life, only
        // evicting one still in use loses identities (e.g. of new forks)
        if let Some((_, evicted)) = self.user_namespaces.insert(ns.inum, Arc::clone(&ns))
            && Arc::strong_count(&evicted) > 1
            && !self.user_ns_evicted_in_use
        {
            log::warn!(
                "user namespace cache is too small ({} entries): namespaces in use get evicted, \
                 some events may miss their in-namespace identity",
                self.user_namespaces.cap()
            );
            self.user_ns_evicted_in_use = true;
        }
        Some(ns)
    }

    pub fn get_user_ns(&mut self, inum: u32) -> Option<Arc<UserNs>> {
        self.user_namespaces.get(&inum).cloned()
    }

    /// Caches mount namespace `ns` of process `pid`. If `track` is set, the
    /// process is recorded as living in `ns` until [Caches::untrack_mnt_ns],
    /// so that `ns` is released once its last tracked process is gone.
    pub fn cache_mnt_ns(&mut self, pid: i32, ns: Mnt, track: Option<ProcKey>) -> Result<(), Error> {
        self.mnt_namespaces.cache(pid, ns, track)
    }

    /// Forgets process `pk`, releasing its mount namespace if it was the
    /// last tracked process in it.
    pub fn untrack_mnt_ns(&mut self, pk: &ProcKey) {
        self.mnt_namespaces.untrack(pk)
    }

    /// Get the [Users] and [Groups] tables of the mount namespace `ns`, so that
    /// any uid/gid can be resolved by the caller. They are shared behind an
    /// [Arc] to avoid copying the whole tables around. Each table is loaded
    /// independently, so a missing `/etc/passwd` doesn't prevent resolving groups.
    pub fn get_user_group_in_ns(&mut self, ns: Mnt) -> Result<AccountTables, Error> {
        let (users_path, groups_path) = (Users::sys_path(), Groups::sys_path());
        // the reopen in ns_table relies on in_mnt_ns restoring our namespace
        let (passwd, group) = self.in_mnt_ns(ns, || {
            Ok((
                open_keyed(ns, &users_path.into()),
                open_keyed(ns, &groups_path.into()),
            ))
        })?;

        let users = passwd
            .inspect_err(|e| log::debug!("{users_path} in mnt_ns={}: {e}", ns.inum))
            .ok()
            .and_then(|(file, key)| ns_account_table(file, key, &mut self.users));

        let groups = group
            .inspect_err(|e| log::debug!("{groups_path} in mnt_ns={}: {e}", ns.inum))
            .ok()
            .and_then(|(file, key)| ns_account_table(file, key, &mut self.groups));

        Ok((users, groups))
    }

    /// Gets hashes and, if `scanner` is set, signatures of `path`, reading
    /// the file once for whatever is missing from the caches.
    pub fn get_scan_in_ns(
        &mut self,
        ns: Mnt,
        path: &Path,
        scanner: Option<&mut Scanner<'_>>,
        magic_db: &MagicDb,
    ) -> Result<ScanOutcome, Error> {
        let (file, key) = self.open_in_ns(ns, path)?;
        Ok(self.scan_file(file, key, scanner, magic_db))
    }

    fn scan_file(
        &mut self,
        file: OpenedFile,
        key: Key,
        mut scanner: Option<&mut Scanner<'_>>,
        magic_db: &MagicDb,
    ) -> ScanOutcome {
        let size = file.meta.len();

        let mut signatures = None;
        let mut scan_error = None;
        if scanner.is_some() {
            if size > FILE_SIZE_SCAN_LIMIT {
                scan_error = Some(String::from("partial scan, file size exceeds scan limit"));
            }
            if let Some(sigs) = self.signatures.get(&key) {
                signatures = Some(Arc::clone(sigs));
                // we clear scanner, we don't need it
                scanner = None;
            }
        }

        let hashes = match (self.hashes.get(&key).cloned(), scanner) {
            (Some(hashes), None) => hashes,
            (hashes, scanner) => {
                // a reader failure only affects what missed the caches
                let mut reader = file.reader();

                if let Some(scanner) = scanner {
                    let res = match reader.as_mut() {
                        Ok(r) => scan_signatures(r, size, scanner).map_err(|e| e.to_string()),
                        Err(e) => Err(e.to_string()),
                    };
                    match res {
                        Ok(sigs) => {
                            self.signatures.insert(key.clone(), Arc::clone(&sigs));
                            signatures = Some(sigs);
                        }
                        Err(e) => scan_error = Some(e),
                    }
                }

                hashes.unwrap_or_else(|| {
                    let path = key.path.clone();
                    let h = Arc::new(match reader.as_mut() {
                        Ok(r) => Hashes::from_reader(path, size, r, magic_db),
                        Err(e) => Hashes::with_error(path, size, e.to_string()),
                    });
                    // errors are cached too, bounding the work a hostile file can cause
                    self.hashes.insert(key, Arc::clone(&h));
                    h
                })
            }
        };

        ScanOutcome {
            hashes,
            signatures,
            scan_error,
        }
    }

    pub fn get_hashes_in_ns(
        &mut self,
        ns: Mnt,
        path: &Path,
        magic_db: &MagicDb,
    ) -> Result<Arc<Hashes>, Error> {
        let (file, key) = self.open_in_ns(ns, path)?;

        if let Some(h) = self.hashes.get(&key) {
            return Ok(Arc::clone(h));
        }

        let h = Arc::new(Hashes::from_file(key.path.clone(), file, magic_db));
        self.hashes.insert(key, Arc::clone(&h));
        Ok(h)
    }

    /// Opens `path` in mount namespace `ns`. Only resolving the path needs the
    /// namespace: the returned descriptor is read from the current one.
    fn open_in_ns(&mut self, ns: Mnt, path: &Path) -> Result<(OpenedFile, Key), Error> {
        self.in_mnt_ns(ns, || open_keyed(ns, path).map_err(namespace::Error::other))
    }

    fn in_mnt_ns<T>(
        &mut self,
        ns: Mnt,
        f: impl FnOnce() -> Result<T, namespace::Error>,
    ) -> Result<T, Error> {
        let Some(mnt_ns) = self.mnt_namespaces.get(&ns) else {
            return Err(Error::UnknownMntNs(ns));
        };

        let res = mnt_ns.do_in_namespace(f);

        // we must be sure that we restore our namespace
        if matches!(res.as_ref(), Err(namespace::Error::Exit(_, _, _))) {
            res.as_ref().expect("failed to restore namespace");
        }

        res.map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::namespace::Namespace;

    fn pkey(pid: i32) -> ProcKey {
        ProcKey::from_proc_uuid(kunai_common::uuid::ProcUuid {
            leader_start_time_ns: 0,
            random: 0,
            tgid: pid,
        })
    }

    fn user_ns(inum: u32, lower_first: u32) -> UserNs {
        let mut map = kunai_common::user_ns::IdMap {
            nr_extents: 1,
            ..Default::default()
        };
        map.extents[0] = kunai_common::user_ns::IdExtent {
            first: 0,
            lower_first,
            count: 1,
        };
        UserNs {
            inum,
            uid_map: map,
            gid_map: map,
        }
    }

    #[test]
    fn cache_user_ns_shares_instances() {
        let mut c = Caches::with_max_entries(1);
        assert!(c.cache_user_ns(&UserNs::default()).is_none());

        let a = c.cache_user_ns(&user_ns(42, 1000)).unwrap();
        let b = c.cache_user_ns(&user_ns(42, 1000)).unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert!(Arc::ptr_eq(&c.get_user_ns(42).unwrap(), &a));

        // inode reused by another namespace
        let r = c.cache_user_ns(&user_ns(42, 2000)).unwrap();
        assert_eq!(r.uid_map.extents[0].lower_first, 2000);
        assert!(Arc::ptr_eq(&c.get_user_ns(42).unwrap(), &r));
        assert!(c.get_user_ns(43).is_none());
    }

    #[test]
    fn cache_user_ns_flags_only_in_use_evictions() {
        let mut c = Caches::with_max_entries(1);
        c.user_namespaces = LruHashMap::with_max_entries(1);

        // nothing holds the evicted one
        c.cache_user_ns(&user_ns(1, 1000));
        c.cache_user_ns(&user_ns(2, 1000));
        assert!(!c.user_ns_evicted_in_use);

        let _held = c.get_user_ns(2);
        c.cache_user_ns(&user_ns(3, 1000));
        assert!(c.user_ns_evicted_in_use);
    }

    #[test]
    fn mnt_ns_refs_release_on_last_process() {
        let (host, jail) = (Mnt::from_inum::<Mnt>(1), Mnt::from_inum::<Mnt>(2));
        let mut refs = MntNsRefs::default();

        assert_eq!(refs.track(pkey(1), host), None);
        assert_eq!(refs.track(pkey(2), host), None);
        // tracking again the same process doesn't take another reference
        assert_eq!(refs.track(pkey(2), host), None);
        // process 2 unshares into the jail namespace
        assert_eq!(refs.track(pkey(2), jail), None);
        assert_eq!(refs.track(pkey(3), jail), None);

        assert_eq!(refs.untrack(&pkey(2)), None);
        assert_eq!(refs.untrack(&pkey(3)), Some(jail));
        // unknown or already untracked process
        assert_eq!(refs.untrack(&pkey(3)), None);
        assert_eq!(refs.untrack(&pkey(1)), Some(host));
    }

    #[test]
    fn mnt_ns_refs_release_on_ns_switch() {
        let (a, b) = (Mnt::from_inum::<Mnt>(1), Mnt::from_inum::<Mnt>(2));
        let mut refs = MntNsRefs::default();

        assert_eq!(refs.track(pkey(1), a), None);
        assert_eq!(refs.track(pkey(1), b), Some(a));
        assert_eq!(refs.untrack(&pkey(1)), Some(b));
    }
}

#[cfg(test)]
mod file_tests {
    use super::*;
    use crate::util::namespace::Namespace;
    use std::{
        ffi::{CString, OsString},
        io::Write,
        os::unix::{
            ffi::OsStringExt,
            fs::{FileExt, symlink},
        },
        process::{Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    fn scanner() -> Scanner<'static> {
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source("rule safe { strings: $s = \"safe\" condition: $s }")
            .unwrap();
        Scanner::with_rules(compiler.build())
    }

    fn caches() -> (Caches, Mnt) {
        let pid = std::process::id();
        let ns = Mnt::from_pid::<Mnt>(pid).unwrap();
        let mut caches = Caches::with_max_entries(16);
        caches.cache_mnt_ns(pid as i32, ns, None).unwrap();
        (caches, ns)
    }

    fn fifo(path: &std::path::Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = CString::new(path.as_os_str().as_bytes()).unwrap();
        // SAFETY: path is a live NUL-terminated string and mkfifo retains no pointers.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    fn assert_digests(hashes: &Hashes, data: &[u8]) {
        assert!(hashes.error.is_none(), "{:?}", hashes.error);
        assert_eq!(hashes.md5, hex::encode(Md5::digest(data)));
        assert_eq!(hashes.sha1, hex::encode(Sha1::digest(data)));
        assert_eq!(hashes.sha256, hex::encode(Sha256::digest(data)));
        assert_eq!(hashes.sha512, hex::encode(Sha512::digest(data)));
        assert_ne!(hashes.magic, "?");
    }

    // procfs refuses to reopen a socket, so building the reader fails
    fn unreadable(meta: fs::Metadata) -> OpenedFile {
        let (sock, _) = std::os::unix::net::UnixStream::pair().unwrap();
        OpenedFile {
            file: File::from(std::os::fd::OwnedFd::from(sock)),
            meta,
        }
    }

    fn users_table(caches: &mut Caches, ns: Mnt, path: &std::path::Path) -> Option<Arc<Users>> {
        let (file, key) = open_keyed(ns, &path.to_path_buf().into()).ok()?;
        ns_account_table(file, key, &mut caches.users)
    }

    fn groups_table(caches: &mut Caches, ns: Mnt, path: &std::path::Path) -> Option<Arc<Groups>> {
        let (file, key) = open_keyed(ns, &path.to_path_buf().into()).ok()?;
        ns_account_table(file, key, &mut caches.groups)
    }

    fn assert_no_digests(hashes: &Hashes) {
        assert!(hashes.error.is_some());
        assert_eq!(hashes.md5, "?");
        assert_eq!(hashes.sha1, "?");
        assert_eq!(hashes.sha256, "?");
        assert_eq!(hashes.sha512, "?");
    }

    // Runs test `name` in a subprocess, so that a blocking open fails it instead of hanging the suite.
    fn run_child(name: &str) {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                &format!("cache::file_tests::{name}"),
                "--nocapture",
            ])
            .env("KUNAI_HOSTILE_FILE_CHILD", "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        let timed_out = loop {
            if child.try_wait().unwrap().is_some() {
                break false;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                break true;
            }
            thread::sleep(Duration::from_millis(10));
        };
        let output = child.wait_with_output().unwrap();
        assert!(!timed_out, "{name} exceeded its watchdog");
        assert!(
            output.status.success(),
            "child failed:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed;"));
    }

    // children run only under run_child
    fn is_child() -> bool {
        std::env::var_os("KUNAI_HOSTILE_FILE_CHILD").is_some()
    }

    fn hostile_paths(dir: &std::path::Path) -> Vec<PathBuf> {
        let named_pipe = dir.join("fifo");
        fifo(&named_pipe);
        let link = dir.join("link");
        symlink(&named_pipe, &link).unwrap();
        let replacement = dir.join("replacement");
        fs::write(&replacement, b"safe").unwrap();
        assert!(replacement.metadata().unwrap().is_file());
        fs::remove_file(&replacement).unwrap();
        fifo(&replacement);
        vec![
            named_pipe,
            link,
            replacement,
            dir.to_path_buf(),
            "/dev/null".into(),
            "/dev/zero".into(),
        ]
    }

    #[test]
    fn hostile_paths_are_not_scanned() {
        run_child("hostile_paths_are_not_scanned_child");
    }

    #[test]
    fn hostile_paths_are_not_scanned_child() {
        if !is_child() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let db = magic_db::load().unwrap();
        let mut scanner = scanner();
        let (mut caches, ns) = caches();
        for path in hostile_paths(dir.path()) {
            assert!(OpenedFile::new(&path).is_err(), "{}", path.display());
            assert_no_digests(&Hashes::from_path_ref(&path, &db));
            let path = Path::Std(path);
            assert!(caches.get_hashes_in_ns(ns, &path, &db).is_err());
            assert!(
                caches
                    .get_scan_in_ns(ns, &path, Some(&mut scanner), &db)
                    .is_err()
            );
        }
        assert!(caches.hashes.is_empty());
        assert!(caches.signatures.is_empty());
    }

    #[test]
    fn hostile_account_files_are_not_loaded() {
        run_child("hostile_account_files_are_not_loaded_child");
    }

    #[test]
    fn hostile_account_files_are_not_loaded_child() {
        if !is_child() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (mut caches, ns) = caches();
        for path in hostile_paths(dir.path()) {
            assert!(
                users_table(&mut caches, ns, &path).is_none(),
                "{}",
                path.display()
            );
            assert!(
                groups_table(&mut caches, ns, &path).is_none(),
                "{}",
                path.display()
            );
        }
        assert!(caches.users.is_empty());
        assert!(caches.groups.is_empty());
    }

    #[test]
    fn cached_account_files_swapped_for_fifo() {
        run_child("cached_account_files_swapped_for_fifo_child");
    }

    #[test]
    fn cached_account_files_swapped_for_fifo_child() {
        if !is_child() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (mut caches, ns) = caches();
        let (passwd, group) = (dir.path().join("passwd"), dir.path().join("group"));
        fs::write(&passwd, "user:x:1000:1000::/home/user:/bin/sh\n").unwrap();
        fs::write(&group, "user:x:1000:\n").unwrap();
        let (passwd_link, group_link) = (
            dir.path().join("passwd_link"),
            dir.path().join("group_link"),
        );
        symlink(&passwd, &passwd_link).unwrap();
        symlink(&group, &group_link).unwrap();
        let users = users_table(&mut caches, ns, &passwd_link).unwrap();
        assert_eq!(users.get_by_uid(1000).unwrap().name, "user");
        let groups = groups_table(&mut caches, ns, &group_link).unwrap();
        assert_eq!(groups.get_by_gid(1000).unwrap().name, "user");
        for path in [&passwd, &group] {
            fs::remove_file(path).unwrap();
            fifo(path);
        }
        assert!(users_table(&mut caches, ns, &passwd_link).is_none());
        assert!(groups_table(&mut caches, ns, &group_link).is_none());
    }

    #[test]
    fn cached_file_swapped_for_fifo() {
        run_child("cached_file_swapped_for_fifo_child");
    }

    #[test]
    fn cached_file_swapped_for_fifo_child() {
        if !is_child() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let db = magic_db::load().unwrap();
        let mut scanner = scanner();
        let (mut caches, ns) = caches();
        let path = dir.path().join("cached");
        fs::write(&path, b"safe").unwrap();
        let cached_path = Path::Std(path.clone());
        assert_digests(
            &caches.get_hashes_in_ns(ns, &cached_path, &db).unwrap(),
            b"safe",
        );
        let scan = caches
            .get_scan_in_ns(ns, &cached_path, Some(&mut scanner), &db)
            .unwrap();
        assert_eq!(scan.signatures.unwrap().as_ref(), ["safe"]);
        assert_eq!(scan.scan_error, None);
        fs::remove_file(&path).unwrap();
        fifo(&path);
        assert!(caches.get_hashes_in_ns(ns, &cached_path, &db).is_err());
        assert!(
            caches
                .get_scan_in_ns(ns, &cached_path, Some(&mut scanner), &db)
                .is_err()
        );
    }

    #[test]
    fn opened_file_survives_path_swap() {
        run_child("opened_file_survives_path_swap_child");
    }

    #[test]
    fn opened_file_survives_path_swap_child() {
        if !is_child() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let db = magic_db::load().unwrap();
        let mut scanner = scanner();
        let original = dir.path().join("original");
        fs::write(&original, b"safe").unwrap();
        let opened = OpenedFile::new(&original).unwrap();
        let scan_opened = OpenedFile::new(&original).unwrap();
        fs::remove_file(&original).unwrap();
        fifo(&original);
        assert_digests(&Hashes::from_file(original, opened, &db), b"safe");
        let size = scan_opened.meta.len();
        let mut reader = scan_opened.reader().unwrap();
        assert_eq!(
            scan_signatures(&mut reader, size, &mut scanner)
                .unwrap()
                .as_ref(),
            ["safe"]
        );
    }

    #[test]
    fn special_files_are_never_opened_for_read() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fifo");
        fifo(&path);

        // a FIFO stands for a device: opening it for read has a visible side effect
        let (tx, rx) = std::sync::mpsc::channel();
        let writer_path = path.clone();
        thread::spawn(move || {
            let _w = OpenOptions::new().write(true).open(&writer_path).unwrap();
            tx.send(()).unwrap();
        });
        thread::sleep(Duration::from_millis(50));

        assert!(OpenedFile::new(&path).is_err());
        let woken = rx.recv_timeout(Duration::from_millis(500)).is_ok();

        // releases the writer; nonblocking so it cannot hang once the writer is gone
        drop(
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&path)
                .unwrap(),
        );
        assert!(!woken, "OpenedFile::new opened a non-regular file for read");
    }

    #[test]
    fn hashes_and_scans_preserve_exact_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(OsString::from_vec(b"file-\xff".to_vec()));
        let data = b"safe\0\xff\n";
        fs::write(&path, data).unwrap();
        let db = magic_db::load().unwrap();
        let hashes = Hashes::from_path_ref(&path, &db);
        assert_eq!(hashes.path, path);
        assert_eq!(hashes.size, data.len() as u64);
        assert_digests(&hashes, data);

        // fresh caches: signatures and hashes share one reader
        let (mut caches, ns) = caches();
        let scan = caches
            .get_scan_in_ns(ns, &Path::Std(path), Some(&mut scanner()), &db)
            .unwrap();
        assert_eq!(scan.signatures.unwrap().as_ref(), ["safe"]);
        assert_eq!(scan.scan_error, None);
        assert_digests(&scan.hashes, data);

        let empty = dir.path().join("empty");
        fs::write(&empty, []).unwrap();
        assert_digests(&Hashes::from_path_ref(&empty, &db), b"");
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source("rule empty { condition: filesize == 0 }")
            .unwrap();
        let mut scanner = Scanner::with_rules(compiler.build());
        let scan = caches
            .get_scan_in_ns(ns, &Path::Std(empty), Some(&mut scanner), &db)
            .unwrap();
        assert_eq!(scan.signatures.unwrap().as_ref(), ["empty"]);
    }

    #[test]
    fn hashes_iterate_in_chunks_and_stop_at_opened_length() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..12_295).map(|i| (i % 251) as u8).collect();
        file.write_all(&data).unwrap();
        let opened = OpenedFile::new(file.path()).unwrap();
        file.write_all(b"appended after metadata").unwrap();
        let hashes = Hashes::from_file(
            file.path().to_path_buf(),
            opened,
            &magic_db::load().unwrap(),
        );
        assert_eq!(hashes.size, data.len() as u64);
        assert_digests(&hashes, &data);
    }

    #[test]
    fn signature_scans_stop_at_opened_length() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"safe").unwrap();
        let opened = OpenedFile::new(file.path()).unwrap();
        file.write_all(b"more").unwrap();
        let size = opened.meta.len();
        let mut reader = opened.reader().unwrap();
        let mut compiler = yara_x::Compiler::new();
        compiler
            .add_source("rule prefix { condition: filesize == 4 and uint32(0) == 0x65666173 }")
            .unwrap();
        let mut scanner = Scanner::with_rules(compiler.build());
        let matches = scan_signatures(&mut reader, size, &mut scanner).unwrap();
        assert_eq!(matches.as_ref(), ["prefix"]);
    }

    #[test]
    fn failed_reads_do_not_publish_partial_hashes() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"safe").unwrap();
        let opened = OpenedFile::new(file.path()).unwrap();
        file.as_file().set_len(2).unwrap();
        let size = opened.meta.len();
        let error =
            scan_signatures(&mut opened.reader().unwrap(), size, &mut scanner()).unwrap_err();
        assert!(
            matches!(&error, Error::IoError(e) if e.kind() == io::ErrorKind::UnexpectedEof),
            "{error}"
        );

        file.as_file().set_len(4).unwrap();
        let opened = OpenedFile::new(file.path()).unwrap();
        file.as_file().set_len(0).unwrap();
        let db = magic_db::load().unwrap();
        assert_no_digests(&Hashes::from_file(file.path().to_path_buf(), opened, &db));

        file.as_file().set_len(4).unwrap();
        let opened = unreadable(file.as_file().metadata().unwrap());
        assert_no_digests(&Hashes::from_file(file.path().to_path_buf(), opened, &db));
    }

    #[test]
    fn reader_failures_keep_cache_hits() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"safe").unwrap();
        let opened = || unreadable(file.as_file().metadata().unwrap());
        let db = magic_db::load().unwrap();
        let mut scanner = scanner();
        let (mut caches, ns) = caches();
        let path = Path::Std(file.path().to_path_buf());
        let key = Key::from_path_and_meta(ns, &path, &opened().meta).unwrap();

        let scan = caches.scan_file(opened(), key.clone(), Some(&mut scanner), &db);
        assert!(scan.signatures.is_none());
        assert!(scan.scan_error.unwrap().contains("reopen"));
        assert_no_digests(&scan.hashes);
        assert_eq!(scan.hashes.size, 4);
        assert!(caches.hashes.contains_key(&key));
        assert!(caches.signatures.is_empty());

        let cached = Arc::new(Hashes::with_error(key.path.clone(), 1, "cached".into()));
        caches.hashes.insert(key.clone(), Arc::clone(&cached));
        let scan = caches.scan_file(opened(), key.clone(), Some(&mut scanner), &db);
        assert!(Arc::ptr_eq(&scan.hashes, &cached));
        assert!(scan.signatures.is_none());
        assert!(scan.scan_error.unwrap().contains("reopen"));

        caches.hashes.remove(&key);
        caches
            .signatures
            .insert(key.clone(), Arc::from(["cached".to_string()]));
        let scan = caches.scan_file(opened(), key, Some(&mut scanner), &db);
        assert_eq!(scan.signatures.unwrap().as_ref(), ["cached"]);
        assert_eq!(scan.scan_error, None);
        assert!(scan.hashes.error.as_ref().unwrap().contains("reopen"));
        assert_eq!(scan.hashes.size, 4);
    }

    fn key(path: &std::path::Path) -> Key {
        Key::from_path_in_ns(Mnt::default(), &Path::Std(path.to_path_buf())).unwrap()
    }

    fn copy_times(file: &File, meta: &fs::Metadata) {
        let times = fs::FileTimes::new()
            .set_accessed(meta.accessed().unwrap())
            .set_modified(meta.modified().unwrap());
        file.set_times(times).unwrap();
    }

    #[test]
    fn key_changes_when_file_renamed_over() {
        let dir = tempfile::tempdir().unwrap();
        let (benign, evil) = (dir.path().join("a"), dir.path().join("b"));
        fs::write(&benign, b"safe").unwrap();
        fs::write(&evil, b"evil").unwrap();
        let cached = key(&benign);

        let evil_file = File::options().write(true).open(&evil).unwrap();
        copy_times(&evil_file, &fs::metadata(&benign).unwrap());
        fs::rename(&evil, &benign).unwrap();
        assert_ne!(key(&benign), cached);
    }

    #[test]
    fn key_changes_when_rewritten_in_place() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"safe").unwrap();
        let meta = fs::metadata(file.path()).unwrap();
        let cached = key(file.path());

        // kernels without multigrain timestamps update ctime from a coarse clock
        thread::sleep(Duration::from_millis(20));
        file.as_file().write_all_at(b"evil", 0).unwrap();
        copy_times(file.as_file(), &meta);
        assert_ne!(key(file.path()), cached);
    }

    fn ebpf_meta(meta: &fs::Metadata) -> kunai_common::path::Metadata {
        kunai_common::path::Metadata {
            ino: meta.ino(),
            size: meta.size() as i64,
            atime: Time::new(meta.atime(), meta.atime_nsec()),
            mtime: Time::new(meta.mtime(), meta.mtime_nsec()),
            ctime: Time::new(meta.ctime(), meta.ctime_nsec()),
            ..Default::default()
        }
    }

    #[test]
    fn bpf_key_rejects_rewrite_since_kernel_event() {
        let file = tempfile::NamedTempFile::new().unwrap();
        fs::write(file.path(), b"safe").unwrap();
        let meta = fs::metadata(file.path()).unwrap();
        let path = Path::Bpf {
            path: file.path().to_path_buf(),
            ebpf_meta: Some(ebpf_meta(&meta)),
        };
        assert!(Key::from_path_in_ns(Mnt::default(), &path).is_ok());

        // coarse ctime clock, see key_changes_when_rewritten_in_place
        thread::sleep(Duration::from_millis(20));
        file.as_file().write_all_at(b"evil", 0).unwrap();
        copy_times(file.as_file(), &meta);
        let err = Key::from_path_in_ns(Mnt::default(), &path).unwrap_err();
        assert!(err.to_string().contains("ctime changed"), "{err}");
    }

    #[test]
    fn oversized_yara_scans_only_the_bounded_prefix() {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(b"safe").unwrap();
        file.as_file()
            .write_all_at(b"outside-the-budget", FILE_SIZE_SCAN_LIMIT)
            .unwrap();
        let source = format!(
            "rule prefix {{ strings: $s = \"safe\" condition: $s at 0 and filesize == \
             {FILE_SIZE_SCAN_LIMIT} }}\nrule excluded {{ strings: $s = \"outside-the-budget\" \
             condition: $s }}"
        );
        let mut compiler = yara_x::Compiler::new();
        compiler.add_source(source.as_str()).unwrap();
        let mut scanner = Scanner::with_rules(compiler.build());
        let (mut caches, ns) = caches();
        let db = magic_db::load().unwrap();
        let scan = caches
            .get_scan_in_ns(
                ns,
                &Path::Std(file.path().to_path_buf()),
                Some(&mut scanner),
                &db,
            )
            .unwrap();
        assert_eq!(scan.signatures.unwrap().as_ref(), ["prefix"]);
        assert_eq!(
            scan.scan_error.as_deref(),
            Some("partial scan, file size exceeds scan limit")
        );
        assert_eq!(
            scan.hashes.error,
            Some(Error::FileSizeScanLimit.to_string())
        );
    }

    #[test]
    fn oversized_files_skip_hashing_but_keep_magic() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(FILE_SIZE_SCAN_LIMIT + 1).unwrap();
        let hashes = Hashes::from_path_ref(file.path(), &magic_db::load().unwrap());
        assert_eq!(hashes.size, FILE_SIZE_SCAN_LIMIT + 1);
        assert_eq!(hashes.error, Some(Error::FileSizeScanLimit.to_string()));
        assert_no_digests(&hashes);
        assert_ne!(hashes.magic, "?");
    }
}
