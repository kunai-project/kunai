use gene::{FieldGetter, FieldValue};
use gene_derive::FieldGetter;

use kunai_common::time::Time;
use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use pure_magic::MagicDb;

use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    borrow::Cow,
    fs::File,
    io::{self, Read},
    os::unix::prelude::MetadataExt,
    path::PathBuf,
    time::SystemTime,
};
use thiserror::Error;

use crate::{
    util::{
        account::{Group, Groups, User, Users},
        namespace::{self, Mnt, Switcher},
    },
    yara::Scanner,
};

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown namespace {0}")]
    UnknownMntNs(Mnt),
    #[error("{0}")]
    Namespace(#[from] namespace::Error),
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("file changed since kernel event: {0}")]
    FileModSinceKernelEvent(&'static str),
    #[error("metadata is needed for ebpf path")]
    MetadataRequired,
    #[error("yara scan error: {0}")]
    ScanError(#[from] yara_x::errors::ScanError),
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
    pub size: usize,
    pub error: Option<String>,
}

impl From<Hashes> for FileMeta {
    fn from(value: Hashes) -> Self {
        Self {
            magic: value.magic,
            md5: value.md5,
            sha1: value.sha1,
            sha256: value.sha256,
            sha512: value.sha512,
            size: value.size,
            error: value.error,
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

#[derive(Debug, Default, Clone, FieldGetter, Serialize, Deserialize)]
pub struct Hashes {
    pub path: PathBuf,
    pub magic: String,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub size: usize,
    pub error: Option<String>,
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

    #[inline(always)]
    pub fn from_path_ref<T: AsRef<std::path::Path>>(p: T, magic_db: &MagicDb) -> Self {
        let path = p.as_ref();
        let mut h = Hashes {
            path: path.to_path_buf(),
            ..Hashes::default()
        };
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();

        if let Ok(mut f) = File::open(path)
            .inspect_err(|e| {
                h.error = Some(format!("failed to open file: {e}",));
            })
            .and_then(MagicDb::optimal_lazy_cache)
            .inspect_err(|e| {
                h.error = Some(format!("failed to create lazy cache: {e}",));
            })
        {
            let mut buf = [0; 4096];
            while let Ok(n) = f.read(&mut buf[..]).inspect_err(|e| {
                h.error = Some(format!("failed to read: {e}",));
            }) {
                if n == 0 {
                    break;
                }
                md5.update(&buf[..n]);
                sha1.update(&buf[..n]);
                sha256.update(&buf[..n]);
                sha512.update(&buf[..n]);
                h.size += n;
            }

            h.md5 = hex::encode(md5.finalize());
            h.sha1 = hex::encode(sha1.finalize());
            h.sha256 = hex::encode(sha256.finalize());
            h.sha512 = hex::encode(sha512.finalize());

            h.magic = magic_db
                .first_magic_with_lazy_cache(&mut f, None)
                .inspect_err(|e| {
                    h.error = Some(format!("failed to find magic: {e}",));
                })
                .map(|m| m.message())
                .unwrap_or("?".into());
        }

        h
    }

    #[inline(always)]
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
            ebpf_meta: value.metadata,
        }
    }
}

impl Path {
    #[inline]
    pub fn to_path_buf(&self) -> &PathBuf {
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
    size: u64,
    modified: SystemTime,
    created: SystemTime,
    accessed: SystemTime,
}

impl Default for Key {
    fn default() -> Self {
        Key {
            mnt_namespace: Mnt::default(),
            path: PathBuf::default(),
            size: 0,
            modified: SystemTime::UNIX_EPOCH,
            created: SystemTime::UNIX_EPOCH,
            accessed: SystemTime::UNIX_EPOCH,
        }
    }
}

impl Key {
    #[inline(always)]
    fn from_path_in_ns(ns: Mnt, path: &Path) -> Result<Self, Error> {
        let pb = path.to_path_buf();

        // checking if the file still exists
        if !pb.exists() {
            // return a io::Error instead of custom error
            return Err(io::Error::new(io::ErrorKind::NotFound, "file not found").into());
        }

        let meta = pb.metadata()?;

        let k = Key {
            mnt_namespace: ns,
            path: pb.clone(),
            size: meta.size(),
            modified: SystemTime::from(&Time::new(meta.mtime(), meta.mtime_nsec())),
            accessed: SystemTime::from(&Time::new(meta.atime(), meta.atime_nsec())),
            ..Default::default()
        };

        // we do extra checks if it is a Path comming from our probes
        // this way we can catch eventual file tampering attempts
        if let Path::Bpf { path: _, ebpf_meta } = path {
            // we don't have to switch to ns here as it is done in caller
            let ebpf_meta = ebpf_meta.ok_or(Error::MetadataRequired)?;

            if k.size != meta.size() {
                return Err(Error::FileModSinceKernelEvent("size changed"));
            }

            if ebpf_meta.ino != meta.ino() {
                return Err(Error::FileModSinceKernelEvent("inode changed"));
            }

            if let Ok(mtime) = meta.modified() {
                if mtime != k.modified {
                    return Err(Error::FileModSinceKernelEvent("mtime changed"));
                }
            }
        }

        Ok(k)
    }
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

pub struct Cache {
    mnt_namespaces: LruHashMap<Mnt, namespace::Switcher<Mnt>>,
    hashes: LruHashMap<Key, Hashes>,
    users: LruHashMap<Key, Users>,
    groups: LruHashMap<Key, Groups>,
    // since hashes and signatures are not computed
    // at the same time. It seems a better option
    // to separate into two HashMaps to prevent
    // any race
    signatures: LruHashMap<Key, Vec<String>>,
}

const NS_CACHE_SIZE: usize = 256;

impl Cache {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        Cache {
            mnt_namespaces: LruHashMap::with_max_entries(NS_CACHE_SIZE),
            users: LruHashMap::with_max_entries(NS_CACHE_SIZE),
            groups: LruHashMap::with_max_entries(NS_CACHE_SIZE),
            hashes: LruHashMap::with_max_entries(cap),
            signatures: LruHashMap::with_max_entries(cap),
        }
    }

    #[inline(always)]
    pub fn cache_mnt_ns(&mut self, pid: i32, ns: Mnt) -> Result<(), Error> {
        if !self.mnt_namespaces.contains_key(&ns) {
            self.mnt_namespaces
                .insert(ns, Switcher::new(pid as u32).map_err(Error::Namespace)?);
            debug_assert!(self.mnt_namespaces.contains_key(&ns));
        }
        Ok(())
    }

    /// Get a [User] structure corresponding to user id `uid`
    #[inline(always)]
    pub fn get_user_group_in_ns(
        &mut self,
        ns: Mnt,
        uid: u32,
        gid: u32,
    ) -> Result<(Option<&User>, Option<&Group>), Error> {
        let Some(mnt_ns) = self.mnt_namespaces.get(&ns) else {
            return Err(Error::UnknownMntNs(ns));
        };

        // we haven't yet parsed users and groups or we don't find an entry
        let user_group = mnt_ns.do_in_namespace(|| {
            let user_path = PathBuf::from(Users::sys_path());

            // we must explicitely return a not found error if the file is missing
            // it avoids multiple layers of io error wrapping and complex analysis of
            // namespace::Error:Other variant to detect missing file
            if !user_path.exists() {
                return Err(namespace::Error::other(io::Error::new(
                    io::ErrorKind::NotFound,
                    "user file not found",
                )));
            }

            // getting user
            let ukey =
                Key::from_path_in_ns(ns, &user_path.into()).map_err(namespace::Error::other)?;

            if !self.users.contains_key(&ukey) {
                self.users.insert(
                    ukey.clone(),
                    Users::from_sys().map_err(namespace::Error::other)?,
                );
            }

            let user = self.users.get(&ukey).and_then(|u| u.get_by_uid(uid));

            let group_path = PathBuf::from(Groups::sys_path());

            if !group_path.exists() {
                return Err(namespace::Error::other(io::Error::new(
                    io::ErrorKind::NotFound,
                    "group file not found",
                )));
            }

            // getting group
            let gkey =
                Key::from_path_in_ns(ns, &group_path.into()).map_err(namespace::Error::other)?;

            if !self.groups.contains_key(&gkey) {
                self.groups.insert(
                    gkey.clone(),
                    Groups::from_sys().map_err(namespace::Error::other)?,
                );
            }

            let group = self.groups.get(&gkey).and_then(|g| g.get_by_gid(gid));

            Ok((user, group))
        })?;

        Ok(user_group)
    }

    #[inline(always)]
    pub fn get_sig_in_ns(
        &mut self,
        ns: Mnt,
        path: &Path,
        scanner: &mut Scanner<'_>,
    ) -> Result<Vec<String>, Error> {
        let Some(mnt_ns) = self.mnt_namespaces.get(&ns) else {
            return Err(Error::UnknownMntNs(ns));
        };

        let res = mnt_ns.do_in_namespace(|| {
            // we get a PathBuf as path ownership is passed down
            let pb = path.to_path_buf();
            // we create key to check if we already have cached
            // signatures for that file
            let key = Key::from_path_in_ns(ns, path).map_err(namespace::Error::other)?;

            let sigs = match self.signatures.get(&key) {
                // we have caches signatures
                Some(sig) => sig.clone(),
                // we don't have cached signatures
                None => {
                    let mut sigs = vec![];
                    // lock should never fail as the scanner is used only in one thread
                    let mut yx_scanner = scanner.lock().expect("failed to lock yara scanner");
                    let sr = yx_scanner.scan_file(pb).map_err(namespace::Error::other)?;
                    // we extend the list of signatures
                    sigs.extend(sr.matching_rules().map(|m| m.identifier().to_string()));
                    // we update our cache
                    self.signatures.insert(key.clone(), sigs.clone());
                    sigs
                }
            };

            Ok(sigs)
        });

        // we must be sure that we restore our namespace
        if matches!(res.as_ref(), Err(namespace::Error::Exit(_, _, _))) {
            res.as_ref().expect("failed to restore namespace");
        }

        res.map_err(Error::from)
    }

    #[inline(always)]
    pub fn get_hashes_in_ns(
        &mut self,
        ns: Mnt,
        path: &Path,
        magic_db: &MagicDb,
    ) -> Result<Hashes, Error> {
        let Some(mnt_ns) = self.mnt_namespaces.get(&ns) else {
            return Err(Error::UnknownMntNs(ns));
        };

        let res = mnt_ns.do_in_namespace(|| {
            let pb = path.to_path_buf();

            let key = Key::from_path_in_ns(ns, path).map_err(namespace::Error::other)?;

            if !self.hashes.contains_key(&key) {
                let h = Hashes::from_path_ref(pb, magic_db);
                self.hashes.insert(key.clone(), h);
            }

            // we cannot panic here as we are sure the cache contains value
            Ok(self.hashes.get(&key).unwrap().clone())
        });

        // we must be sure that we restore our namespace
        if matches!(res.as_ref(), Err(namespace::Error::Exit(_, _, _))) {
            res.as_ref().expect("failed to restore namespace");
        }

        res.map_err(Error::from)
    }
}
