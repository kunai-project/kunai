use event_derive::FieldGetter;
use gene::{FieldGetter, FieldValue};

use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    borrow::Cow,
    collections::HashMap,
    fs::File,
    io::{self, BufReader, Read},
    os::unix::prelude::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};
use thiserror::Error;

use crate::util::namespaces::{self, Kind, Namespace, Switcher};

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown namespace expected={exp} got={got}")]
    WrongNsKind { exp: Kind, got: Kind },
    #[error("unknown namespace {0}")]
    UnknownNs(Namespace),
    #[error("{0}")]
    Namespace(#[from] namespaces::Error),
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("file changed since kernel event: {0}")]
    FileModSinceKernelEvent(&'static str),
    #[error("metadata is needed for ebpf path")]
    MetadataRequired,
    #[error("file not found")]
    FileNotFound,
}

#[derive(Debug, Default, Clone, FieldGetter, Serialize, Deserialize)]
pub struct Hashes {
    pub file: PathBuf,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Hashes {
    pub fn from_path_ref<T: AsRef<Path>>(p: T) -> Self {
        let path = p.as_ref();
        let mut h = Hashes {
            file: path.to_path_buf(),
            ..Hashes::default()
        };
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();

        if let Ok(f) = File::open(path) {
            let mut reader = BufReader::new(f);
            let mut buf = [0; 4096];
            while let Ok(n) = reader.read(&mut buf[..]) {
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
        }

        h
    }

    #[inline]
    pub(crate) fn iocs(&self) -> Vec<Cow<'_, str>> {
        vec![
            self.file.to_string_lossy(),
            self.md5.as_str().into(),
            self.sha1.as_str().into(),
            self.sha256.as_str().into(),
            self.sha512.as_str().into(),
        ]
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
struct Key {
    mnt_namespace: u32,
    path: PathBuf,
    size: u64,
    modified: SystemTime,
    created: SystemTime,
    accessed: SystemTime,
}

impl Default for Key {
    fn default() -> Self {
        Key {
            mnt_namespace: 0,
            path: PathBuf::default(),
            size: 0,
            modified: SystemTime::UNIX_EPOCH,
            created: SystemTime::UNIX_EPOCH,
            accessed: SystemTime::UNIX_EPOCH,
        }
    }
}

impl Key {
    fn from_ebpf_path_ref_with_ns(
        ns: &Namespace,
        path: &kunai_common::path::Path,
    ) -> Result<Self, Error> {
        let pb = path.to_path_buf();

        // checking if the file still exists
        if !pb.exists() {
            return Err(Error::FileNotFound);
        }

        let meta = pb.metadata()?;

        let mut k = Key {
            mnt_namespace: ns.inum,
            path: path.to_path_buf(),
            ..Default::default()
        };

        // we don't have to switch to ns here as it is done in caller
        let ebpf_meta = path.metadata.ok_or(Error::MetadataRequired)?;
        k.size = ebpf_meta.size as u64;
        k.modified = ebpf_meta.mtime.into_system_time();
        k.accessed = ebpf_meta.atime.into_system_time();

        if k.size != meta.size() {
            return Err(Error::FileModSinceKernelEvent("inode changed"));
        }

        if ebpf_meta.ino != meta.ino() {
            return Err(Error::FileModSinceKernelEvent("sized changed"));
        }

        if let Ok(mtime) = meta.modified() {
            if mtime != k.modified {
                return Err(Error::FileModSinceKernelEvent("mtime changed"));
            }
        }

        Ok(k)
    }
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

struct CachedNs {
    switcher: namespaces::Switcher,
}

pub struct Cache {
    namespaces: HashMap<Namespace, CachedNs>,
    hashes: LruHashMap<Key, Hashes>,
}

impl Cache {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        Cache {
            namespaces: HashMap::new(),
            hashes: LruHashMap::with_max_entries(cap),
        }
    }

    #[inline]
    pub fn cache_ns(&mut self, pid: i32, ns: Namespace) -> Result<(), Error> {
        self.namespaces.entry(ns).or_insert(CachedNs {
            switcher: Switcher::new(ns.kind, pid as u32).map_err(Error::Namespace)?,
        });
        Ok(())
    }

    #[inline]
    pub fn get_or_cache_in_ns(
        &mut self,
        ns: Namespace,
        path: &kunai_common::path::Path,
    ) -> Result<Hashes, Error> {
        // check that the namespace is a mount namespace
        if !ns.is_kind(Kind::Mnt) {
            return Err(Error::WrongNsKind {
                exp: Kind::Mnt,
                got: ns.kind,
            });
        }

        let Some(entry) = self.namespaces.get(&ns) else {
            return Err(Error::UnknownNs(ns));
        };

        // we switch to namespace
        entry.switcher.enter()?;
        let pb = path.to_path_buf();

        let key = Key::from_ebpf_path_ref_with_ns(&ns, path)?;

        if !self.hashes.contains_key(&key) {
            let h = Hashes::from_path_ref(pb);
            self.hashes.insert(key.clone(), h);
        }

        // we cannot panic here as we are sure the cache contains value
        let res = Ok(self.hashes.get(&key).unwrap().clone());

        // we must be sure that we restore our namespace
        entry.switcher.exit().expect("failed to restore namespace");

        res
    }
}
