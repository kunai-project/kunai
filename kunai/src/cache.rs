use json::{object, JsonValue};
use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    collections::HashMap,
    fs::{self, File},
    io::{self, BufReader, Read},
    os::unix::prelude::MetadataExt,
    path::{Path, PathBuf},
    time::SystemTime,
};
use thiserror::Error;

use crate::util::namespaces::{self, MntNamespace};

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown namespace inum={0}")]
    UnknownNs(u32),
    #[error("{0}")]
    Namespace(#[from] namespaces::Error),
    #[error("{0}")]
    IoError(#[from] io::Error),
    #[error("file changed since kernel event")]
    FileModSinceKernelEvent,
    #[error("metadata is needed for ebpf path")]
    MetadataRequired,
    #[error("hash not found")]
    HashNotFound,
}

#[derive(Debug, Default, Clone)]
pub struct Hashes {
    pub file: PathBuf,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub tlsh: String,
    pub size: usize,
    pub error: Option<String>,
}

impl From<Hashes> for JsonValue {
    fn from(value: Hashes) -> Self {
        let mut out = object! {
            file: value.file.to_string_lossy().to_string(),
            md5: value.md5,
            sha1: value.sha1,
            sha256: value.sha256,
            sha512: value.sha512,
            size: value.size,
        };

        if value.error.is_some() {
            out["error"] = value.error.unwrap().into();
        }

        out
    }
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
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct Key {
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
    pub fn from_ebpf_path_ref_with_ns(
        ns: &MntNamespace,
        path: &kunai_common::path::Path,
    ) -> Result<Self, Error> {
        let pb = path.to_path_buf();
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
        //k.created = meta.created().unwrap_or(SystemTime::UNIX_EPOCH);
        k.accessed = ebpf_meta.atime.into_system_time();

        if k.size != meta.size() || ebpf_meta.ino != meta.ino() {
            return Err(Error::FileModSinceKernelEvent);
        }

        if let Ok(atime) = meta.accessed() {
            if atime != k.accessed {
                return Err(Error::FileModSinceKernelEvent);
            }
        }

        if let Ok(mtime) = meta.modified() {
            if mtime != k.modified {
                return Err(Error::FileModSinceKernelEvent);
            }
        }

        Ok(k)
    }
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

struct NsEntry {
    ns: MntNamespace,
    hostname: Option<String>,
}

pub struct Cache {
    ns: HashMap<u32, NsEntry>,
    hcache: LruHashMap<Key, Hashes>,
}

impl Cache {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        Cache {
            ns: HashMap::new(),
            hcache: LruHashMap::with_max_entries(cap),
        }
    }

    #[inline]
    pub fn cache_ns(&mut self, pid: i32, ns_inum: u32) -> Result<(), Error> {
        self.ns.entry(ns_inum).or_insert(NsEntry {
            ns: MntNamespace::open_with_procfs(pid, ns_inum).map_err(Error::Namespace)?,
            hostname: None,
        });
        Ok(())
    }

    #[inline]
    pub fn get_hostname(&mut self, ns_inum: u32) -> Result<String, Error> {
        let entry = self.ns.get_mut(&ns_inum).ok_or(Error::UnknownNs(ns_inum))?;

        if entry.hostname.is_none() {
            entry.ns.enter()?;
            let hostname = fs::read_to_string("/etc/hostname").unwrap_or("?".into());
            entry.hostname = Some(hostname.trim_end().into());
            entry.ns.exit().expect("failed to restore namespace");
        }

        Ok(entry.hostname.as_ref().unwrap().clone())
    }

    #[inline]
    pub fn get_or_cache_in_ns(
        &mut self,
        ns_inum: u32,
        path: &kunai_common::path::Path,
    ) -> Result<Hashes, Error> {
        let Some(entry) = self.ns.get(&ns_inum) else {
            return Err(Error::UnknownNs(ns_inum));
        };

        let mut ret = Err(Error::HashNotFound);

        entry.ns.enter()?;
        let pb = path.to_path_buf();

        if pb.exists() {
            let key = Key::from_ebpf_path_ref_with_ns(&entry.ns, path)?;

            if !self.hcache.contains_key(&key) {
                let h = Hashes::from_path_ref(pb);
                self.hcache.insert(key.clone(), h);
            }

            // we cannot panic here as we are sure the cache contains value
            ret = Ok(self.hcache.get(&key).unwrap().clone());
        }

        // we must be sure that we restore our namespace
        entry.ns.exit().expect("failed to restore namespace");
        ret
    }
}
