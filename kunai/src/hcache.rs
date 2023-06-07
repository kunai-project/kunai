use json::{object, JsonValue};
use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    collections::HashMap,
    io,
    path::{Path, PathBuf},
    time::SystemTime,
};
use thiserror::Error;
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, BufReader},
};

use crate::util::namespaces::{self, MntNamespace};

#[derive(Debug, Default, Clone)]
pub struct Hashes {
    pub file: PathBuf,
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub tlsh: String,
    pub size: usize,
}

impl From<Hashes> for JsonValue {
    fn from(value: Hashes) -> Self {
        object! {
            file: value.file.to_string_lossy().to_string(),
            md5: value.md5,
            sha1: value.sha1,
            sha256: value.sha256,
            sha512: value.sha512,
            size: value.size,
        }
    }
}

impl Hashes {
    pub async fn from_path_ref<T: AsRef<Path>>(p: T) -> Self {
        let path = p.as_ref();
        let mut h = Hashes {
            file: path.to_path_buf(),
            ..Hashes::default()
        };
        let mut md5 = Md5::new();
        let mut sha1 = Sha1::new();
        let mut sha256 = Sha256::new();
        let mut sha512 = Sha512::new();

        if let Ok(f) = File::open(path).await {
            let mut reader = BufReader::new(f);
            let mut buf = [0; 4096];
            while let Ok(n) = reader.read(&mut buf[..]).await {
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
    pub async fn from_path_ref<T: AsRef<Path>>(r: T) -> Self {
        let path = r.as_ref();
        let mut k = Key {
            path: path.to_path_buf(),
            ..Default::default()
        };
        if let Ok(meta) = fs::metadata(r).await {
            k.size = meta.len();
            k.modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            k.created = meta.created().unwrap_or(SystemTime::UNIX_EPOCH);
            k.accessed = meta.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
        }
        k
    }

    pub async fn from_path_ref_with_ns<T: AsRef<Path>>(ns: &MntNamespace, p: T) -> Self {
        let path = p.as_ref();
        let mut k = Key {
            mnt_namespace: ns.inum,
            path: path.to_path_buf(),
            ..Default::default()
        };
        ns.switch();
        if let Ok(meta) = fs::metadata(p).await {
            k.size = meta.len();
            k.modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            k.created = meta.created().unwrap_or(SystemTime::UNIX_EPOCH);
            k.accessed = meta.accessed().unwrap_or(SystemTime::UNIX_EPOCH);
        }
        ns.restore();
        k
    }
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

pub struct FsCache {
    ns: HashMap<u32, MntNamespace>,
    hcache: LruHashMap<Key, Hashes>,
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("unknown namespace inum={0}")]
    UnknownNs(u32),
    #[error("Namespace creation failed: {0}")]
    NsCreate(#[from] namespaces::Error),
}

impl FsCache {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        FsCache {
            ns: HashMap::new(),
            hcache: LruHashMap::with_max_entries(cap),
        }
    }

    #[inline]
    pub fn cache_ns(&mut self, pid: i32, ns_inum: u32) -> Result<(), Error> {
        self.ns
            .entry(ns_inum)
            .or_insert(MntNamespace::from_pid_with_inum(pid, ns_inum).map_err(Error::NsCreate)?);
        Ok(())
    }

    pub async fn cache_with_ns<T: AsRef<Path>>(&mut self, ns_inum: u32, p: T) -> Result<(), Error> {
        let path = p.as_ref();

        let ns = self.ns.get(&ns_inum).ok_or(Error::UnknownNs(ns_inum))?;

        ns.switch();
        if path.exists() {
            let key = Key::from_path_ref_with_ns(ns, path).await;

            if !self.hcache.contains_key(&key) {
                let h = Hashes::from_path_ref(path).await;
                self.hcache.insert(key, h);
            }
        }
        ns.restore();
        Ok(())
    }

    pub async fn cache<T: AsRef<Path>>(&mut self, p: T) {
        let path = p.as_ref();

        if !path.exists() {
            return;
        }

        let key = Key::from_path_ref(path).await;

        if !self.hcache.contains_key(&key) {
            let h = Hashes::from_path_ref(path).await;
            self.hcache.insert(key, h);
        }
    }

    pub async fn get_or_cache<T: AsRef<Path>>(&mut self, p: T) -> Option<Hashes> {
        let path = p.as_ref();

        if !path.exists() {
            return None;
        }

        let key = Key::from_path_ref(path).await;

        if !self.hcache.contains_key(&key) {
            let h = Hashes::from_path_ref(path).await;
            self.hcache.insert(key, h.clone());
            return Some(h);
        }

        // we cannot panic here as we are sure the cache contains value
        Some(self.hcache.get(&key).unwrap().clone())
    }

    pub async fn get_or_cache_with_ns<T: AsRef<Path>>(
        &mut self,
        ns_inum: u32,
        p: T,
    ) -> Option<Hashes> {
        let path = p.as_ref();

        let ns = self.ns.get(&ns_inum)?;
        let mut ret = None;

        // so that we can switch to other namespaces
        ns.switch().unwrap();
        if path.exists() {
            let key = Key::from_path_ref_with_ns(ns, path).await;

            if !self.hcache.contains_key(&key) {
                let h = Hashes::from_path_ref(path).await;
                self.hcache.insert(key.clone(), h.clone());
            }

            // we cannot panic here as we are sure the cache contains value
            ret = Some(self.hcache.get(&key).unwrap().clone());
        }
        // we must be sure that we restore our namespace
        //namespaces::unshare(libc::CLONE_FS).unwrap();
        ns.restore().unwrap();
        ret
    }
}
