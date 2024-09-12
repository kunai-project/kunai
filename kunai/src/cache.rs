use gene::{FieldGetter, FieldValue};
use gene_derive::FieldGetter;

use kunai_common::time::Time;
use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    borrow::Cow,
    fs::File,
    io::{self, BufReader, Read},
    os::unix::prelude::MetadataExt,
    path::PathBuf,
    time::SystemTime,
};
use thiserror::Error;

use crate::{
    util::{
        defer::defer,
        namespaces::{self, Kind, Namespace, Switcher},
    },
    yara::Scanner,
};

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
    #[error("yara scan error: {0}")]
    ScanError(#[from] yara_x::errors::ScanError),
}

#[derive(Debug, Default, Clone, FieldGetter, Serialize, Deserialize)]
pub struct FileMeta {
    pub md5: String,
    pub sha1: String,
    pub sha256: String,
    pub sha512: String,
    pub size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
    pub file: PathBuf,
    #[serde(flatten)]
    pub meta: FileMeta,
}

impl Hashes {
    pub fn from_path_ref<T: AsRef<std::path::Path>>(p: T) -> Self {
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
                h.meta.size += n;
            }

            h.meta.md5 = hex::encode(md5.finalize());
            h.meta.sha1 = hex::encode(sha1.finalize());
            h.meta.sha256 = hex::encode(sha256.finalize());
            h.meta.sha512 = hex::encode(sha512.finalize());
        }

        h
    }

    #[inline]
    pub(crate) fn iocs(&self) -> Vec<Cow<'_, str>> {
        let mut v = vec![self.file.to_string_lossy()];
        v.extend(self.meta.iocs());
        v
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
    fn from_path_with_ns(ns: &Namespace, path: &Path) -> Result<Self, Error> {
        let pb = path.to_path_buf();

        // checking if the file still exists
        if !pb.exists() {
            return Err(Error::FileNotFound);
        }

        let meta = pb.metadata()?;

        let k = Key {
            mnt_namespace: ns.inum,
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

struct CachedNs {
    switcher: namespaces::Switcher,
}

pub struct Cache {
    namespaces: LruHashMap<Namespace, CachedNs>,
    hashes: LruHashMap<Key, Hashes>,
    // since hashes and signatures are not computed
    // at the same time. It seems a better option
    // to separate into two HashMaps to prevent
    // any race
    signatures: LruHashMap<Key, Vec<String>>,
}

impl Cache {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        Cache {
            namespaces: LruHashMap::with_max_entries(128),
            hashes: LruHashMap::with_max_entries(cap),
            signatures: LruHashMap::with_max_entries(cap),
        }
    }

    #[inline]
    pub fn cache_ns(&mut self, pid: i32, ns: Namespace) -> Result<(), Error> {
        if !self.namespaces.contains_key(&ns) {
            self.namespaces.insert(
                ns,
                CachedNs {
                    switcher: Switcher::new(ns.kind, pid as u32).map_err(Error::Namespace)?,
                },
            );
            debug_assert!(self.namespaces.contains_key(&ns));
        }
        Ok(())
    }

    #[inline]
    pub fn get_sig_or_cache(
        &mut self,
        ns: Namespace,
        path: &Path,
        scanner: &mut Scanner<'_>,
    ) -> Result<Vec<String>, Error> {
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

        // we switch to a cached namespace that holds opened
        // file descriptors to namespaces
        entry.switcher.enter()?;
        // we must be sure that we restore our namespace
        defer!(|| { entry.switcher.exit().expect("failed to restore namespace") });

        // we get a PathBuf as path ownership is passed down
        let pb = path.to_path_buf();
        // we create key to check if we already have cached
        // signatures for that file
        let key = Key::from_path_with_ns(&ns, path)?;

        let sigs = match self.signatures.get(&key) {
            // we have caches signatures
            Some(sig) => sig.clone(),
            // we don't have cached signatures
            None => {
                let mut sigs = vec![];
                // lock should never fail as the scanner is used only in one thread
                let mut yx_scanner = scanner.lock().expect("failed to lock yara scanner");
                let sr = yx_scanner.scan_file(pb)?;
                // we extend the list of signatures
                sigs.extend(sr.matching_rules().map(|m| m.identifier().to_string()));
                // we update our cache
                self.signatures.insert(key.clone(), sigs.clone());
                sigs
            }
        };

        Ok(sigs)
    }

    #[inline]
    pub fn get_or_cache_in_ns(&mut self, ns: Namespace, path: &Path) -> Result<Hashes, Error> {
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
        // we must be sure that we restore our namespace
        defer!(|| { entry.switcher.exit().expect("failed to restore namespace") });

        let pb = path.to_path_buf();

        let key = Key::from_path_with_ns(&ns, path)?;

        if !self.hashes.contains_key(&key) {
            let h = Hashes::from_path_ref(pb);
            self.hashes.insert(key.clone(), h);
        }

        // we cannot panic here as we are sure the cache contains value
        let res = Ok(self.hashes.get(&key).unwrap().clone());

        res
    }
}
