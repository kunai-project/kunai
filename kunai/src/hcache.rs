use json::{object, JsonValue};
use lru_st::collections::LruHashMap;
use md5::{Digest, Md5};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::{
    path::{Path, PathBuf},
    time::SystemTime,
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, BufReader},
};

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
    path: PathBuf,
    size: u64,
    modified: SystemTime,
    created: SystemTime,
    accessed: SystemTime,
}

impl Default for Key {
    fn default() -> Self {
        Key {
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
}

unsafe impl Send for Key {}
unsafe impl Sync for Key {}

pub struct Hcache {
    cache: LruHashMap<Key, Hashes>,
}

impl Hcache {
    // Constructs a new Hcache
    pub fn with_max_entries(cap: usize) -> Self {
        Hcache {
            cache: LruHashMap::with_max_entries(cap),
        }
    }

    pub async fn get_or_cache<T: AsRef<Path>>(&mut self, p: T) -> Option<Hashes> {
        let path = p.as_ref();

        if !path.exists() {
            return None;
        }

        let key = Key::from_path_ref(path).await;

        if !self.cache.contains_key(&key) {
            let h = Hashes::from_path_ref(path).await;
            self.cache.insert(key, h.clone());
            return Some(h);
        }

        // we cannot panic here as we are sure the cache contains value
        Some(self.cache.get(&key).unwrap().clone())
    }
}
