/// This module contains the necessary structures to parse /etc/passwd
/// and /etc/group files and provide API to query user and group information.
use std::{
    collections::HashMap,
    fs::File,
    io::{self, Read},
    num::ParseIntError,
    path::Path,
    str::FromStr,
};

use thiserror::Error;

#[derive(Debug, Clone)]
pub struct User {
    pub name: String,
    pub uid: u32,
}

impl FromStr for User {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.split(':').collect::<Vec<&str>>())
    }
}

impl TryFrom<Vec<&str>> for User {
    type Error = ParseError;
    fn try_from(value: Vec<&str>) -> Result<Self, ParseError> {
        if value.len() < 3 {
            return Err(ParseError::BadLineFormat);
        }

        Ok(Self {
            name: value[0].into(),
            uid: value[2]
                .parse::<u32>()
                .map_err(|e| ParseError::ParseInt("uid", e))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Group {
    pub name: String,
    pub gid: u32,
}

#[derive(Debug, Error, PartialEq)]
pub enum ParseError {
    #[error("bad line format")]
    BadLineFormat,
    #[error("parse {0} error: {1}")]
    ParseInt(&'static str, ParseIntError),
}

impl FromStr for Group {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s.split(':').collect::<Vec<&str>>())
    }
}

impl TryFrom<Vec<&str>> for Group {
    type Error = ParseError;
    fn try_from(value: Vec<&str>) -> Result<Self, ParseError> {
        if value.len() < 3 {
            return Err(ParseError::BadLineFormat);
        }

        Ok(Self {
            name: value[0].into(),
            gid: value[2]
                .parse::<u32>()
                .map_err(|e| ParseError::ParseInt("gid", e))?,
        })
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("parse error: {0}")]
    Parse(#[from] ParseError),
    #[error("file exceeds limit of {MAX_BYTES} bytes")]
    SizeLimit,
    #[error("file exceeds limit of {MAX_ENTRIES} entries")]
    EntryLimit,
}

// Account files may come from a hostile namespace root, these bound the memory they cost.
pub const MAX_BYTES: usize = 1 << 20;
pub const MAX_ENTRIES: usize = 16384;

fn read_bounded<R: io::Read>(r: R) -> Result<String, Error> {
    let mut s = String::new();
    r.take(MAX_BYTES as u64 + 1).read_to_string(&mut s)?;
    if s.len() > MAX_BYTES {
        return Err(Error::SizeLimit);
    }
    Ok(s)
}

pub trait AccountTable: Sized {
    fn from_reader<R: io::Read>(r: R) -> Result<Self, Error>;
}

impl AccountTable for Users {
    fn from_reader<R: io::Read>(r: R) -> Result<Self, Error> {
        let mut out = Self::new();
        out.extend_from_reader(r)?;
        Ok(out)
    }
}

impl AccountTable for Groups {
    fn from_reader<R: io::Read>(r: R) -> Result<Self, Error> {
        let mut out = Self::new();
        out.extend_from_reader(r)?;
        Ok(out)
    }
}

// Structure holding data parsed from /etc/passwd
#[derive(Debug, Default, Clone)]
pub struct Users {
    users: Vec<User>,
    users_by_name: HashMap<String, usize>,
    users_by_id: HashMap<u32, usize>,
}

impl Users {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn sys_path() -> &'static str {
        "/etc/passwd"
    }

    #[inline]
    pub fn extend_from_vec<S: AsRef<str>>(
        &mut self,
        v: impl IntoIterator<Item = S>,
    ) -> Result<&mut Self, Error> {
        for line in v {
            if self.users.len() == MAX_ENTRIES {
                return Err(Error::EntryLimit);
            }
            self.insert_user(User::from_str(line.as_ref())?);
        }
        Ok(self)
    }

    pub fn extend_from_reader<R: io::Read>(&mut self, r: R) -> Result<&mut Self, Error> {
        self.extend_from_vec(read_bounded(r)?.lines())
    }

    pub fn extend_from_file<P: AsRef<Path>>(&mut self, p: P) -> Result<&mut Self, Error> {
        self.extend_from_reader(File::open(p.as_ref())?)
    }

    pub fn extend_from_str<S: AsRef<str>>(&mut self, s: S) -> Result<&mut Self, Error> {
        self.extend_from_reader(io::Cursor::new(s.as_ref()))
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.users.clear();
        self.users_by_id.clear();
        self.users_by_name.clear();
        Ok(())
    }

    pub fn from_sys() -> Result<Self, Error> {
        let mut out = Self::new();
        out.extend_from_file(Self::sys_path())?;
        Ok(out)
    }

    fn insert_user(&mut self, u: User) {
        let group_idx = self.users.len();
        self.users_by_name.insert(u.name.clone(), group_idx);
        self.users_by_id.insert(u.uid, group_idx);
        self.users.push(u);
    }

    pub fn get_by_uid(&self, uid: u32) -> Option<&User> {
        self.users_by_id
            .get(&uid)
            .and_then(|&idx| self.users.get(idx))
    }

    pub fn contains_uid(&self, uid: u32) -> bool {
        self.users_by_id.contains_key(&uid)
    }

    pub fn get_by_name<S: AsRef<str>>(&self, name: S) -> Option<&User> {
        self.users_by_name
            .get(name.as_ref())
            .and_then(|&idx| self.users.get(idx))
    }
}

// Structure holding data parsed from /etc/group
#[derive(Debug, Default, Clone)]
pub struct Groups {
    groups: Vec<Group>,
    groups_by_name: HashMap<String, usize>,
    groups_by_id: HashMap<u32, usize>,
}

impl Groups {
    pub fn new() -> Self {
        Self::default()
    }

    pub const fn sys_path() -> &'static str {
        "/etc/group"
    }

    #[inline]
    pub fn extend_from_vec<S: AsRef<str>>(
        &mut self,
        v: impl IntoIterator<Item = S>,
    ) -> Result<&mut Self, Error> {
        for line in v {
            if self.groups.len() == MAX_ENTRIES {
                return Err(Error::EntryLimit);
            }
            self.insert_group(Group::from_str(line.as_ref())?);
        }
        Ok(self)
    }

    #[inline]
    pub fn extend_from_reader<R: io::Read>(&mut self, r: R) -> Result<&mut Self, Error> {
        self.extend_from_vec(read_bounded(r)?.lines())
    }

    pub fn extend_from_file<P: AsRef<Path>>(&mut self, p: P) -> Result<&mut Self, Error> {
        self.extend_from_reader(File::open(p.as_ref())?)
    }

    pub fn extend_from_str<S: AsRef<str>>(&mut self, s: S) -> Result<&mut Self, Error> {
        self.extend_from_reader(io::Cursor::new(s.as_ref()))
    }

    pub fn from_sys() -> Result<Self, Error> {
        let mut out = Self::default();
        out.extend_from_file(Self::sys_path())?;
        Ok(out)
    }

    fn insert_group(&mut self, g: Group) {
        let group_idx = self.groups.len();
        self.groups_by_name.insert(g.name.clone(), group_idx);
        self.groups_by_id.insert(g.gid, group_idx);
        self.groups.push(g);
    }

    pub fn get_by_gid(&self, gid: u32) -> Option<&Group> {
        self.groups_by_id
            .get(&gid)
            .and_then(|&idx| self.groups.get(idx))
    }

    pub fn contains_gid(&self, gid: &u32) -> bool {
        self.groups_by_id.contains_key(gid)
    }

    pub fn get_by_name<S: AsRef<str>>(&self, name: S) -> Option<&Group> {
        self.groups_by_name
            .get(name.as_ref())
            .and_then(|&idx| self.groups.get(idx))
    }

    pub fn clear(&mut self) -> Result<(), Error> {
        self.groups.clear();
        self.groups_by_id.clear();
        self.groups_by_name.clear();
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_users() {
        let mut users = Users::new();
        users
            .extend_from_str(
                r#"john:x:1386:1384:Charles White:/home/lucas:/bin/bash
bob:x:1108:1468:Charles White:/home/rachel:/sbin/nologin
jane:x:1733:1109:Paul Davis:/home/diana:/bin/bash
charles:x:1758:1121:Bob Johnson:/home/charles:/bin/bash
alice:x:1798:1890:John Doe:/home/alice:/bin/zsh
lucas:x:1477:1996:Lucas Black:/home/bob:/bin/zsh
paul:x:1429:1766:Alice Smith:/home/lucas:/bin/zsh
mark:x:1639:1485:Diana Green:/home/alice:/bin/bash
rachel:x:1337:1930:Rachel Miller:/home/bob:/bin/bash
diana:x:1622:1718:Charles White:/home/charles:/bin/bash"#,
            )
            .unwrap();

        assert_eq!(users.get_by_uid(1386).unwrap().name.as_str(), "john");
        assert_eq!(users.get_by_name("john").unwrap().name.as_str(), "john");
        assert_eq!(users.get_by_uid(1622).unwrap().name.as_str(), "diana");
        assert_eq!(users.get_by_name("diana").unwrap().name.as_str(), "diana");
    }

    #[test]
    fn test_groups() {
        let mut db = Groups::new();
        db.extend_from_str(
            r#"wheel:x:371:chris,kate,adam
research:x:838:olivia,george,tom
developers:x:952:nina,paul,fiona
finance:x:395:nina,paul,fiona
users:x:661:olivia,george,tom
admins:x:362:zoe,brian,harry
marketing:x:862:jane,charles,diana
staff:x:844:chris,kate,adam
hr:x:655:zoe,brian,harry
operations:x:612:chris,kate,adam"#,
        )
        .unwrap();

        assert_eq!(db.get_by_gid(371).unwrap().name.as_str(), "wheel");
        assert_eq!(db.get_by_name("wheel").unwrap().name.as_str(), "wheel");
        assert_eq!(db.get_by_gid(612).unwrap().name.as_str(), "operations");
        assert_eq!(
            db.get_by_name("operations").unwrap().name.as_str(),
            "operations"
        );
    }

    struct Counted<R> {
        inner: R,
        read: usize,
    }

    impl<R: io::Read> io::Read for Counted<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.read += n;
            Ok(n)
        }
    }

    // valid for both formats, `width` includes the newline
    fn table(entries: usize, width: usize) -> String {
        (0..entries)
            .map(|i| format!("{:<1$}\n", format!("u{i:05}:x:{i}:"), width - 1))
            .collect()
    }

    fn reads_are_bounded<T: AccountTable>() {
        let mut r = Counted {
            inner: io::Read::take(io::repeat(0), 4 * MAX_BYTES as u64),
            read: 0,
        };
        assert!(matches!(T::from_reader(&mut r), Err(Error::SizeLimit)));
        assert!(r.read <= MAX_BYTES + 1, "read {} bytes", r.read);
    }

    #[test]
    fn newline_free_input_reads_are_bounded() {
        reads_are_bounded::<Users>();
        reads_are_bounded::<Groups>();
    }

    fn byte_limit<T: AccountTable>() {
        let at_limit = table(MAX_ENTRIES, MAX_BYTES / MAX_ENTRIES);
        assert_eq!(at_limit.len(), MAX_BYTES);
        let over = format!("{} \n", at_limit.trim_end_matches('\n'));
        T::from_reader(at_limit.as_bytes()).unwrap();
        assert!(matches!(
            T::from_reader(over.as_bytes()),
            Err(Error::SizeLimit)
        ));
    }

    #[test]
    fn byte_limit_boundary() {
        byte_limit::<Users>();
        byte_limit::<Groups>();
    }

    fn entry_limit<T: AccountTable>() {
        T::from_reader(table(MAX_ENTRIES, 16).as_bytes()).unwrap();
        assert!(matches!(
            T::from_reader(table(MAX_ENTRIES + 1, 16).as_bytes()),
            Err(Error::EntryLimit)
        ));
    }

    #[test]
    fn entry_limit_boundary() {
        entry_limit::<Users>();
        entry_limit::<Groups>();
    }
}
