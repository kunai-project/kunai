/// This module contains the necessary structures to parse /etc/passwd
/// and /etc/group files and provide API to query user and group information.
use std::{
    collections::HashMap,
    fs::File,
    io::{self, BufRead, BufReader},
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

    #[inline]
    pub fn extend_from_vec<S: AsRef<str>>(&mut self, v: Vec<S>) -> Result<&mut Self, Error> {
        let mut lines = Vec::new();
        for line in v {
            let group = User::from_str(line.as_ref())?;
            self.insert_user(group);
            lines.push(line.as_ref().to_string());
        }
        Ok(self)
    }

    pub fn extend_from_reader<R: io::Read>(&mut self, r: R) -> Result<&mut Self, Error> {
        let r = BufReader::new(r);
        let mut lines = Vec::new();
        for res in r.lines() {
            lines.push(res?);
        }
        self.extend_from_vec(lines)
    }

    pub fn extend_from_file<P: AsRef<Path>>(&mut self, p: P) -> Result<&mut Self, Error> {
        let r = BufReader::new(File::open(p.as_ref())?);
        for res in r.lines() {
            let user = User::from_str(&res?)?;
            self.insert_user(user);
        }
        Ok(self)
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
        out.extend_from_file("/etc/passwd")?;
        Ok(out)
    }

    fn insert_user(&mut self, u: User) {
        let group_idx = self.users.len();
        self.users_by_name.insert(u.name.clone(), group_idx);
        self.users_by_id.insert(u.uid, group_idx);
        self.users.push(u);
    }

    #[inline(always)]
    pub fn get_by_uid(&self, uid: &u32) -> Option<&User> {
        self.users_by_id
            .get(uid)
            .and_then(|&idx| self.users.get(idx))
    }

    #[inline(always)]
    pub fn contains_uid(&self, uid: &u32) -> bool {
        self.users_by_id.contains_key(uid)
    }

    #[inline(always)]
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

    #[inline]
    pub fn extend_from_vec<S: AsRef<str>>(&mut self, v: Vec<S>) -> Result<&mut Self, Error> {
        let mut lines = Vec::new();
        for line in v {
            let group = Group::from_str(line.as_ref())?;
            self.insert_group(group);
            lines.push(line.as_ref().to_string());
        }
        Ok(self)
    }

    #[inline]
    pub fn extend_from_reader<R: io::Read>(&mut self, r: R) -> Result<&mut Self, Error> {
        let r = BufReader::new(r);
        let mut lines = Vec::new();
        for res in r.lines() {
            lines.push(res?);
        }
        self.extend_from_vec(lines)
    }

    pub fn extend_from_file<P: AsRef<Path>>(&mut self, p: P) -> Result<&mut Self, Error> {
        self.extend_from_reader(File::open(p.as_ref())?)
    }

    pub fn extend_from_str<S: AsRef<str>>(&mut self, s: S) -> Result<&mut Self, Error> {
        self.extend_from_reader(io::Cursor::new(s.as_ref()))
    }

    pub fn from_sys() -> Result<Self, Error> {
        let mut out = Self::default();
        out.extend_from_file("/etc/group")?;
        Ok(out)
    }

    fn insert_group(&mut self, g: Group) {
        let group_idx = self.groups.len();
        self.groups_by_name.insert(g.name.clone(), group_idx);
        self.groups_by_id.insert(g.gid, group_idx);
        self.groups.push(g);
    }

    #[inline(always)]
    pub fn get_by_gid(&self, gid: &u32) -> Option<&Group> {
        self.groups_by_id
            .get(gid)
            .and_then(|&idx| self.groups.get(idx))
    }

    #[inline(always)]
    pub fn contains_gid(&self, gid: &u32) -> bool {
        self.groups_by_id.contains_key(gid)
    }

    #[inline(always)]
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

        assert_eq!(users.get_by_uid(&1386).unwrap().name.as_str(), "john");
        assert_eq!(users.get_by_name("john").unwrap().name.as_str(), "john");
        assert_eq!(users.get_by_uid(&1622).unwrap().name.as_str(), "diana");
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

        assert_eq!(db.get_by_gid(&371).unwrap().name.as_str(), "wheel");
        assert_eq!(db.get_by_name("wheel").unwrap().name.as_str(), "wheel");
        assert_eq!(db.get_by_gid(&612).unwrap().name.as_str(), "operations");
        assert_eq!(
            db.get_by_name("operations").unwrap().name.as_str(),
            "operations"
        );
    }
}
