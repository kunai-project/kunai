use core::str::FromStr;
use gene::FieldGetter;
use kunai_common::cgroup::Cgroup;
use kunai_macros::StrEnum;
use serde::{Deserialize, Serialize};
use std::path::{self};

#[derive(StrEnum, Debug, PartialEq, Clone, Copy)]
pub enum Container {
    #[str("lxc")]
    Lxc,
    #[str("docker")]
    Docker,
    #[str("firejail")]
    Firejail,
}

impl Serialize for Container {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Container {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Deserialization logic goes here
        struct ContainerVisitor;
        const VARIANTS: &'static [&'static str] = &Container::variants_str();

        impl<'de> serde::de::Visitor<'de> for ContainerVisitor {
            type Value = Container;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a valid representation of Container enum")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Container::from_str(value)
                    .map_err(|_| serde::de::Error::unknown_variant(value, VARIANTS))
            }
        }

        deserializer.deserialize_str(ContainerVisitor)
    }
}

impl FieldGetter for Container {
    fn get_from_iter(
        &self,
        i: core::slice::Iter<'_, std::string::String>,
    ) -> Option<gene::FieldValue> {
        if i.len() > 0 {
            return None;
        }
        return Some(self.as_str().into());
    }
}

impl Container {
    fn from_split_cgroup<S: AsRef<str>>(cgroup: Vec<S>) -> Option<Container> {
        if let Some(last) = cgroup.last() {
            if last.as_ref().starts_with("docker-") {
                return Some(Container::Docker);
            }
        }

        if let Some(first) = cgroup.get(1) {
            if first.as_ref().starts_with("lxc.payload.") {
                return Some(Container::Lxc);
            }
        }

        None
    }

    #[inline]
    pub fn from_cgroup(cgrp: &Cgroup) -> Option<Container> {
        Self::from_split_cgroup(cgrp.to_vec())
    }

    #[inline]
    pub fn from_cgroups(cgroups: &Vec<String>) -> Option<Container> {
        for c in cgroups {
            if let Some(c) = Self::from_split_cgroup(c.split(path::MAIN_SEPARATOR).collect()) {
                return Some(c);
            }
        }
        None
    }

    #[inline]
    pub fn from_ancestors(ancestors: &Vec<String>) -> Option<Container> {
        for a in ancestors {
            match a.as_str() {
                "/usr/bin/firejail" => return Some(Container::Firejail),
                "/usr/bin/containerd-shim-runc-v2" => return Some(Container::Docker),
                _ => {}
            };

            if a.starts_with("/snap/lxd/") && a.ends_with("/bin/lxd/") {
                return Some(Container::Lxc);
            }
        }
        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_serde() {
        let c = Container::Docker;

        let ser = serde_json::to_string(&c).unwrap();
        assert_eq!(ser, r#""docker""#);
        let de: Container = serde_json::from_str(&ser).unwrap();
        assert_eq!(de, Container::Docker);

        // this is an unknown variant so we should get an error
        assert!(serde_json::from_str::<'_, Container>(r#""lxk""#).is_err());
    }
}
