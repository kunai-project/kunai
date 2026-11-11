use std::{path::Path, time::Duration};

use kunai_common::string::escape_invalid_utf8_path;
use serde::{Deserialize, Deserializer, Serializer};

// Serde's default path serialization fails on bytes that are not valid UTF-8
pub(crate) fn serialize_path<P, S>(path: &P, serializer: S) -> Result<S::Ok, S::Error>
where
    P: AsRef<Path>,
    S: Serializer,
{
    serializer.serialize_str(&escape_invalid_utf8_path(path.as_ref()))
}

// Custom serialization function for Option<Duration>
pub(crate) fn serialize_opt_duration<S>(
    duration: &Option<Duration>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    match duration {
        Some(d) => serializer.serialize_str(humantime::format_duration(*d).to_string().as_str()),
        None => serializer.serialize_none(),
    }
}

// Custom deserialization function for Option<Duration>
pub(crate) fn deserialize_opt_duration<'de, D>(
    deserializer: D,
) -> Result<Option<Duration>, D::Error>
where
    D: Deserializer<'de>,
{
    let s: Option<String> = Option::deserialize(deserializer)?;
    match s {
        Some(s) => Ok(Some(humantime::parse_duration(&s).unwrap())),
        None => Ok(None),
    }
}
