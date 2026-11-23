use std::time::Duration;

use serde::{Deserialize, Deserializer, Serializer};

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
