use core::slice;
use std::str::FromStr;

use gene::{Event, FieldValue, PartialEvent, XPath};
use json::JsonValue;
use lazy_static::lazy_static;
use log::error;

lazy_static! {
    static ref ID_PATH: XPath = XPath::from_str(".info.event.id").unwrap();
}

pub struct JsonEvent(JsonValue);

impl<'a> JsonEvent {
    fn get_rec(
        v: &'a JsonValue,
        mut next: slice::Iter<'_, std::string::String>,
    ) -> Option<&'a JsonValue> {
        match v {
            JsonValue::Object(m) => Self::get_rec(m.get(next.next()?)?, next),
            _ => Some(v),
        }
    }

    fn field_value(value: &JsonValue) -> FieldValue {
        match value {
            JsonValue::Short(s) => s.as_str().into(),
            JsonValue::String(s) => s.as_str().into(),
            JsonValue::Boolean(b) => (*b).into(),
            JsonValue::Number(n) => FieldValue::from(f64::from(*n)),
            JsonValue::Null => FieldValue::None,
            JsonValue::Object(_) | JsonValue::Array(_) => {
                error!("cannot handle array or object field value");
                FieldValue::None
            }
        }
    }
}

impl std::fmt::Display for JsonEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<JsonValue> for JsonEvent {
    fn from(value: JsonValue) -> Self {
        JsonEvent(value)
    }
}

impl PartialEvent for JsonEvent {
    fn get_from_iter(
        &self,
        i: core::slice::Iter<'_, std::string::String>,
    ) -> Option<gene::FieldValue> {
        Some(Self::field_value(Self::get_rec(&self.0, i)?))
    }
}

impl Event for JsonEvent {
    #[inline(always)]
    fn id(&self) -> i64 {
        if let Some(FieldValue::Number(num)) = self.get_from_path(&ID_PATH) {
            if let Ok(id) = i64::try_from(num) {
                return id;
            }
        }
        error!("failed to retrieve event id");
        0
    }

    #[inline(always)]
    fn source(&self) -> std::borrow::Cow<'_, str> {
        "kunai".into()
    }
}
