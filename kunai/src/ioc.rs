use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Deserialize, Serialize)]
pub struct IoC {
    pub source: String,
    pub uuid: uuid::Uuid,
    pub value: String,
    pub severity: u8,
}
