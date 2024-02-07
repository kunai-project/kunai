use uuid;

use super::{Uuid, TaskUuid};

impl From<Uuid> for uuid::Uuid {
    fn from(value: Uuid) -> Self {
        Self::from_bytes(value.0)
    }
}

impl From<uuid::Uuid> for Uuid {
    fn from(value: uuid::Uuid) -> Self {
        Self(value.into_bytes())
    }
}

impl Uuid {
    pub fn new_v4() -> Self {
        uuid::Uuid::new_v4().into()
    }

    pub fn into_uuid(self) -> uuid::Uuid {
        self.into()
    }
}

impl From<TaskUuid> for uuid::Uuid {
    fn from(value: TaskUuid) -> Self {
        unsafe { core::mem::transmute(value) }
    }
}

impl TaskUuid {
    pub fn into_uuid(self) -> uuid::Uuid {
        self.into()
    }
}
