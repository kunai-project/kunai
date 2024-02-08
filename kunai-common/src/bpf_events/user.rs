use aya::Pod;
use core::fmt::Display;

use thiserror::Error;

unsafe impl Pod for Type {}

impl Display for Type {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct EncodedEvent {
    event: Vec<u8>,
}

#[derive(Error, Debug)]
pub enum DecoderError {
    #[error("not enough bytes to decode")]
    NotEnoughBytes,
    #[error("size of buffer does not match with size of event")]
    SizeDontMatch,
}

impl EncodedEvent {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            event: Vec::from(bytes),
        }
    }

    pub fn from_event<T>(event: Event<T>) -> Self {
        Self::from_bytes(event.encode())
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    pub unsafe fn info(&self) -> Result<&EventInfo, DecoderError> {
        // event content must be at least the size of EventInfo
        if self.event.len() < core::mem::size_of::<EventInfo>() {
            return Err(DecoderError::NotEnoughBytes);
        }

        Ok(&(*(self.event.as_ptr() as *const EventInfo)))
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    pub unsafe fn info_mut(&mut self) -> Result<&mut EventInfo, DecoderError> {
        // event content must be at least the size of EventInfo
        if self.event.len() < core::mem::size_of::<EventInfo>() {
            return Err(DecoderError::NotEnoughBytes);
        }

        Ok(&mut (*(self.event.as_ptr() as *mut EventInfo)))
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    pub unsafe fn as_event_with_data<D>(&self) -> Result<&Event<D>, DecoderError> {
        // must be at least the size of Event<T>
        if self.event.len() < core::mem::size_of::<Event<D>>() {
            return Err(DecoderError::SizeDontMatch);
        }

        Ok(&(*(self.event.as_ptr() as *const Event<D>)))
    }

    /// # Safety
    /// * the bytes decoded must be a valid Event<T>
    pub unsafe fn as_mut_event_with_data<D>(&mut self) -> Result<&mut Event<D>, DecoderError> {
        // must be at least the size of Event<T>
        if self.event.len() < core::mem::size_of::<Event<D>>() {
            return Err(DecoderError::SizeDontMatch);
        }

        Ok(&mut (*(self.event.as_mut_ptr() as *mut Event<D>)))
    }
}

#[macro_export]
macro_rules! mut_event {
    ($enc: expr) => {
        unsafe { $enc.as_mut_event_with_data() }
    };
    ($enc:expr, $event:ty) => {{
        let event: Result<&mut $event, $crate::bpf_events::DecoderError> =
            unsafe { $enc.as_mut_event_with_data() };
        event
    }};
}

pub use mut_event;

#[macro_export]
macro_rules! event {
    ($enc: expr) => {
        unsafe { $enc.as_event_with_data() }
    };
    ($enc:expr, $event:ty) => {{
        let event: Result<&$event, $crate::bpf_events::DecoderError> =
            unsafe { $enc.as_event_with_data() };
        event
    }};
}

pub use event;

use super::{Event, EventInfo, Type};
