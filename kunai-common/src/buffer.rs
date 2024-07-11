use core::cmp::min;

use crate::{errors::ProbeError, macros::bpf_target_code, macros::not_bpf_target_code};
use kunai_macros::BpfError;

not_bpf_target_code! {
    mod user;
}

bpf_target_code! {
    mod bpf;
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Buffer<const N: usize> {
    pub buf: [u8; N],
    len: usize,
}

impl<const N: usize> Default for Buffer<N> {
    fn default() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }
}

impl<const N: usize> core::ops::Index<usize> for Buffer<N> {
    type Output = u8;
    fn index(&self, index: usize) -> &Self::Output {
        &self.buf[index]
    }
}

impl<const N: usize> Buffer<N> {
    pub fn new() -> Self {
        Default::default()
    }

    pub const fn const_default() -> Self {
        Self {
            buf: [0; N],
            len: 0,
        }
    }

    #[inline(always)]
    pub fn copy(&mut self, other: &Self) {
        unsafe { core::ptr::copy_nonoverlapping(other as *const _, self as *mut _, 1) }
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..min(self.len(), N)]
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.space_left() == 0
    }

    #[inline(always)]
    pub fn space_left(&self) -> usize {
        N - self.len
    }

    #[inline(always)]
    pub fn reset(&mut self) {
        for i in 0..N {
            if i == self.len {
                break;
            }
            self.buf[i] = 0;
        }
        self.len = 0;
    }

    #[inline(always)]
    pub const fn cap(&self) -> usize {
        N
    }
}

#[derive(BpfError, Clone, Copy)]
pub enum Error {
    #[error("bpf_probe_read failed")]
    FailedToRead,
    #[error("failed to read iovec")]
    FailedToReadIovec,
    #[error("failed to read iov element")]
    FailedToReadIovElement,
    #[error("failed to read iov_base")]
    FailedToReadIovBase,
    #[error("iov_base is null")]
    NullIovBase,
    #[error("nr_segs member is missing")]
    NrSegsMissing,
    #[error("count member is missing")]
    CountMissing,
    #[error("iov member is null")]
    IovNull,
    #[error("iov member is missing")]
    IovMissing,
    #[error("iovec.iov_len member is missing")]
    IovLenMissing,
    #[error("iovec.ubuf member is missing")]
    UbufMissing,
    #[error("iovec.iov_base member is missing")]
    IovBaseMissing,
    #[error("unimplemented iter")]
    UnimplementedIter,
    #[error("should not happen")]
    ShouldNotHappen,
    #[error("buffer full")]
    BufferFull,
    // bvec related
    #[error("iov_iter.bvec missing")]
    BvecMissing,
    #[error("bio_vec.page missing")]
    BvecPageMissing,
    #[error("bio_vec.bv_offset missing")]
    BvecOffsetMissing,
    #[error("bio_vec.bv_len missing")]
    BvecLenMissing,
    #[error("failed to read bio_vec")]
    FailedToReadBioVec,
}

impl From<Error> for ProbeError {
    fn from(value: Error) -> Self {
        Self::BufferError(value)
    }
}
