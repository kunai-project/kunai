use core::cmp::min;

use crate::co_re::{iov_iter, iovec};
use crate::helpers::{gen, *};
use crate::utils::cap_size;

use super::{Buffer, Error};

impl<const N: usize> Buffer<N> {
    #[inline(always)]
    pub unsafe fn fill_from_iov_iter<const MAX_NR_SEGS: usize>(
        &mut self,
        iter: &iov_iter,
        count: Option<usize>,
    ) -> Result<(), Error> {
        let nr_segs = iter.nr_segs().ok_or(Error::NrSegsMissing)? as usize;
        let iov = iter.iov().ok_or(Error::IovMissing)?;

        if iov.is_null() {
            return Err(Error::IovNull);
        }

        // in case we are iterating over a ubuf
        if iter.is_iter_ubuf() {
            let ubuf = iter.ubuf().ok_or(Error::UbufMissing)?;
            let count = iter.count().ok_or(Error::CountMissing)?;
            // ubuf is in userland so we need to read it accordingly
            self.read_user_at(ubuf, count as u32)?;
        } else if iter.is_iter_iovec() {
            // we put a threshold to nr_segs (that can be fixed from call site)
            for i in 0..MAX_NR_SEGS {
                if self.is_full() || i >= nr_segs {
                    break;
                }
                self.append_iov(&iov.get(i), count)?;
            }
        } else {
            return Err(Error::UnimplementedIter);
        }

        Ok(())
    }

    #[inline(always)]
    unsafe fn append_iov(&mut self, iov: &iovec, count: Option<usize>) -> Result<(), Error> {
        let iov_len = iov.iov_len().ok_or(Error::IovLenMissing)?;
        let iov_base = iov.iov_base().ok_or(Error::IovBaseMissing)?;

        let len = cap_size(self.len, N);

        let mut size = min(iov_len as u32, N as u32);

        if let Some(count) = count {
            size = min(count as u32, size);
        }

        let left = cap_size((N - len) as u32, N as u32);
        if size > left {
            return Err(Error::BufferFull);
        }

        if gen::bpf_probe_read_user(
            self.buf[len as usize..N].as_mut_ptr() as *mut _,
            cap_size(size, N as u32),
            iov_base as *const _,
        ) < 0
        {
            return Err(Error::FailedToReadIovBase);
        }

        self.len += size as usize;

        Ok(())
    }

    #[inline(always)]
    pub unsafe fn read_kernel_str<P>(&mut self, src: *const P) -> Result<(), Error> {
        bpf_probe_read_kernel_str_bytes(src as *const _, &mut self.buf)
            .map_err(|_| Error::FailedToRead)?;
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn read_user_at<P>(&mut self, from: *const P, size: u32) -> Result<(), Error> {
        let size = cap_size(size, N as u32);

        let buf = &mut self.buf[..size as usize];
        bpf_probe_read_user_buf(from as *const _, buf).map_err(|_| Error::FailedToRead)?;

        self.len = size as usize;
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn read_kernel_at<P>(&mut self, from: *const P, size: u32) -> Result<(), Error> {
        let size = cap_size(size, N as u32);

        let buf = &mut self.buf[..size as usize];
        bpf_probe_read_kernel_buf(from as *const _, buf).map_err(|_| Error::FailedToRead)?;

        self.len = size as usize;
        Ok(())
    }
}
