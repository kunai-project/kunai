use core::cmp::min;

use crate::co_re::{bio_vec, iov_iter, iovec};
use aya_ebpf::check_bounds_signed;
use aya_ebpf::helpers::{gen, *};

use super::{Buffer, Error};

impl<const N: usize> Buffer<N> {
    #[inline(always)]
    pub unsafe fn fill_from_iov_iter<const MAX_NR_SEGS: usize>(
        &mut self,
        iter: iov_iter,
        count: Option<usize>,
    ) -> Result<(), Error> {
        let nr_segs = iter.nr_segs().ok_or(Error::NrSegsMissing)? as usize;

        // in case we are iterating over a ubuf
        if iter.is_iter_ubuf() {
            let ubuf = iter.ubuf().ok_or(Error::UbufMissing)?;
            let count = iter.count().ok_or(Error::CountMissing)?;
            // ubuf is in userland so we need to read it accordingly
            self.read_user_at(ubuf, count as u32)?;
        } else if iter.is_iter_iovec() {
            let iov = iter.iov().ok_or(Error::IovMissing)?;

            if iov.is_null() {
                return Err(Error::IovNull);
            }

            // we put a threshold to nr_segs (that can be fixed from call site)
            for i in 0..MAX_NR_SEGS {
                if self.is_full() || i >= nr_segs {
                    break;
                }
                self.append_iov(iov.get(i), count)?;
            }
        } else if iter.is_iter_bvec() {
            let bvec = iter.bvec().ok_or(Error::BvecMissing)?;

            for i in 0..MAX_NR_SEGS {
                if self.is_full() || i >= nr_segs {
                    break;
                }
                self.append_bio_vec(bvec.get(i), count)?;
            }
        } else {
            return Err(Error::UnimplementedIter);
        }

        Ok(())
    }

    #[inline(always)]
    unsafe fn append_iov(&mut self, iov: iovec, count: Option<usize>) -> Result<(), Error> {
        let iov_len = iov.iov_len().ok_or(Error::IovLenMissing)?;
        let iov_base = iov.iov_base().ok_or(Error::IovBaseMissing)?;

        // our offset is at current len to append
        let offset = self.len as i64;

        let mut size = iov_len as i64;

        if let Some(count) = count {
            size = min(count as i64, size);
        }

        let left = N as i64 - offset;
        if size > left {
            return Err(Error::BufferFull);
        }

        // we check map access is not OOB
        if !check_bounds_signed(offset, 0, N as i64) {
            return Ok(());
        }

        // we check we will not write OOB
        if !check_bounds_signed(size, 0, N as i64) {
            return Ok(());
        }

        if let Some(dst) = self
            .buf
            // we need to clamp as we cast offset and bounds might be lost by verifier
            .get_mut((offset as usize).clamp(0, N)..N)
            .map(|d| d.as_mut_ptr())
        {
            if gen::bpf_probe_read_user(
                dst as *mut _,
                (size as u32).clamp(0, N as u32),
                iov_base as *const _,
            ) < 0
            {
                return Err(Error::FailedToReadIovec);
            }

            self.len += size as usize;
            Ok(())
        } else {
            // this path should never be taken as we
            // bound checked everything upstream
            Err(Error::ShouldNotHappen)
        }
    }

    #[inline(always)]
    unsafe fn append_bio_vec(&mut self, bvec: bio_vec, count: Option<usize>) -> Result<(), Error> {
        let page = bvec.bv_page().ok_or(Error::BvecPageMissing)?;
        let bv_offset = bvec.bv_len().ok_or(Error::BvecOffsetMissing)?;
        let bv_len = bvec.bv_len().ok_or(Error::BvecLenMissing)?;

        let bvec_base = (page.to_va() as u64).wrapping_add(bv_offset as u64);

        // our offset is at current len to append
        let offset = self.len as i64;
        let mut size = bv_len as i64;

        if let Some(count) = count {
            size = min(count as i64, size);
        }

        let left = N as i64 - offset;
        if size > left {
            return Err(Error::BufferFull);
        }

        // we check map access is not OOB
        if !check_bounds_signed(offset, 0, N as i64) {
            return Ok(());
        }

        // we check we will not write OOB
        if !check_bounds_signed(size, 0, N as i64) {
            return Ok(());
        }

        if let Some(dst) = self
            .buf
            // we need to clamp as we cast offset and bounds might be lost by verifier
            .get_mut((offset as usize).clamp(0, N)..N)
            .map(|d| d.as_mut_ptr())
        {
            if gen::bpf_probe_read_kernel(
                dst as *mut _,
                (size as u32).clamp(0, N as u32),
                bvec_base as *const _,
            ) < 0
            {
                return Err(Error::FailedToReadBioVec);
            }

            self.len += size as usize;
            Ok(())
        } else {
            // this path should never be taken as we
            // bound checked everything upstream
            Err(Error::ShouldNotHappen)
        }
    }

    #[inline(always)]
    pub unsafe fn read_kernel_str<P>(&mut self, src: *const P) -> Result<(), Error> {
        bpf_probe_read_kernel_str_bytes(src as *const _, &mut self.buf)
            .map_err(|_| Error::FailedToRead)?;
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn read_user_at<P>(&mut self, from: *const P, size: u32) -> Result<(), Error> {
        let size = (size as i64).clamp(0, N as i64);

        if check_bounds_signed(size as i64, 0, N as i64) {
            let ret = gen::bpf_probe_read_user(
                self.buf.as_mut_ptr() as *mut _,
                size as u32,
                from as *const _,
            );
            if ret != 0 {
                return Err(Error::FailedToRead);
            }
        }

        self.len = size as usize;
        Ok(())
    }

    #[inline(always)]
    pub unsafe fn read_kernel_at<P>(&mut self, from: *const P, size: u32) -> Result<(), Error> {
        let size = (size as i64).clamp(0, N as i64);

        if check_bounds_signed(size as i64, 0, N as i64) {
            let ret = gen::bpf_probe_read_kernel(
                self.buf.as_mut_ptr() as *mut _,
                size as u32,
                from as *const _,
            );
            if ret != 0 {
                return Err(Error::FailedToRead);
            }
        }

        self.len = size as usize;
        Ok(())
    }
}
