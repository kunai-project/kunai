use crate::{bpf_target_code, not_bpf_target_code};

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
        &self.buf[..self.len()]
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
}

not_bpf_target_code! {
    use crate::utils::cstr_to_string;

    impl<const N: usize> Buffer<N> {
        pub fn to_command_line(&self) -> String {
            self.to_argv().join(" ")
        }

        pub fn to_argv(&self) -> Vec<String> {
            self.as_slice().split(|&b| b == b'\0').map(cstr_to_string).filter(|s| !s.is_empty()).collect()

        }
    }
}

bpf_target_code! {

    use crate::map_err;
    use super::{bpf_utils::*};
    use aya_bpf::helpers::{gen, *};
    use core::cmp::min;
    use kunai_macros::BpfError;
    use crate::co_re::{iov_iter, iovec};


    #[derive(BpfError)]
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
        #[error("iov member is null")]
        IovNull,
        #[error("iov member is missing")]
        IovMissing,
        #[error("iovec.iov_len member is missing")]
        IovLenMissing,
        #[error("iovec.iov_base member is missing")]
        IovBaseMissing,
        #[error("should not happen")]
        ShouldNotHappen,
        #[error("buffer full")]
        BufferFull
    }

    impl<const N: usize> Buffer<N> {
        #[inline(always)]
        pub unsafe fn fill_from_iov_iter<const MAX_NR_SEGS:usize>(
            &mut self,
            iter: &iov_iter,
            count: Option<usize>
        ) -> Result<(), Error> {
            let nr_segs = iter.nr_segs().ok_or(Error::NrSegsMissing)? as usize;
            let iov = iter.iov().ok_or(Error::IovMissing)?;

            if iov.is_null() {
                return Err(Error::IovNull);
            }

            // we put a threshold to nr_segs (that can be fixed from call site)
            for i in 0..MAX_NR_SEGS {
                if self.is_full() || i >= nr_segs{
                    break;
                }
                self.append_iov(&iov.get(i), count)?;
            }

            Ok(())
        }

        #[inline(always)]
        unsafe fn append_iov(&mut self, iov: &iovec, count: Option<usize>) -> Result<(), Error> {
            let iov_len = iov.iov_len().ok_or(Error::IovLenMissing)?;
            let iov_base = iov.iov_base().ok_or(Error::IovBaseMissing)?;

            let len = cap_size(self.len, N);

            let mut size = iov_len as u32;

            if let Some(count) = count {
                size = min(count as u32, size);
            }

            let left = cap_size((N-len) as u32, N as u32);
            if size > left {
                return Err(Error::BufferFull);
            }

            if gen::bpf_probe_read_user(
                self.buf[len as usize..N].as_mut_ptr() as *mut _,
                min(size, N as u32),
                iov_base as *const _,
            ) < 0
            {
                return Err(Error::FailedToReadIovBase);
            }

            self.len += size as usize ;

            Ok(())
        }

        #[inline(always)]
        pub unsafe fn read_kernel_str<P>(&mut self, src:*const P) -> Result<(), Error>{
            map_err!(
                bpf_probe_read_kernel_str_bytes(src as *const _, &mut self.buf),
                Error::FailedToRead
            )?;
            Ok(())
        }

        #[inline(always)]
        pub unsafe fn read_user_at<P>(&mut self, from:*const P, size: u32) -> Result<(), Error>{
            let size = min(size, N as u32);

            let buf = &mut self.buf[..size as usize];
            bpf_probe_read_user_buf(from as *const _, buf).map_err(|_| Error::FailedToRead)?;

            self.len = size as usize;
            Ok(())
        }

        #[inline(always)]
        pub unsafe fn read_kernel_at<P>(&mut self, from:*const P, size: u32) -> Result<(), Error>{
            let size = min(size, N as u32);

            let buf = &mut self.buf[..size as usize];
            bpf_probe_read_kernel_buf(from as *const _, buf).map_err(|_| Error::FailedToRead)?;

            self.len = size as usize;
            Ok(())
        }

    }

}
