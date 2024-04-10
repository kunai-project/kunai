use super::Error;
use crate::{bpf_events, buffer::Buffer};
use aya_ebpf::{
    macros::map,
    maps::{PerCpuArray, PerCpuHashMap},
};
use core::{mem, result};

const fn max(a: usize, b: usize) -> usize {
    if a < b {
        return b;
    }
    a
}

macro_rules! max {
    ($a:expr) => ($a);
    ($a:expr, $($rest:expr),*) => {{max($a, max!($($rest),*))}};
}

const MAX_ALLOCS: u32 = 8;

// Optimized HEAP_MAX_ALLOC_SIZE
// we need to double the actual maximum size we need to hack the verifier.
// It is sometimes impossible for the verifier to evaluate the correct bound
// check. This is the case for self modifying structure (appending/prepending
// operations). The verifier always need a constant value to bound a probe_read
// operation, however when appending the size we actually can write is variable
// and this causes a lot of troubles to the verifier. It is not always possible
// to fix an acceptable bound for size in probe_read, so a hack is to double
// the size of the map value used to allocate such a structure. In this way,
// the verifier always think there is enough room to write data. Special care
// to the bound checks must be taken because it may overrun the structures without
// triping up the verifier.
const HEAP_MAX_ALLOC_SIZE: usize = max!(
    bpf_events::MAX_BPF_EVENT_SIZE,
    mem::size_of::<Buffer<{ bpf_events::ENCRYPT_DATA_MAX_BUFFER_SIZE }>>()
) * 2;

const ZEROS: [u8; HEAP_MAX_ALLOC_SIZE] = [0; HEAP_MAX_ALLOC_SIZE];

// allocator is much faster with a PerCpuHashMap filled out with ZEROS
// elements rather than using a PerCpuArray + memset 0
#[map]
static mut HEAP: PerCpuHashMap<u32, [u8; HEAP_MAX_ALLOC_SIZE]> =
    PerCpuHashMap::with_max_entries(MAX_ALLOCS, 0);

#[map]
static mut ALLOCATOR: PerCpuArray<Allocator> = PerCpuArray::with_max_entries(1, 0);

pub struct Allocator {
    pub i_next: u32,
}

type Result<T> = result::Result<T, Error>;

#[inline(always)]
pub fn init() -> Result<()> {
    Allocator::new()?;
    Ok(())
}

#[inline(always)]
pub fn alloc_zero<T>() -> Result<&'static mut T> {
    let alloc = Allocator::reuse()?;
    alloc.zero_alloc::<T>()
}

impl Allocator {
    fn new() -> Result<&'static mut Self> {
        let a = Self::reuse()?;
        a.i_next = 0;
        Ok(a)
    }

    fn reuse() -> Result<&'static mut Self> {
        unsafe {
            let ptr = ALLOCATOR
                .get_ptr_mut(0)
                .ok_or(Error::FailedToGetAllocator)?;
            let a = &mut *ptr;
            Ok(a)
        }
    }

    fn alloc_slice<T>(&mut self) -> Result<&'static mut [u8]> {
        let sizeof = mem::size_of::<T>();

        if self.i_next == MAX_ALLOCS {
            return Err(Error::NoMoreSpace);
        }

        unsafe {
            let k = self.i_next;
            HEAP.insert(&k, &ZEROS, 0)
                .map_err(|_| Error::ZeroChunkFailed)?;

            if let Some(alloc) = HEAP.get_ptr_mut(&k).and_then(|a| a.as_mut()) {
                if sizeof > alloc.len() {
                    return Err(Error::AllocTooBig);
                }

                self.i_next += 1;

                return Ok(alloc);
            }
        }

        Err(Error::NoMoreSpace)
    }

    fn zero_alloc<T>(&mut self) -> Result<&'static mut T> {
        unsafe {
            let alloc = self.alloc_slice::<T>()?;
            Ok(core::mem::transmute(alloc.as_mut_ptr()))
        }
    }
}
