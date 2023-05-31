use aya_bpf::{
    macros::map,
    maps::{PerCpuArray, PerCpuHashMap},
};
use core::{mem, result};
use kunai_common::events;
use kunai_macros::BpfError;

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

// Optimized HEAP_MAX_ALLOC_SIZE, allocation can never be larger than the largest of the events
// This const needs to be updated when new events are defined
const HEAP_MAX_ALLOC_SIZE: usize = max!(
    mem::size_of::<events::ExecveEvent>(),
    mem::size_of::<events::BpfProgLoadEvent>(),
    mem::size_of::<events::ConnectEvent>(),
    mem::size_of::<events::DnsQueryEvent>(),
    mem::size_of::<events::ExitEvent>(),
    mem::size_of::<events::MmapExecEvent>(),
    mem::size_of::<events::SendEntropyEvent>(),
    mem::size_of::<events::InitModuleEvent>(),
    mem::size_of::<events::ConfigEvent>(),
    mem::size_of::<events::SendEntropyEvent>(),
    mem::size_of::<events::FileRenameEvent>(),
    mem::size_of::<events::MprotectEvent>()
);

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

#[derive(BpfError)]
pub enum Error {
    #[error("failed to get allocator")]
    FailedToGetAllocator,
    #[error("no more place to allocate")]
    NoMoreSpace,
    #[error("allocation is too big")]
    AllocTooBig,
    #[error("failed to insert new chunk")]
    ZeroChunkFailed,
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

    fn alloc<T>(&mut self) -> Result<&'static mut [u8]> {
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
            let alloc = self.alloc::<T>()?;
            // memsetting only the size we need
            //alloc.iter_mut().for_each(|u| *u = 0);
            Ok((alloc.as_mut_ptr() as *mut T).as_mut().unwrap())
        }
    }
}
