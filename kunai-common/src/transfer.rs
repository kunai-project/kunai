use crate::buffer::Buffer;
use crate::{bpf_target_code, not_bpf_target_code};
use core::mem::size_of;

const CHUNK_SIZE: usize = 0x4000;
// to make Chunk exactly the size we want;
const BUF_SIZE: usize = CHUNK_SIZE - size_of::<Chunk<0>>();
// this limits the total amount of data that can be in the perf array
const MAX_CHUNK_COUNT: usize = 64;

pub type TChunk = Chunk<BUF_SIZE>;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Chunk<const N: usize> {
    pub id: usize,
    pub transfer_id: u64,
    pub data: Buffer<N>,
    pub chunks_count: usize,
}

not_bpf_target_code! {

use crate::perf;
use lru_st::collections::LruHashMap;
use aya::{
    util::online_cpus,
    maps::{perf::{AsyncPerfEventArray, PerfBufferError}},
    Bpf, Pod,
};
use tokio::{self, sync::Mutex, time::{self, sleep, Duration, error::Elapsed}};
//use std::sync::{Arc,Mutex};
use std::sync::{Arc};

const MAP_NAME: &str = "TRANSFER_ARRAY";

#[derive(Debug)]
pub enum Error{
    InvalidFirstChunk(u32),
    MissingChunks{recv:usize, exp:usize},
    MissingData{recv:usize, exp:usize},
}

#[derive(Default)]
pub struct Transfer{
    // remove this pub
    pub chunks: Vec<TChunk>,
    exp_chunks: usize,
}

impl Transfer {
    #[inline]
    pub fn count_chunks(&self) -> usize{
        self.chunks.len()
    }

    #[inline]
    pub fn completed(&self) -> bool {
        self.exp_chunks == self.count_chunks()
    }

    #[inline]
    pub fn gather(& mut self) -> Result<Vec<u8>,Error> {
        if !self.completed() {
            return Err(Error::MissingChunks{recv: self.count_chunks(), exp: self.exp_chunks});
        }

        // first make sure chunks are sorted by id
        self.chunks.sort_unstable_by_key(|t| t.id);

        Ok(self
            .chunks
            .iter()
            .map(|c| c.data.as_slice())
            .collect::<Vec<&[u8]>>()
            .concat())
    }
}

pub struct TransferMap {
    transfers: LruHashMap<u64, Transfer>
}

unsafe impl Pod for TChunk {}

impl TransferMap {
    pub fn init(bpf: &mut Bpf, max_transfer: usize) -> Arc<Mutex<Self>> {
        let tm = Arc::new(Mutex::new(TransferMap {transfers: LruHashMap::with_max_entries(max_transfer)}));

        let mut perf_array = AsyncPerfEventArray::<_>::try_from(bpf.take_map(MAP_NAME).expect(
            &(MAP_NAME.to_owned() + "map should not be missing, maybe you forgot using it your eBPF code"),
        ))
        .expect(&(MAP_NAME.to_owned() + "should be a valid HashMap"));

        for cpu_id in online_cpus().unwrap() {

                let mut buf = perf_array
                .open(
                    cpu_id,
                    Some(perf::optimal_page_count(4096, size_of::<TChunk>(), MAX_CHUNK_COUNT)),
                )
                .unwrap();

                let tm = Arc::clone(&tm);

            tokio::spawn(async move {
                let mut buffers = perf::event_buffers(size_of::<TChunk>(), MAX_CHUNK_COUNT, MAX_CHUNK_COUNT);
                loop{
                    // wait for events
                    let events = buf.read_events(&mut buffers).await?;
                    for buf in buffers.iter().take(events.read) {
                        let chunk = unsafe { *(buf.as_ptr() as *const TChunk) };
                        // update map with the chunk we just received
                        let mut tm = tm.lock().await;
                        tm.update(chunk);

                    }
                }

                #[allow(unreachable_code)]
                Ok::<_, PerfBufferError>(())
            });
        }

        tm
    }

    fn update(&mut self, chunk: TChunk) {
       if let Some(t) = self.transfers.get_mut(&chunk.transfer_id) {
            t.chunks.push(chunk);
       } else {
        let mut t = Transfer::default();
        t.chunks.push(chunk);
        t.exp_chunks = chunk.chunks_count;
        self.transfers.insert(chunk.transfer_id, t)
       }
    }

    async fn _wait_completion(&mut self, id: &u64) {
        loop {
            if let Some(t) = self.get(id){
                if t.completed() {
                    return;
                }
            }
            sleep(Duration::from_millis(5)).await
        }
    }

    pub async fn wait_completion(&mut self, id: &u64, timeout: Duration) -> Result<(), Elapsed> {
        time::timeout(
            timeout,
            self._wait_completion(id)
        ).await
    }

    pub fn get(&mut self, id: &u64) -> Option<&Transfer>{
        self.transfers.get(id)
    }

    pub fn get_mut(&mut self, id: &u64) -> Option<&mut Transfer>{
        self.transfers.get_mut(id)
    }

    // returns None if transfer is not completed after timeout or if transfer is not found
    pub async fn wait_completed_and_get_mut(&mut self, id: &u64, timeout: Duration) -> Option<&mut Transfer>{
        if self.wait_completion(id, timeout).await.is_ok() {
            return self.transfers.get_mut(id);
        }
        None
    }
}
}

bpf_target_code! {
use aya_bpf::helpers::bpf_get_prandom_u32;
use aya_bpf::maps::{LruPerCpuHashMap, PerfEventArray};
use aya_bpf::{BpfContext, macros::*};
use core::ffi::c_void;

pub enum Error {
    DataTooBig,
    NoMoreSpace,
    InsertionFailure,
    MissingChunk,
    FailedToReadData,
}

#[map]
static INIT_MAP: LruPerCpuHashMap<u64, TChunk> = LruPerCpuHashMap::with_max_entries(1, 0);

#[map]
static TRANSFER_ARRAY: PerfEventArray<TChunk> = PerfEventArray::with_max_entries(MAX_CHUNK_COUNT as u32, 0);

static EMPTY_CHUNK: TChunk = Chunk{id: 0, transfer_id:0, data: Buffer::const_default(), chunks_count: 0};

#[inline(always)]
unsafe fn random_u64() -> u64 {
    core::mem::transmute([bpf_get_prandom_u32(), bpf_get_prandom_u32()])
}

#[inline(always)]
unsafe fn new_chunk_with_transfer_id(tid:u64, id:usize, count: usize) -> Result<&'static mut TChunk, Error>{
    let key=random_u64();
    INIT_MAP.insert(&key,&EMPTY_CHUNK,0).map_err(|_| Error::InsertionFailure)?;
    let chunk = &mut (*INIT_MAP.get_ptr_mut(&key).ok_or(Error::MissingChunk)?);
    chunk.id=id;
    chunk.transfer_id = tid;
    chunk.chunks_count = count;
    Ok(chunk)
}

#[inline(always)]
pub unsafe fn transfer_kernel_data<C: BpfContext, P>(ctx: &C, src: *const P, size: u32) -> Result<u64,Error>{
    transfer_data::<C, P, true>(ctx, src, size)
}

#[inline(always)]
pub unsafe fn transfer_user_data<C: BpfContext, P>(ctx: &C, src: *const P, size: u32) -> Result<u64,Error>{
    transfer_data::<C, P, false>(ctx, src, size)
}

#[inline(always)]
 unsafe fn transfer_data<C: BpfContext, P, const KERNEL: bool>(ctx: &C, src: *const P, size: u32) -> Result<u64,Error>{
    // we cannot transfer data because the map cannot old so much data
    let n = size as usize / size_of::<TChunk>() ;
    if n > MAX_CHUNK_COUNT{
        return Err(Error::DataTooBig);
    }

    // first chunk id to return in order to identify first chunk
    let tid = random_u64();
    let mut addr = src as *const c_void;
    let mut to_read = size;

    for i in 1..=MAX_CHUNK_COUNT{
        if to_read>0{
            // we get a new chunk and we modify it
            let chunk = new_chunk_with_transfer_id(tid, i, n+1)?;
            if KERNEL{
                chunk.data.read_kernel_at(addr, to_read).map_err(|_| Error::FailedToReadData)?;
            } else {
                chunk.data.read_user_at(addr, to_read).map_err(|_| Error::FailedToReadData)?;
            }
            // we substract the length of what we have read
            to_read -= chunk.data.len() as u32;
            // we update pointer for next chunk
            addr = addr.add(chunk.data.len());
            TRANSFER_ARRAY.output(ctx, chunk, 0);
        }
    }

    Ok(tid)
}


}
