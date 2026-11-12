//! Storage transfer profile for read scheduling. It chooses a request size and a
//! read parallelism from what Windows reports about the disk. It never changes
//! which bytes are read or how they are hashed; proof granules stay fixed.
use serde::Serialize;
use std::{fs::File, io, os::windows::io::AsRawHandle, ptr};
use windows_sys::Win32::System::IO::DeviceIoControl;

const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D_1400;
const STORAGE_ADAPTER_PROPERTY: u32 = 1;
const STORAGE_ACCESS_ALIGNMENT_PROPERTY: u32 = 6;
const STORAGE_DEVICE_SEEK_PENALTY_PROPERTY: u32 = 7;
const BUS_TYPE_NVME: u8 = 17;

/// Smallest and largest request the scheduler issues. 1 MiB keeps requests
/// aligned to the proof chunk; 8 MiB bounds each handle's buffer.
pub const MIN_REQUEST_BYTES: usize = 1024 * 1024;
pub const MAX_REQUEST_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_QUEUE_DEPTH: usize = 8;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct IoProfile {
    pub bus_type: Option<u8>,
    pub maximum_transfer_bytes: Option<u32>,
    pub maximum_physical_pages: Option<u32>,
    pub physical_sector_bytes: Option<u32>,
    pub incurs_seek_penalty: Option<bool>,
    pub request_bytes: usize,
    pub queue_depth: usize,
    pub source: &'static str,
}

impl IoProfile {
    /// The conservative profile when the device reports nothing usable.
    pub fn fallback() -> Self {
        Self {
            bus_type: None,
            maximum_transfer_bytes: None,
            maximum_physical_pages: None,
            physical_sector_bytes: None,
            incurs_seek_penalty: None,
            request_bytes: 4 * 1024 * 1024,
            queue_depth: 1,
            source: "fallback",
        }
    }
}

fn query(file: &File, property: u32, capacity: usize) -> io::Result<Vec<u8>> {
    // STORAGE_PROPERTY_QUERY: PropertyId, QueryType = PropertyStandardQuery,
    // one byte of AdditionalParameters (padded to the structure size).
    let mut input = [0u8; 12];
    input[..4].copy_from_slice(&property.to_le_bytes());
    let mut output = vec![0u8; capacity];
    let mut returned = 0u32;
    // SAFETY: File owns a live handle; both buffers are owned and sized as declared;
    // the call is synchronous and keeps neither pointer.
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle(),
            IOCTL_STORAGE_QUERY_PROPERTY,
            input.as_ptr().cast(),
            input.len() as u32,
            output.as_mut_ptr().cast(),
            output.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }
    admit_reply(output, returned)
}

/// The bytes Windows says it wrote into `output`. A count larger than the
/// buffer is not an answer: `truncate` would leave the buffer whole, and its
/// zero padding would then be read as property fields.
fn admit_reply(mut output: Vec<u8>, returned: u32) -> io::Result<Vec<u8>> {
    if returned as usize > output.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "storage property query returned more bytes than its buffer",
        ));
    }
    output.truncate(returned as usize);
    Ok(output)
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes(b.try_into().expect("four bytes")))
}

/// The part of the measured region one request covers: its offset within
/// the region and its length. The last request stops where the region does,
/// rounded up to the 4 KiB an unbuffered read has to be a multiple of.
fn lane_span(bytes: u64, request_bytes: usize, block: u64) -> (u64, usize) {
    let start = block * request_bytes as u64;
    let length = (bytes - start)
        .min(request_bytes as u64)
        .next_multiple_of(4096);
    (start, length as usize)
}

/// Lab measurement: read `bytes` from `\\.\PhysicalDriveN` at `offset` with
/// `queue_depth` unbuffered readers, each striding over `request_bytes` blocks,
/// and return MB/s. Read-only with write sharing; it never changes the disk.
pub fn read_throughput(
    disk_number: u32,
    offset: u64,
    bytes: u64,
    request_bytes: usize,
    queue_depth: usize,
) -> io::Result<f64> {
    use std::{
        alloc::{Layout, alloc_zeroed, dealloc},
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom},
        os::windows::fs::OpenOptionsExt,
        time::Instant,
    };
    if !offset.is_multiple_of(4096)
        || bytes == 0
        || !(MIN_REQUEST_BYTES..=MAX_REQUEST_BYTES).contains(&request_bytes)
        || !(1..=MAX_QUEUE_DEPTH).contains(&queue_depth)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "benchmark geometry out of range",
        ));
    }
    let path = format!(r"\\.\PhysicalDrive{disk_number}");
    let blocks = bytes.div_ceil(request_bytes as u64);
    let started = Instant::now();
    std::thread::scope(|scope| -> io::Result<()> {
        let mut readers = Vec::new();
        for lane in 0..queue_depth as u64 {
            let path = &path;
            readers.push(scope.spawn(move || -> io::Result<()> {
                let mut file = OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(0x2000_0000) // FILE_FLAG_NO_BUFFERING
                    .open(path)?;
                let layout = Layout::from_size_align(request_bytes, 4096)
                    .map_err(|_| io::Error::other("benchmark buffer layout"))?;
                // SAFETY: nonzero, valid layout; freed below with the same layout.
                let pointer = unsafe { alloc_zeroed(layout) };
                if pointer.is_null() {
                    return Err(io::Error::other("benchmark buffer allocation failed"));
                }
                // SAFETY: the allocation holds exactly `request_bytes` initialized bytes.
                let buffer = unsafe { std::slice::from_raw_parts_mut(pointer, request_bytes) };
                let result = (|| -> io::Result<()> {
                    let mut block = lane;
                    while block < blocks {
                        let (start, length) = lane_span(bytes, request_bytes, block);
                        file.seek(SeekFrom::Start(offset + start))?;
                        file.read_exact(&mut buffer[..length])?;
                        block += queue_depth as u64;
                    }
                    Ok(())
                })();
                // SAFETY: same pointer and layout as the allocation above.
                unsafe { dealloc(pointer, layout) };
                result
            }));
        }
        for reader in readers {
            reader
                .join()
                .map_err(|_| io::Error::other("benchmark reader panicked"))??;
        }
        Ok(())
    })?;
    // What was read: the region, not a whole request for its last part.
    Ok(bytes.next_multiple_of(4096) as f64 / started.elapsed().as_secs_f64() / 1e6)
}

/// Query the disk behind `file` (a `\\.\PhysicalDriveN` handle). Any property
/// Windows refuses is left unknown and the choice stays conservative.
pub fn for_disk(file: &File) -> IoProfile {
    let adapter = query(file, STORAGE_ADAPTER_PROPERTY, 64).ok();
    let alignment = query(file, STORAGE_ACCESS_ALIGNMENT_PROPERTY, 64).ok();
    let seek = query(file, STORAGE_DEVICE_SEEK_PENALTY_PROPERTY, 16).ok();
    let maximum_transfer_bytes = adapter.as_deref().and_then(|b| u32_at(b, 8));
    let maximum_physical_pages = adapter.as_deref().and_then(|b| u32_at(b, 12));
    let bus_type = adapter.as_deref().and_then(|b| b.get(24).copied());
    let physical_sector_bytes = alignment.as_deref().and_then(|b| u32_at(b, 20));
    let incurs_seek_penalty = seek.as_deref().and_then(|b| b.get(8)).map(|v| *v != 0);
    if adapter.is_none() {
        let mut profile = IoProfile::fallback();
        profile.physical_sector_bytes = physical_sector_bytes;
        profile.incurs_seek_penalty = incurs_seek_penalty;
        return profile;
    }
    // The adapter's transfer limit, further bounded by its scatter/gather pages.
    let mut cap = u64::from(maximum_transfer_bytes.unwrap_or(0));
    if let Some(pages) = maximum_physical_pages.filter(|pages| *pages > 1) {
        let paged = u64::from(pages - 1) * 4096;
        cap = if cap == 0 { paged } else { cap.min(paged) };
    }
    if cap == 0 {
        cap = MAX_REQUEST_BYTES as u64;
    }
    let mut request = MIN_REQUEST_BYTES;
    while request * 2 <= MAX_REQUEST_BYTES && (request * 2) as u64 <= cap {
        request *= 2;
    }
    // A rotational disk keeps one sequential stream. A disk that reports no
    // seek-penalty property (the Hyper-V lab disk) gets two: measured there,
    // two outstanding 1-4 MiB reads were about twice as fast as one.
    let queue_depth = match (incurs_seek_penalty, bus_type) {
        (Some(true), _) => 1,
        (_, Some(BUS_TYPE_NVME)) => 4,
        _ => 2,
    };
    IoProfile {
        bus_type,
        maximum_transfer_bytes,
        maximum_physical_pages,
        physical_sector_bytes,
        incurs_seek_penalty,
        request_bytes: request,
        queue_depth,
        source: "storage-properties",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reply_longer_than_its_buffer_is_refused_not_padded() {
        assert_eq!(admit_reply(vec![7; 16], 8).unwrap(), vec![7; 8]);
        assert_eq!(admit_reply(vec![7; 16], 16).unwrap(), vec![7; 16]);
        assert_eq!(admit_reply(vec![7; 16], 0).unwrap(), Vec::<u8>::new());
        let refused = admit_reply(vec![0; 16], 17).unwrap_err();
        assert_eq!(refused.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn the_benchmark_reads_its_region_and_nothing_after_it() {
        const MIB: u64 = 1024 * 1024;
        let spans = |bytes: u64, request: usize| -> Vec<(u64, usize)> {
            (0..bytes.div_ceil(request as u64))
                .map(|block| lane_span(bytes, request, block))
                .collect()
        };
        // Five MiB in 4 MiB requests is 4 + 1, not 4 + 4.
        assert_eq!(
            spans(5 * MIB, 4 * MIB as usize),
            vec![(0, 4 * MIB as usize), (4 * MIB, MIB as usize)]
        );
        // A whole number of requests is unchanged.
        assert_eq!(
            spans(8 * MIB, 4 * MIB as usize),
            vec![(0, 4 * MIB as usize), (4 * MIB, 4 * MIB as usize)]
        );
        // A ragged end is rounded up to one 4 KiB unit, which the caller's
        // region spacing already allows for, and never to a whole request.
        for bytes in [1, 4095, 4097, 5 * MIB + 1, 9 * MIB - 1] {
            let read: u64 = spans(bytes, MIB as usize)
                .iter()
                .map(|(_, length)| *length as u64)
                .sum();
            assert_eq!(read, bytes.next_multiple_of(4096), "{bytes}");
            for (start, length) in spans(bytes, MIB as usize) {
                assert!(length <= MIB as usize && length % 4096 == 0);
                assert!(start + length as u64 <= bytes.next_multiple_of(4096));
            }
        }
    }
}
