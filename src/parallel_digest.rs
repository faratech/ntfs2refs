//! Bounded parallel XXH3-128 of independent chunks, for change detection
//! between two passes over the same frozen bytes in one run. It is not a
//! cryptographic content hash; file content records keep SHA-256. The caller's
//! thread reads every chunk in order through its one handle; up to [`workers`]
//! threads hash them. Digests return in chunk order, so a result never depends
//! on how many workers ran or on the device's request size.
use anyhow::{Result, anyhow, ensure};
use std::{
    io::{Read, Seek, SeekFrom},
    sync::{Arc, Mutex, mpsc},
};

/// Largest chunk one job may name; it bounds each recycled buffer.
pub(crate) const MAX_CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug)]
pub(crate) struct Chunk {
    pub offset: u64,
    pub length: usize,
}

/// Hash threads: the available parallelism less the reading thread, 1..=8.
pub(crate) fn workers() -> usize {
    std::thread::available_parallelism()
        .map_or(1, |cores| cores.get().saturating_sub(1))
        .clamp(1, 8)
}

/// The canonical (big-endian) XXH3-128 of `bytes`.
pub(crate) fn xxh3_128(bytes: &[u8]) -> [u8; 16] {
    xxhash_rust::xxh3::xxh3_128(bytes).to_be_bytes()
}

/// Like [`digest_chunks`] over a frozen partition, with as many outstanding
/// reads as its storage profile allows: this thread and each extra read lane
/// claim the next chunk, read it and hash it. Results are in chunk order and
/// do not depend on the lane count.
pub(crate) fn digest_frozen_chunks(
    image: &mut n2r_win32::GeneralFrozenPartition,
    chunks: &[Chunk],
) -> Result<Vec<[u8; 16]>> {
    let depth = image.io_profile().queue_depth.clamp(1, 8);
    digest_frozen_chunks_at_depth(image, chunks, depth)
}

/// A chunk at most this long is a small read: a lane reading such chunks
/// waits on each read's latency more than on the device's bandwidth.
pub(crate) const SMALL_READ_BYTES: usize = 256 * 1024;

/// How many reads are kept outstanding for chunks that are all small reads,
/// whatever queue depth the storage profile names for large ones: 20,000
/// reads of about 23 KiB at the profile's depth of two took 7.4 s (#250).
pub(crate) const SMALL_READ_DEPTH: usize = 8;

/// Whether every chunk is a small read ([`SMALL_READ_BYTES`]).
pub(crate) fn small_reads(chunks: &[Chunk]) -> bool {
    chunks.iter().all(|chunk| chunk.length <= SMALL_READ_BYTES)
}

/// [`digest_frozen_chunks`] with up to `depth` reads outstanding (this
/// thread and `depth - 1` read lanes), for a caller that has paid for that
/// many lanes. The digests do not depend on the depth.
pub(crate) fn digest_frozen_chunks_at_depth(
    image: &mut n2r_win32::GeneralFrozenPartition,
    chunks: &[Chunk],
    depth: usize,
) -> Result<Vec<[u8; 16]>> {
    let depth = depth.clamp(1, 8).min(chunks.len().max(1));
    if depth <= 1 {
        return digest_chunks(image, chunks);
    }
    let mut events = Vec::new();
    let mut lanes = image.read_lanes(depth - 1, &mut events)?;
    digest_chunks_lanes(image, &mut lanes, chunks, None)
}

/// The digests of `chunks`, read by `image` on this thread and by each of
/// `lanes` on a thread of its own, in chunk order. Nearby ascending small
/// chunks (gap ≤ 64 KiB, combined span ≤ 1 MiB) are coalesced into one read
/// and sliced in memory before hashing, preserving exact per-chunk digests.
/// Where `cancel` is set, no lane claims another span and the call fails: a
/// cancelled read never returns digests.
pub(crate) fn digest_chunks_lanes<R: Read + Seek, L: Read + Seek + Send>(
    image: &mut R,
    lanes: &mut [L],
    chunks: &[Chunk],
    cancel: Option<&std::sync::atomic::AtomicBool>,
) -> Result<Vec<[u8; 16]>> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    ensure!(
        chunks
            .iter()
            .all(|chunk| (1..=MAX_CHUNK_BYTES).contains(&chunk.length)),
        "parallel digest chunk must be between one byte and 4MiB"
    );
    const BRIDGE: u64 = 64 * 1024;
    const COALESCE_MAX: usize = 1024 * 1024;
    struct ReadSpan {
        start: u64,
        length: usize,
        first: usize,
        last: usize,
    }
    let mut spans: Vec<ReadSpan> = Vec::with_capacity(chunks.len());
    let mut i = 0;
    while i < chunks.len() {
        let first = i;
        let start = chunks[i].offset;
        let mut end = start.saturating_add(chunks[i].length as u64);
        i += 1;
        while i < chunks.len() {
            let next = chunks[i];
            if next.offset < end || next.offset - end > BRIDGE {
                break;
            }
            let next_end = next.offset.saturating_add(next.length as u64);
            if next_end - start > COALESCE_MAX as u64 {
                break;
            }
            end = next_end;
            i += 1;
        }
        spans.push(ReadSpan {
            start,
            length: (end - start) as usize,
            first,
            last: i,
        });
    }
    let largest = spans.iter().map(|span| span.length).max().unwrap_or(0);
    let next = AtomicUsize::new(0);
    let failed = AtomicBool::new(false);
    fn lane<T: Read + Seek>(
        reader: &mut T,
        chunks: &[Chunk],
        spans: &[ReadSpan],
        largest: usize,
        next: &AtomicUsize,
        failed: &AtomicBool,
        cancel: Option<&AtomicBool>,
    ) -> Result<Vec<(usize, [u8; 16])>> {
        let mut buffer = vec![0u8; largest];
        let mut digests = Vec::new();
        while !failed.load(Ordering::Acquire) {
            if cancel.is_some_and(|cancel| cancel.load(Ordering::Acquire)) {
                failed.store(true, Ordering::Release);
                return Err(anyhow!("the read was given up"));
            }
            let span_index = next.fetch_add(1, Ordering::AcqRel);
            let Some(span) = spans.get(span_index) else {
                break;
            };
            let bytes = &mut buffer[..span.length];
            let read = reader
                .seek(SeekFrom::Start(span.start))
                .and_then(|_| reader.read_exact(bytes));
            if let Err(error) = read {
                failed.store(true, Ordering::Release);
                return Err(error.into());
            }
            for position in span.first..span.last {
                let chunk = chunks[position];
                let from = (chunk.offset - span.start) as usize;
                digests.push((position, xxh3_128(&bytes[from..from + chunk.length])));
            }
        }
        Ok(digests)
    }
    let mut found = std::thread::scope(|scope| -> Result<Vec<(usize, [u8; 16])>> {
        let others: Vec<_> = lanes
            .iter_mut()
            .map(|reader| {
                scope.spawn(|| {
                    let _sampled = n2r_win32::stack_sampler::helper();
                    lane(reader, chunks, &spans, largest, &next, &failed, cancel)
                })
            })
            .collect();
        let mut found = lane(image, chunks, &spans, largest, &next, &failed, cancel)?;
        for other in others {
            found.extend(
                other
                    .join()
                    .map_err(|_| anyhow!("parallel read lane panicked"))??,
            );
        }
        Ok(found)
    })?;
    found.sort_unstable_by_key(|(position, _)| *position);
    ensure!(
        found.len() == chunks.len()
            && found
                .iter()
                .enumerate()
                .all(|(index, (position, _))| index == *position),
        "parallel read lanes did not hash every chunk exactly once"
    );
    Ok(found.into_iter().map(|(_, digest)| digest).collect())
}

/// The XXH3-128 of each chunk, in `chunks` order. Every chunk is read in full
/// or the call fails; no partial result is returned.
pub(crate) fn digest_chunks<R: Read + Seek>(
    image: &mut R,
    chunks: &[Chunk],
) -> Result<Vec<[u8; 16]>> {
    ensure!(
        chunks
            .iter()
            .all(|chunk| (1..=MAX_CHUNK_BYTES).contains(&chunk.length)),
        "parallel digest chunk must be between one byte and 4MiB"
    );
    let workers = workers().min(chunks.len()).max(1);
    let largest = chunks.iter().map(|chunk| chunk.length).max().unwrap_or(0);
    std::thread::scope(|scope| -> Result<Vec<[u8; 16]>> {
        let (jobs, queue) = mpsc::sync_channel::<(usize, Vec<u8>)>(workers);
        let queue = Arc::new(Mutex::new(queue));
        let (recycle, free) = mpsc::channel::<Vec<u8>>();
        let (done, results) = mpsc::channel::<(usize, [u8; 16])>();
        // One buffer per worker plus two in reading or queued bounds memory.
        for _ in 0..workers + 2 {
            let _ = recycle.send(Vec::with_capacity(largest));
        }
        let mut hashers = Vec::with_capacity(workers);
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let recycle = recycle.clone();
            let done = done.clone();
            hashers.push(scope.spawn(move || -> Result<()> {
                let _sampled = n2r_win32::stack_sampler::helper();
                loop {
                    let job = queue
                        .lock()
                        .map_err(|_| anyhow!("parallel digest queue poisoned"))?
                        .recv();
                    let Ok((position, buffer)) = job else {
                        return Ok(());
                    };
                    if done.send((position, xxh3_128(&buffer))).is_err() {
                        return Ok(());
                    }
                    let _ = recycle.send(buffer);
                }
            }));
        }
        // Only workers hold these now, so a reader waiting on them sees every
        // worker's exit instead of blocking.
        drop((queue, recycle, done));
        let mut read = Ok(());
        for (position, chunk) in chunks.iter().enumerate() {
            let Ok(mut buffer) = free.recv() else {
                break; // Every worker stopped; its error is reported below.
            };
            buffer.resize(chunk.length, 0);
            if let Err(error) = image
                .seek(SeekFrom::Start(chunk.offset))
                .and_then(|_| image.read_exact(&mut buffer))
            {
                read = Err(error);
                break;
            }
            if jobs.send((position, buffer)).is_err() {
                break;
            }
        }
        drop(jobs);
        for hasher in hashers {
            hasher
                .join()
                .map_err(|_| anyhow!("parallel digest worker panicked"))??;
        }
        read?;
        let mut digests = vec![None; chunks.len()];
        for (position, digest) in results.try_iter() {
            digests[position] = Some(digest);
        }
        digests
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| anyhow!("parallel digest did not hash every chunk"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::AtomicBool;

    #[test]
    fn lanes_digest_as_one_reader_does_and_a_cancelled_read_returns_no_digests() {
        let bytes: Vec<u8> = (0..200_000u32).map(|n| (n % 251) as u8).collect();
        let chunks: Vec<Chunk> = (0..40)
            .map(|n| Chunk {
                offset: n * 4_000,
                length: 3_000 + n as usize,
            })
            .collect();
        let alone = digest_chunks(&mut Cursor::new(bytes.clone()), &chunks).unwrap();
        let mut lanes: Vec<Cursor<Vec<u8>>> = (0..3).map(|_| Cursor::new(bytes.clone())).collect();
        let together = digest_chunks_lanes(
            &mut Cursor::new(bytes.clone()),
            &mut lanes,
            &chunks,
            Some(&AtomicBool::new(false)),
        )
        .unwrap();
        assert_eq!(together, alone);
        let cancelled = digest_chunks_lanes(
            &mut Cursor::new(bytes.clone()),
            &mut lanes,
            &chunks,
            Some(&AtomicBool::new(true)),
        );
        assert!(cancelled.is_err());
    }
}
