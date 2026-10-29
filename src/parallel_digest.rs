//! Bounded parallel SHA-256 of independent chunks. The caller's thread reads
//! every chunk in order through its one handle; up to [`workers`] threads hash
//! them. Digests return in chunk order, so a result never depends on how many
//! workers ran or on the device's request size.
use anyhow::{Result, anyhow, ensure};
use std::{
    io::{self, Read, Seek, SeekFrom},
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

/// The SHA-256 of each chunk, in `chunks` order. Every chunk is read in full or
/// the call fails; no partial result is returned.
pub(crate) fn digest_chunks<R: Read + Seek>(
    image: &mut R,
    chunks: &[Chunk],
) -> Result<Vec<[u8; 32]>> {
    ensure!(
        chunks
            .iter()
            .all(|chunk| (1..=MAX_CHUNK_BYTES).contains(&chunk.length)),
        "parallel digest chunk must be between one byte and 4MiB"
    );
    let workers = workers().min(chunks.len()).max(1);
    let largest = chunks.iter().map(|chunk| chunk.length).max().unwrap_or(0);
    std::thread::scope(|scope| -> Result<Vec<[u8; 32]>> {
        let (jobs, queue) = mpsc::sync_channel::<(usize, Vec<u8>)>(workers);
        let queue = Arc::new(Mutex::new(queue));
        let (recycle, free) = mpsc::channel::<Vec<u8>>();
        let (done, results) = mpsc::channel::<(usize, [u8; 32])>();
        // One buffer per worker plus two in reading or queued bounds memory.
        for _ in 0..workers + 2 {
            let _ = recycle.send(Vec::with_capacity(largest));
        }
        let mut hashers = Vec::with_capacity(workers);
        for _ in 0..workers {
            let queue = Arc::clone(&queue);
            let recycle = recycle.clone();
            let done = done.clone();
            // Each worker creates its CNG object on its own thread.
            hashers.push(scope.spawn(move || -> io::Result<()> {
                let mut hash = n2r_win32::sha256_native::Sha256Reusable::new()?;
                loop {
                    let job = queue
                        .lock()
                        .map_err(|_| io::Error::other("parallel digest queue poisoned"))?
                        .recv();
                    let Ok((position, buffer)) = job else {
                        return Ok(());
                    };
                    let digest = hash.digest(&buffer)?;
                    if done.send((position, digest)).is_err() {
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
