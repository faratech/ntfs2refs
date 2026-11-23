//! The thread that writes a journal's staged rows while its preparation
//! stages the next ones.
//!
//! Journal preparation stages its rows in batches of up to four megabytes
//! (descriptors, OLD and NEW payloads, in file order) and wrote each batch,
//! and read it back where it reads back, on the thread that reads the source
//! and the capture for the rows that follow. Here a second batch buffer, paid
//! for as spare memory, lets a thread of its own write one batch, and read it
//! back where that is asked for, while the preparing thread fills the other.
//!
//! The batches are written through the journal's own handle, one after
//! another in the order they are handed over, each at the position the one
//! before left: the bytes written, their order and where they go are those
//! the preparing thread wrote itself, and so is where the handle is left. The
//! preparing thread uses the handle itself only when no batch is with the
//! writing thread: it waits for them first ([`StageWriter::drain`]), and
//! [`SharedJournal`] refuses it otherwise. Where the second buffer or the
//! thread cannot be had, the preparing thread writes the batches itself.
use super::*;
use std::{
    cell::Cell,
    io,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::{Scope, ScopedJoinHandle},
};

/// The preparing thread's use of the journal's handle while a
/// [`StageWriter`] writes through it: refused while a batch is with the
/// writing thread, so that the two never use the handle, and its position,
/// at once.
pub(super) struct SharedJournal<'a> {
    file: &'a File,
    in_flight: &'a Cell<usize>,
}

impl<'a> SharedJournal<'a> {
    pub(super) fn new(file: &'a File, in_flight: &'a Cell<usize>) -> Self {
        Self { file, in_flight }
    }

    fn idle(&self) -> io::Result<&'a File> {
        if self.in_flight.get() == 0 {
            Ok(self.file)
        } else {
            Err(io::Error::other(
                "journal preparation used the journal while its writing thread still held a staged batch of it",
            ))
        }
    }
}

impl Read for SharedJournal<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let mut file = self.idle()?;
        file.read(out)
    }
}

impl Write for SharedJournal<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut file = self.idle()?;
        file.write(bytes)
    }
    fn flush(&mut self) -> io::Result<()> {
        let mut file = self.idle()?;
        file.flush()
    }
}

impl Seek for SharedJournal<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let mut file = self.idle()?;
        file.seek(from)
    }
}

impl ReadSeek for SharedJournal<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.idle()?.metadata()?.len())
    }
}

impl DurableIo for SharedJournal<'_> {
    fn sync_all(&mut self) -> io::Result<()> {
        self.idle()?.sync_all()
    }
}

/// A batch for the writing thread: where it begins in the journal, and its
/// bytes, descriptors in place.
struct Batch {
    base: u64,
    bytes: Vec<u8>,
}

/// The preparing thread's side of the writing thread.
pub(super) struct StageWriter<'scope, 'a> {
    jobs: Option<mpsc::SyncSender<Batch>>,
    /// Each batch's buffer, emptied, once the batch is written (and read
    /// back), or the error that stopped the writing thread.
    returned: mpsc::Receiver<Result<Vec<u8>>>,
    /// Empty buffers the preparing thread may fill next.
    idle: Vec<Vec<u8>>,
    /// How many batches are with the writing thread; [`SharedJournal`] reads
    /// it.
    in_flight: &'a Cell<usize>,
    worker: Option<ScopedJoinHandle<'scope, ()>>,
    /// Set where the preparation stops early: the writing thread writes no
    /// batch it has not begun.
    stopping: Arc<AtomicBool>,
    path: &'a Path,
}

impl<'scope, 'a> StageWriter<'scope, 'a> {
    /// Starts the thread that writes batches through `file`, the journal at
    /// `path`. `spare` is the second batch buffer, empty; `read_back`, where
    /// each batch is read back and held to the bytes written, the buffer it
    /// is read into.
    pub(super) fn start<'env>(
        scope: &'scope Scope<'scope, 'env>,
        file: &'env File,
        path: &'a Path,
        spare: Vec<u8>,
        read_back: Option<Vec<u8>>,
        in_flight: &'a Cell<usize>,
    ) -> io::Result<Self> {
        let (jobs, queue) = mpsc::sync_channel::<Batch>(2);
        let (back, returned) = mpsc::channel::<Result<Vec<u8>>>();
        let journal = path.to_path_buf();
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopping);
        let worker = std::thread::Builder::new()
            .name("n2r-journal-writer".into())
            .spawn_scoped(scope, move || {
                let _sampled = n2r_win32::stack_sampler::helper();
                let mut file = file;
                let mut read_back = read_back;
                for Batch { base, mut bytes } in queue {
                    if stop.load(Ordering::SeqCst) {
                        return;
                    }
                    match write_batch(&mut file, &journal, base, &bytes, read_back.as_deref_mut()) {
                        Ok(()) => {
                            bytes.clear();
                            if back.send(Ok(bytes)).is_err() {
                                return;
                            }
                        }
                        Err(error) => {
                            let _ = back.send(Err(error));
                            return;
                        }
                    }
                }
            })?;
        Ok(Self {
            jobs: Some(jobs),
            returned,
            idle: vec![spare],
            in_flight,
            worker: Some(worker),
            stopping,
            path,
        })
    }

    /// Hands the batch `bytes`, which begins at `base` in the journal, to the
    /// writing thread, and returns an empty buffer for the next one: the
    /// other buffer, once the batch before this one is written.
    pub(super) fn submit(&mut self, base: u64, bytes: Vec<u8>) -> Result<Vec<u8>> {
        let sent = self
            .jobs
            .as_ref()
            .is_some_and(|jobs| jobs.send(Batch { base, bytes }).is_ok());
        if !sent {
            return Err(self.stopped());
        }
        self.in_flight.set(self.in_flight.get() + 1);
        match self.idle.pop() {
            Some(buffer) => Ok(buffer),
            None => self.take_back(),
        }
    }

    /// Waits until every batch handed over is in the journal (and read back
    /// where batches are); the preparing thread may then use the journal
    /// again, at the end of the last batch.
    pub(super) fn drain(&mut self) -> Result<()> {
        while self.in_flight.get() != 0 {
            let buffer = self.take_back()?;
            self.idle.push(buffer);
        }
        Ok(())
    }

    /// Waits for every batch, then ends the writing thread.
    pub(super) fn finish(mut self) -> Result<()> {
        self.drain()?;
        self.jobs = None;
        match self.worker.take().map(ScopedJoinHandle::join) {
            Some(Err(_)) => anyhow::bail!(
                "journal preparation: the thread writing the staged rows of the journal {} panicked",
                self.path.display()
            ),
            _ => Ok(()),
        }
    }

    fn take_back(&mut self) -> Result<Vec<u8>> {
        match self.returned.recv() {
            Ok(Ok(buffer)) => {
                self.in_flight.set(self.in_flight.get() - 1);
                Ok(buffer)
            }
            Ok(Err(error)) => {
                self.jobs = None;
                Err(error)
            }
            Err(_) => Err(self.stopped()),
        }
    }

    /// The error that stopped the writing thread: the one it sent before it
    /// stopped, or its panic.
    fn stopped(&mut self) -> anyhow::Error {
        self.jobs = None;
        while let Ok(message) = self.returned.try_recv() {
            if let Err(error) = message {
                return error;
            }
        }
        let panicked = matches!(self.worker.take().map(ScopedJoinHandle::join), Some(Err(_)));
        anyhow::anyhow!(
            "journal preparation: the thread writing the staged rows of the journal {} {}",
            self.path.display(),
            if panicked {
                "panicked"
            } else {
                "stopped before its batches were written"
            }
        )
    }
}

impl Drop for StageWriter<'_, '_> {
    /// A preparation that stops early lets the writing thread finish the
    /// batch it is writing, leaves any other unwritten, and ends the thread.
    /// After [`StageWriter::finish`] there is none left.
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::SeqCst);
        self.jobs = None;
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Writes `bytes` at the journal's position, which must be `base`, and where
/// `read_back` is given reads them back and holds them to `bytes`, as the
/// preparing thread does when it writes a batch itself. Leaves the position
/// at the end of the batch.
fn write_batch(
    file: &mut &File,
    path: &Path,
    base: u64,
    bytes: &[u8],
    read_back: Option<&mut [u8]>,
) -> Result<()> {
    // Where the batch is not read back, nothing else would notice it
    // written anywhere but at its place before the gate.
    let at = file.stream_position().with_context(|| {
        format!(
            "journal preparation: finding the position of the journal {} before its staged rows at offset {base}",
            path.display()
        )
    })?;
    ensure!(
        at == base,
        "journal preparation: the journal {} is at offset {at}, not at offset {base} where its staged rows begin; the journal is not used",
        path.display()
    );
    file.write_all(bytes).with_context(|| {
        format!(
            "journal preparation: writing the staged rows at offset {base} ({} bytes) of the journal {}",
            bytes.len(),
            path.display()
        )
    })?;
    let Some(buffer) = read_back else {
        return Ok(());
    };
    file.seek(SeekFrom::Start(base)).with_context(|| {
        format!(
            "journal preparation read-back: seeking to the staged rows at offset {base} of the journal {}",
            path.display()
        )
    })?;
    let mut pos = 0usize;
    while pos < bytes.len() {
        let count = (bytes.len() - pos).min(buffer.len());
        file.read_exact(&mut buffer[..count]).with_context(|| {
            format!(
                "journal preparation read-back: reading the staged rows at offset {} of the journal {}",
                base + pos as u64,
                path.display()
            )
        })?;
        ensure!(
            buffer[..count] == bytes[pos..pos + count],
            "journal preparation read-back: staged batch at offset {} of the journal {} differs from the bytes written; the journal is not used",
            base + pos as u64,
            path.display()
        );
        pos += count;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn batch(seed: u8, length: usize) -> Vec<u8> {
        (0..length)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Writes `batches` through a writing thread (reading each back where
    /// `read_back`) and returns the file's bytes and where it was left.
    fn written_by_the_thread(batches: &[Vec<u8>], read_back: bool) -> (Vec<u8>, u64) {
        let file = tempfile::tempfile().unwrap();
        let path = Path::new("journal");
        let in_flight = Cell::new(0);
        let mut shared = SharedJournal::new(&file, &in_flight);
        shared.write_all(b"header").unwrap();
        std::thread::scope(|scope| {
            let capacity = batches.iter().map(Vec::len).max().unwrap();
            let mut writer = StageWriter::start(
                scope,
                &file,
                path,
                Vec::with_capacity(capacity),
                read_back.then(|| vec![0u8; 7]),
                &in_flight,
            )
            .unwrap();
            let mut stage = Vec::with_capacity(capacity);
            let mut base = 6u64;
            for (index, bytes) in batches.iter().enumerate() {
                stage.extend_from_slice(bytes);
                stage = writer.submit(base, std::mem::take(&mut stage)).unwrap();
                assert!(stage.is_empty() && stage.capacity() >= capacity);
                base += bytes.len() as u64;
                if index == 1 {
                    // The preparing thread takes the journal back for a row
                    // of its own, where the last batch left it.
                    writer.drain().unwrap();
                    shared.write_all(b"own row").unwrap();
                    base += 7;
                }
            }
            writer.finish().unwrap();
        });
        let at = shared.stream_position().unwrap();
        let mut stored = Vec::new();
        shared.seek(SeekFrom::Start(0)).unwrap();
        shared.read_to_end(&mut stored).unwrap();
        (stored, at)
    }

    #[test]
    fn batches_go_where_the_preparing_thread_would_write_them() {
        let batches: Vec<Vec<u8>> = (0..5).map(|i| batch(i, 1000 + 37 * i as usize)).collect();
        let mut expected = b"header".to_vec();
        for (index, bytes) in batches.iter().enumerate() {
            expected.extend_from_slice(bytes);
            if index == 1 {
                expected.extend_from_slice(b"own row");
            }
        }
        for read_back in [false, true] {
            let (stored, at) = written_by_the_thread(&batches, read_back);
            assert_eq!(stored, expected, "read back: {read_back}");
            assert_eq!(at, expected.len() as u64, "left at the end of the last");
        }
    }

    #[test]
    fn the_journal_is_refused_to_the_preparing_thread_while_a_batch_is_out() {
        let file = tempfile::tempfile().unwrap();
        let in_flight = Cell::new(0);
        let mut shared = SharedJournal::new(&file, &in_flight);
        std::thread::scope(|scope| {
            let mut writer = StageWriter::start(
                scope,
                &file,
                Path::new("journal"),
                Vec::with_capacity(16),
                None,
                &in_flight,
            )
            .unwrap();
            let _next = writer.submit(0, batch(1, 16)).unwrap();
            assert!(
                shared.write_all(b"x").is_err(),
                "refused while the batch is out"
            );
            writer.drain().unwrap();
            shared.write_all(b"x").unwrap();
            writer.finish().unwrap();
        });
    }

    #[test]
    fn a_batch_is_written_only_at_its_own_offset() {
        let file = tempfile::tempfile().unwrap();
        let in_flight = Cell::new(0);
        std::thread::scope(|scope| {
            let mut writer = StageWriter::start(
                scope,
                &file,
                Path::new("journal"),
                Vec::with_capacity(16),
                None,
                &in_flight,
            )
            .unwrap();
            let next = writer.submit(5, batch(1, 16)).unwrap();
            let error = match writer.submit(21, next) {
                Err(error) => error,
                Ok(_) => writer.drain().unwrap_err(),
            };
            let message = format!("{error:#}");
            assert!(
                message.contains("the journal journal is at offset 0, not at offset 5"),
                "{message}"
            );
        });
        assert_eq!(file.metadata().unwrap().len(), 0, "nothing was written");
    }

    #[test]
    fn a_failed_write_is_the_error_of_a_later_hand_over() {
        // A read-only handle: the write fails, and the error names the
        // journal and the offset.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal");
        std::fs::write(&path, b"").unwrap();
        let file = File::open(&path).unwrap();
        let in_flight = Cell::new(0);
        std::thread::scope(|scope| {
            let mut writer = StageWriter::start(
                scope,
                &file,
                &path,
                Vec::with_capacity(16),
                None,
                &in_flight,
            )
            .unwrap();
            let next = writer.submit(0, batch(1, 16)).unwrap();
            let error = match writer.submit(16, next) {
                Err(error) => error,
                Ok(_) => writer.drain().unwrap_err(),
            };
            let message = format!("{error:#}");
            assert!(
                message.contains("writing the staged rows at offset 0")
                    && message.contains(&path.display().to_string()),
                "{message}"
            );
        });
    }
}
