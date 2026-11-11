//! Preallocated lab-only signal; never source/replay authority.
use crate::{
    resource_preparation::create_external_output,
    selected_journal::resource_domain::prepare::FirstFlushedWrite,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    journal_file::GeneralJournalStorageBinding, reference_file::ReferenceFileSnapshot,
};
use serde::Serialize;
use std::{
    fs::{File, OpenOptions},
    io::{Cursor, Read, Seek, SeekFrom, Write},
    os::windows::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

const BYTES: usize = 4096;
pub(super) const RAM_RESERVE: u64 = 1024 * 1024;

pub(super) struct FirstWriteSignal {
    file: File,
    snapshot: ReferenceFileSnapshot,
    path: PathBuf,
    buffers: Vec<u8>,
    _parents: Vec<File>,
}
#[derive(Serialize)]
struct SignalRecord<'a> {
    kind: &'static str,
    schema_version: u32,
    actual: &'a FirstFlushedWrite,
    publication_path: &'a Path,
    publication_sha256: &'a str,
    signal_path: &'a Path,
    source_offline_and_actual_ap_observed: bool,
    source_replay_authority: bool,
    conversion_qualified: bool,
    physical_power_loss_proven: bool,
}
impl FirstWriteSignal {
    pub(super) fn create(
        output: &Path,
        journal: &GeneralJournalStorageBinding,
        minimum_free: u64,
    ) -> Result<Self> {
        let name = output
            .file_name()
            .and_then(|s| s.to_str())
            .context("ordinary diagnostic output name required")?;
        let directory = output.with_file_name(format!("{name}-first-write-signal"));
        // These exact write/readback buffers are allocated and held before
        // preparation. Job-limit headroom is diagnostic-only accounting; it
        // is not a claim of reserved physical RAM or arena coverage.
        let mut buffers = Vec::new();
        buffers.try_reserve_exact(2 * BYTES)?;
        ensure!(
            buffers.capacity() as u64 <= RAM_RESERVE / 2,
            "diagnostic signal buffers exceed their Job headroom"
        );
        buffers.resize(2 * BYTES, 0);
        let parents = create_external_output(&directory, journal)?;
        let available = n2r_win32::resource_native::observe_available_resources(&directory)?;
        ensure!(
            available.scratch_available_bytes
                >= minimum_free
                    .checked_add(1024 * 1024)
                    .context("signal reserve overflow")?,
            "signal cannot preserve journal reserve"
        );
        let path = directory.join("signal.json");
        // No reader can mistake a partially written record for the durable
        // signal; the handle is released only while unwinding the real error.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000 | 0x8000_0000)
            .open(&path)?;
        file.set_len(BYTES as u64)?;
        file.write_all(&[0u8; BYTES])?;
        file.sync_all()?;
        let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
            &file,
            BYTES as u64,
        )?;
        let root = format!("{}\\", journal.disk.volume_path()?);
        ensure!(
            snapshot.file_bytes == BYTES as u64
                && snapshot.allocation_bytes >= BYTES as u64
                && snapshot.number_of_links == 1
                && snapshot
                    .final_path
                    .to_ascii_lowercase()
                    .starts_with(&root.to_ascii_lowercase()),
            "signal actual storage or preallocation differs"
        );
        println!(
            "{}",
            serde_json::json!({"kind":"resource-first-write-signal-prepared",
            "signal_path":path,"actual_file_allocation_bytes":snapshot.allocation_bytes,
            "held_buffer_bytes":buffers.capacity(),"diagnostic_job_headroom_bytes":RAM_RESERVE,
            "physical_ram_reserved":false,"arena_ram_coverage_claimed":false,
            "grants_source_or_replay_authority":false})
        );
        std::io::stdout().flush()?;
        Ok(Self {
            file,
            snapshot,
            path,
            buffers,
            _parents: parents,
        })
    }

    pub(super) fn commit(
        &mut self,
        observation: &FirstFlushedWrite,
        publication: &Path,
        publication_sha256: &str,
    ) -> Result<()> {
        ensure!(
            n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                BYTES as u64
            )? == self.snapshot,
            "held diagnostic signal identity changed"
        );
        let record = SignalRecord {
            kind: "resource-first-flushed-write-observation-v1",
            schema_version: 1,
            actual: observation,
            publication_path: publication,
            publication_sha256,
            signal_path: &self.path,
            source_offline_and_actual_ap_observed: true,
            source_replay_authority: false,
            conversion_qualified: false,
            physical_power_loss_proven: false,
        };
        self.buffers[..BYTES].fill(b' ');
        let mut writer = Cursor::new(&mut self.buffers[..BYTES]);
        serde_json::to_writer(&mut writer, &record)
            .context("first-write signal exceeds its preallocated bound")?;
        let used = usize::try_from(writer.position())?;
        ensure!(
            used < BYTES,
            "first-write signal exceeds its preallocated bound"
        );
        drop(writer);
        self.file.seek(SeekFrom::Start(0))?;
        self.file.write_all(&self.buffers[..BYTES])?;
        self.file.sync_all()?;
        self.file.seek(SeekFrom::Start(0))?;
        self.file.read_exact(&mut self.buffers[BYTES..2 * BYTES])?;
        ensure!(
            self.buffers[..BYTES] == self.buffers[BYTES..2 * BYTES]
                && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file,
                    BYTES as u64
                )? == self.snapshot,
            "durable signal readback or owner differs"
        );
        let mut out = std::io::stdout().lock();
        out.write_all(&self.buffers[..used])?;
        out.write_all(b"\n")?;
        out.flush()?;
        Ok(())
    }
}
