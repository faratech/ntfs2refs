//! `--review` (#110): a conversion that stops before its handoff.
//!
//! A review run writes every new byte, flushes it and reads it back exactly
//! as a conversion does, then does not write the handoff marker. It seals the
//! source again (offline, read-only), takes a fingerprint of the whole
//! converted partition, records it in `review-stop.json` beside the recovery
//! publication and puts the disk online read-only, so that Windows mounts the
//! converted volume write-protected under its letter. Rollback stays open:
//! `--recover` commits (handoff, verification, online as today) and
//! `--recover --rollback` puts the NTFS volume back.
//!
//! What a review run may do that another may not is decided by its recovery
//! publication alone, which is pinned by the checksum the run printed before
//! it wrote anything: a run whose publication does not record a review keeps
//! every check it had before this existed. A review run additionally:
//!
//! - accepts a frozen source under the apply marker that holds exactly the
//!   old or exactly the new selected bytes (a review run seals its source
//!   again after its last write);
//! - seals its source read-only beside the apply marker alone;
//! - compares the whole converted partition with the fingerprint taken at the
//!   stop before it commits or rolls back, and refuses both if it changed:
//!   a volume that was ever writable cannot be undone or committed safely;
//! - checks the restored NTFS volume against the source fingerprint of the
//!   run's frozen source after a rollback, before it is put online.
use crate::{
    ntfs_inspect::paged_storage::SourceScratch, selected_journal::SelectedLifecycle,
    source_fingerprint::resource::PagedSourceFingerprint,
};
use anyhow::{Context, Result, ensure};
use n2r_win32::general_layout::GeneralDiskBinding;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{Read, Seek, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicBool, Ordering},
};

static CHOSEN: AtomicBool = AtomicBool::new(false);

/// Chooses a review for the conversion of this process (`--review`).
pub(crate) fn choose() {
    CHOSEN.store(true, Ordering::SeqCst);
}

/// Whether this process converts for a review.
pub(crate) fn chosen() -> bool {
    CHOSEN.load(Ordering::SeqCst)
}

/// What a publication records: nothing for a run without a review, so that
/// the records of every other run are byte for byte what they were.
pub(crate) fn recorded() -> Option<bool> {
    chosen().then_some(true)
}

/// The name of the record a review run writes at its stop, beside its
/// recovery publication.
pub(crate) const RECORD_NAME: &str = "review-stop.json";
const RECORD_KIND: &str = "ntfs2refs-review-stop-v1";
/// How the converted partition is fingerprinted at the stop: XXH3-128 of
/// every 4 MiB piece of the whole partition, in order, under SHA-256.
pub(crate) const VOLUME_FINGERPRINT_KIND: &str = "whole-partition-xxh3-128-4mib-pieces-v1";
const VOLUME_DOMAIN: &[u8] = b"ntfs2refs/review/whole-partition/v1\0";

/// What a review run records at its stop. It is written only after the
/// source is sealed read-only again under the apply marker, and before the
/// disk is put online read-only.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ReviewStop {
    pub schema_version: u32,
    pub kind: String,
    /// The SHA-256 of the run's recovery publication.
    pub publication_sha256: String,
    pub source: GeneralDiskBinding,
    pub partition_bytes: u64,
    pub new_selected_sha256: String,
    pub volume_fingerprint_kind: String,
    pub volume_fingerprint: String,
    pub grants_authority: bool,
}

impl ReviewStop {
    pub(crate) fn new(
        publication_sha256: [u8; 32],
        source: &GeneralDiskBinding,
        new_selected_sha256: [u8; 32],
        volume_fingerprint: String,
    ) -> Self {
        Self {
            schema_version: 1,
            kind: RECORD_KIND.into(),
            publication_sha256: hex::encode(publication_sha256),
            source: source.clone(),
            partition_bytes: source.identity.partition_bytes,
            new_selected_sha256: hex::encode(new_selected_sha256),
            volume_fingerprint_kind: VOLUME_FINGERPRINT_KIND.into(),
            volume_fingerprint,
            grants_authority: false,
        }
    }

    /// Whether this record belongs to the run with this publication, source
    /// and new bytes.
    fn require_run(
        &self,
        path: &Path,
        publication_sha256: [u8; 32],
        source: &GeneralDiskBinding,
        new_selected_sha256: [u8; 32],
    ) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.kind == RECORD_KIND
                && !self.grants_authority
                && self.volume_fingerprint_kind == VOLUME_FINGERPRINT_KIND
                && self.volume_fingerprint.len() == 64,
            "the review record {} has another format",
            path.display()
        );
        ensure!(
            self.publication_sha256 == hex::encode(publication_sha256)
                && self.source == *source
                && self.partition_bytes == source.identity.partition_bytes
                && self.new_selected_sha256 == hex::encode(new_selected_sha256),
            "the review record {} belongs to another run, source or journal",
            path.display()
        );
        Ok(())
    }
}

pub(crate) fn record_path(publication: &Path) -> Result<PathBuf> {
    Ok(publication
        .parent()
        .context("the recovery publication has no directory")?
        .join(RECORD_NAME))
}

/// Writes the record of the stop, flushes it to the disk and reads it back.
/// It is written whole under a temporary name and then renamed, so that a
/// power cut leaves either no record or a whole one, never a torn one. A
/// record that is there already is refused: a run stops for review once.
pub(crate) fn write_record(path: &Path, record: &ReviewStop) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(record)?;
    let written = (|| -> Result<()> {
        ensure!(!path.exists(), "a record of this stop is there already");
        let partial = path.with_extension("json.partial");
        // A partial record of an earlier attempt was never renamed: nothing
        // reads it.
        match std::fs::remove_file(&partial) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&partial)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        std::fs::rename(&partial, path)?;
        // Flushing the renamed file commits the file system's log, the
        // rename with it, before the disk is put online.
        OpenOptions::new().write(true).open(path)?.sync_all()?;
        let mut back = Vec::new();
        File::open(path)?.read_to_end(&mut back)?;
        ensure!(
            back == bytes,
            "the record read back differs from what was written"
        );
        Ok(())
    })();
    written.with_context(|| format!("review stop: writing its record {}", path.display()))
}

/// The record of the stop, if the run reached it.
pub(crate) fn read_record(
    path: &Path,
    publication_sha256: [u8; 32],
    source: &GeneralDiskBinding,
    new_selected_sha256: [u8; 32],
) -> Result<Option<ReviewStop>> {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!("recovery: reading the review record {}", path.display())
            });
        }
    };
    let record: ReviewStop = serde_json::from_slice(&bytes)
        .with_context(|| format!("recovery: parsing the review record {}", path.display()))?;
    record.require_run(path, publication_sha256, source, new_selected_sha256)?;
    Ok(Some(record))
}

/// The fingerprint of a whole partition: XXH3-128 of each 4 MiB piece, read
/// in order, framed with its offset and length under SHA-256. It covers the
/// journaled ranges and everything else, file data that stayed in place
/// included, so that any write to the converted volume changes it.
pub(crate) fn volume_fingerprint<R: Read + Seek>(
    reader: &mut R,
    partition_bytes: u64,
    scratch: &SourceScratch,
) -> Result<String> {
    use crate::parallel_digest::{Chunk, MAX_CHUNK_BYTES, digest_chunks, workers};
    let _timed = n2r_win32::perf::scope(n2r_win32::perf::Point::SourceFingerprint);
    ensure!(
        partition_bytes > 0,
        "an empty partition has no review fingerprint"
    );
    let workers = workers();
    // One buffer per hashing thread and two being read, as digest_chunks
    // holds them, and the stacks of its threads.
    let ram = ((workers as u64) + 2)
        .checked_mul(MAX_CHUNK_BYTES as u64)
        .and_then(|n| n.checked_add(workers as u64 * 2 * 1024 * 1024))
        .context("review fingerprint memory overflow")?;
    let _ram = scratch.lease_ram(ram)?;
    let batch = workers * 8;
    let mut chunks = Vec::with_capacity(batch);
    let mut digest = Sha256::new();
    digest.update(VOLUME_DOMAIN);
    digest.update(partition_bytes.to_le_bytes());
    let mut flush = |chunks: &mut Vec<Chunk>| -> Result<()> {
        for (chunk, hash) in chunks.iter().zip(digest_chunks(reader, chunks)?) {
            digest.update(chunk.offset.to_le_bytes());
            digest.update((chunk.length as u64).to_le_bytes());
            digest.update(hash);
        }
        chunks.clear();
        Ok(())
    };
    let mut offset = 0u64;
    while offset < partition_bytes {
        let length = (partition_bytes - offset).min(MAX_CHUNK_BYTES as u64) as usize;
        chunks.push(Chunk { offset, length });
        offset += length as u64;
        if chunks.len() == batch {
            flush(&mut chunks)?;
        }
    }
    if !chunks.is_empty() {
        flush(&mut chunks)?;
    }
    Ok(hex::encode(digest.finalize()))
}

/// What a recovery does with a review run's source disk when it opens it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReviewOpen {
    /// As for every other run.
    AsToday,
    /// The review stop: online and read-only. Dismount it and seal the disk
    /// offline and read-only again before anything else.
    ResealStop,
    /// The disk is online and writable: the converted volume may have been
    /// written to, and neither direction is safe.
    RefuseWritable,
    /// Online and read-only without the record of the stop: a run never
    /// left its disk so before it recorded the stop.
    RefuseUnrecordedOnline,
}

/// The decision at open, from the lifecycle in the journal, the disk's
/// attributes (3 offline read-only, 1 offline, 2 online read-only, 0 online)
/// and whether the stop was recorded.
pub(crate) fn review_open(
    review: bool,
    lifecycle: SelectedLifecycle,
    disk_attributes: u64,
    recorded: bool,
) -> ReviewOpen {
    if !review || lifecycle != SelectedLifecycle::ApplyIntent {
        return ReviewOpen::AsToday;
    }
    match (disk_attributes, recorded) {
        (2, true) => ReviewOpen::ResealStop,
        (2, false) => ReviewOpen::RefuseUnrecordedOnline,
        (0, _) => ReviewOpen::RefuseWritable,
        _ => ReviewOpen::AsToday,
    }
}

/// Whether a recovery compares the whole partition with the fingerprint of
/// the stop before it goes in either direction: whenever the stop was
/// recorded and the journal still holds the apply intent alone. Until it
/// writes the rollback intent or the handoff, a recovery from the review
/// stop writes nothing to the source, so the partition must still be what
/// it was at the stop.
pub(crate) fn compare_before_direction(
    review: bool,
    lifecycle: SelectedLifecycle,
    recorded: bool,
) -> bool {
    review && recorded && lifecycle == SelectedLifecycle::ApplyIntent
}

/// Whether a rollback holds the restored NTFS volume to the fingerprint of
/// the run's frozen source before it is put online. Decided from the
/// lifecycle the recovery found, before it writes anything: every rollback
/// of a review run that had written to its source (the apply intent, the
/// rollback intent, or the abort marker of a rollback that did not put NTFS
/// online). A run cut before its apply intent wrote nothing; its
/// cancellation is not made to depend on the check.
pub(crate) fn check_restored_source(review: bool, found: SelectedLifecycle) -> bool {
    review
        && matches!(
            found,
            SelectedLifecycle::ApplyIntent
                | SelectedLifecycle::RollbackIntent
                | SelectedLifecycle::Aborted
        )
}

/// The refusal when the converted volume changed after the review stop.
pub(crate) fn changed_since_stop(path: &Path) -> anyhow::Error {
    anyhow::anyhow!(
        "the converted volume is not what it was when the run stopped for review (its fingerprint \
         in {} differs): it was written to after it was made writable. Neither committing nor \
         rolling back is safe now, and neither is done. The journal still holds the apply \
         intent; the disk is left offline and read-only. Copy what you need from the ReFS volume \
         (bring the disk online in Disk Management) and restore the NTFS volume from a backup",
        path.display()
    )
}

/// The fingerprint of the run's frozen NTFS source, reopened from the run's
/// own records (`source/source-frozen.json` in the conversion directory) and
/// held to the source digest and inspection digest that its authenticated
/// publication pins. Its stores are read below the conversion directory as
/// it is found now, wherever the working volume was mounted when they were
/// written (`found_below_conversion_directory`).
pub(crate) fn reopen_source_fingerprint(
    conversion_directory: &Path,
    publication_source_sha256: &str,
    publication_inspection_sha256: &str,
    scratch: &SourceScratch,
) -> Result<PagedSourceFingerprint> {
    let candidates = [
        conversion_directory
            .join("source")
            .join("source-frozen.json"),
        conversion_directory
            .join("source")
            .join("source")
            .join("source-frozen.json"),
    ];
    let mut found = candidates.iter().filter(|path| path.is_file());
    let path = found.next().with_context(|| {
        format!(
            "rollback check: the record of the frozen source is not in {}",
            conversion_directory.join("source").display()
        )
    })?;
    ensure!(
        found.next().is_none(),
        "rollback check: two records of the frozen source in {}",
        conversion_directory.display()
    );
    #[derive(Deserialize)]
    struct Frozen {
        source_sha256: String,
        inspection_sha256: String,
        fingerprint: crate::source_fingerprint::resource::ReopenedFingerprintPins,
    }
    let frozen: Frozen = serde_json::from_slice(
        &std::fs::read(path)
            .with_context(|| format!("rollback check: reading {}", path.display()))?,
    )
    .with_context(|| format!("rollback check: parsing {}", path.display()))?;
    ensure!(
        frozen.source_sha256 == publication_source_sha256
            && frozen.inspection_sha256 == publication_inspection_sha256
            && frozen.fingerprint.source_inspection_sha256 == publication_inspection_sha256,
        "rollback check: {} is not the record of this run's frozen source",
        path.display()
    );
    let mut pins = frozen.fingerprint;
    let mut moved = false;
    for store in [&mut pins.allocated, &mut pins.covered, &mut pins.omitted] {
        for page in [&mut store.data, &mut store.directory] {
            let now = found_below_conversion_directory(&page.path, conversion_directory);
            moved |= !now.as_os_str().eq_ignore_ascii_case(page.path.as_os_str());
            page.path = now;
        }
    }
    let stores = pins
        .allocated
        .data
        .path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default();
    if moved {
        println!(
            "The fingerprint of the frozen source was recorded on the working volume under \
             another name than it has now; it is read in {}.",
            stores.display()
        );
    }
    pins.open(scratch).with_context(|| {
        format!(
            "rollback check: reopening the fingerprint of {} from its stores in {}",
            path.display(),
            stores.display()
        )
    })
}

/// Where a file the run recorded below its conversion directory is now.
///
/// The fingerprint's stores are recorded by the paths they were written at,
/// which name the working volume as it was named then, by its drive letter.
/// The working volume can come back under another letter, as the
/// running-Windows route expects of its recovery environment from one start
/// to the next, while the conversion directory is the one this recovery
/// found and authenticated the run's publication in. A store recorded below
/// that directory, as it was named then, is opened below it as it is found
/// now: the two paths differ only in how the volume is named, the
/// directories below it are the same. Any other path is opened as recorded.
/// Either way the store is held to the size and the digests recorded for it
/// when it is opened, and the fingerprint to the run's publication.
fn found_below_conversion_directory(recorded: &Path, conversion_directory: &Path) -> PathBuf {
    use std::path::Component;
    // The names below the volume of an absolute path without `.` or `..`.
    fn below_volume(path: &Path) -> Option<Vec<&std::ffi::OsStr>> {
        let mut names = Vec::new();
        let mut rooted = false;
        for component in path.components() {
            match component {
                Component::Prefix(_) => {}
                Component::RootDir => rooted = true,
                Component::Normal(name) => names.push(name),
                Component::CurDir | Component::ParentDir => return None,
            }
        }
        rooted.then_some(names)
    }
    let Ok(now) = std::path::absolute(conversion_directory) else {
        return recorded.to_path_buf();
    };
    let (Some(recorded_names), Some(now_names)) = (below_volume(recorded), below_volume(&now))
    else {
        return recorded.to_path_buf();
    };
    if recorded_names.len() > now_names.len()
        && recorded_names
            .iter()
            .zip(&now_names)
            .all(|(recorded, now)| recorded.eq_ignore_ascii_case(now))
    {
        recorded_names[now_names.len()..]
            .iter()
            .fold(now.clone(), |path, name| path.join(name))
    } else {
        recorded.to_path_buf()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use SelectedLifecycle::*;

    const ALL: [SelectedLifecycle; 5] =
        [PreparedClear, ApplyIntent, RollbackIntent, Handoff, Aborted];

    #[test]
    fn a_process_that_did_not_choose_a_review_records_none() {
        // Nothing in this test binary chooses one; a publication of such a
        // process leaves the field out, so its bytes are what they were.
        assert!(!chosen());
        assert_eq!(recorded(), None);
    }

    #[test]
    fn a_run_without_a_review_is_opened_as_today_in_every_state() {
        for lifecycle in ALL {
            for disk in 0..4 {
                for recorded in [false, true] {
                    assert_eq!(
                        review_open(false, lifecycle, disk, recorded),
                        ReviewOpen::AsToday
                    );
                    assert!(!compare_before_direction(false, lifecycle, recorded));
                }
            }
            assert!(!check_restored_source(false, lifecycle));
        }
    }

    #[test]
    fn a_review_stop_is_sealed_again_only_when_it_was_recorded() {
        assert_eq!(
            review_open(true, ApplyIntent, 2, true),
            ReviewOpen::ResealStop
        );
        assert_eq!(
            review_open(true, ApplyIntent, 2, false),
            ReviewOpen::RefuseUnrecordedOnline
        );
    }

    #[test]
    fn a_writable_online_review_is_refused_in_both_directions() {
        for recorded in [false, true] {
            assert_eq!(
                review_open(true, ApplyIntent, 0, recorded),
                ReviewOpen::RefuseWritable
            );
        }
    }

    #[test]
    fn offline_review_states_open_as_today() {
        // 3: cut at its activation (old bytes), after its reseal (new
        // bytes) or after its record; 1: cut while writing, before the
        // reseal, or a recovery cut after it made the disk writable.
        for disk in [1, 3] {
            for recorded in [false, true] {
                assert_eq!(
                    review_open(true, ApplyIntent, disk, recorded),
                    ReviewOpen::AsToday
                );
            }
        }
    }

    #[test]
    fn other_lifecycles_of_a_review_run_open_as_today() {
        for lifecycle in [PreparedClear, RollbackIntent, Handoff, Aborted] {
            for disk in 0..4 {
                for recorded in [false, true] {
                    assert_eq!(
                        review_open(true, lifecycle, disk, recorded),
                        ReviewOpen::AsToday
                    );
                }
            }
        }
    }

    #[test]
    fn the_stop_fingerprint_is_compared_under_the_apply_intent_when_recorded() {
        for lifecycle in ALL {
            for recorded in [false, true] {
                assert_eq!(
                    compare_before_direction(true, lifecycle, recorded),
                    recorded && lifecycle == ApplyIntent
                );
            }
        }
    }

    #[test]
    fn every_rollback_of_a_review_run_that_wrote_checks_the_restored_source() {
        for lifecycle in ALL {
            assert_eq!(
                check_restored_source(true, lifecycle),
                matches!(lifecycle, ApplyIntent | RollbackIntent | Aborted),
                "{lifecycle:?}"
            );
        }
    }

    fn binding() -> GeneralDiskBinding {
        GeneralDiskBinding {
            disk_number: 7,
            volume_guid: "5f2d3e41-5555-4444-aabb-123456789abc".into(),
            identity: n2r_win32::layout::PartitionIdentity {
                disk_guid: "12345678-1111-2222-aaaa-123456789abc".into(),
                partition_guid: "23456789-2222-3333-bbbb-123456789abc".into(),
                partition_number: 2,
                disk_bytes: 8 << 30,
                partition_offset: 1 << 20,
                partition_bytes: 6 << 30,
                logical_sector_bytes: 512,
                physical_sector_bytes: 4096,
            },
            layout_profile: Default::default(),
        }
    }

    fn scratch() -> SourceScratch {
        SourceScratch::new(crate::ntfs_inspect::SourceMetadataBudget {
            ram_bytes: 256 * 1024 * 1024,
            scratch_bytes: 64 * 1024 * 1024,
            page_bytes: 4096,
            record_bytes: 64 * 1024,
            merge_fan_in: 8,
        })
        .unwrap()
    }

    #[test]
    fn a_record_is_written_once_read_back_and_held_to_its_run() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join(RECORD_NAME);
        let source = binding();
        let record = ReviewStop::new([1; 32], &source, [2; 32], "ab".repeat(32));
        // What a power cut during an earlier write leaves is never read.
        let partial = path.with_extension("json.partial");
        std::fs::write(&partial, b"{\"schema_ver").unwrap();
        assert_eq!(read_record(&path, [1; 32], &source, [2; 32]).unwrap(), None);
        write_record(&path, &record).unwrap();
        assert!(!partial.exists(), "the record is renamed into place whole");
        assert!(write_record(&path, &record).is_err(), "written twice");
        assert_eq!(
            read_record(&path, [1; 32], &source, [2; 32]).unwrap(),
            Some(record)
        );
        let foreign = read_record(&path, [9; 32], &source, [2; 32]).unwrap_err();
        assert!(foreign.to_string().contains("another run"), "{foreign}");
        let other_bytes = read_record(&path, [1; 32], &source, [8; 32]).unwrap_err();
        assert!(
            other_bytes.to_string().contains("another run"),
            "{other_bytes}"
        );
        assert_eq!(
            read_record(
                &directory.path().join("absent.json"),
                [1; 32],
                &source,
                [2; 32]
            )
            .unwrap(),
            None
        );
    }

    /// A small fingerprint of a 16 KiB partition, of which bytes 4096..12288
    /// are allocated and covered, written as a run writes its stores.
    fn fingerprint_stores(
        root: &Path,
        scratch: &SourceScratch,
    ) -> crate::source_fingerprint::resource::ReopenedFingerprintPins {
        use crate::ntfs_inspect::record_store::SortedRecordWriter;
        let store = |name: &str, rows: &[(u64, u64)]| {
            let mut writer =
                SortedRecordWriter::new(&root.join(name), *b"N2RFRNG1", scratch).unwrap();
            for &(offset, length) in rows {
                let mut key = [0u8; 16];
                key[..8].copy_from_slice(&offset.to_be_bytes());
                writer.reserve_next_record(256).unwrap();
                writer
                    .push(key, &serde_json::json!({"offset":offset,"length":length}))
                    .unwrap();
            }
            writer.finish().unwrap()
        };
        let allocated = store("allocated", &[(4096, 8192)]);
        let covered = store("covered", &[(4096, 8192)]);
        let omitted = store("omitted", &[]);
        serde_json::from_value(serde_json::json!({
            "schema_version": 1,
            "kind": crate::source_fingerprint::resource::FULL_KIND,
            "partition_bytes": 16384,
            "source_inspection_sha256": "cd".repeat(32),
            "policy": crate::verification_policy::VerificationPolicy::FullContent,
            "allocated": allocated, "covered": covered, "omitted": omitted,
            "allocated_bytes": 8192, "covered_bytes": 8192, "omitted_bytes": 0,
            "raw_extent_identity_streams": 0
        }))
        .unwrap()
    }

    #[test]
    fn a_rollback_reopens_the_frozen_source_fingerprint_from_the_runs_records() {
        let conversion = tempfile::tempdir().unwrap();
        let source = conversion.path().join("source");
        std::fs::create_dir_all(source.join("fingerprint")).unwrap();
        let writer = scratch();
        let pins = fingerprint_stores(&source.join("fingerprint"), &writer);
        let image = (0..16384u32).map(|n| (n % 251) as u8).collect::<Vec<_>>();
        let expected = pins
            .clone()
            .open(&writer)
            .unwrap()
            .hash_partition_reader(&mut std::io::Cursor::new(&image), 16384)
            .unwrap();
        let inspection = "cd".repeat(32);
        std::fs::write(
            source.join("source-frozen.json"),
            serde_json::to_vec_pretty(&serde_json::json!({
                "binding": null, "source_sha256": expected,
                "inspection_sha256": inspection, "fingerprint": pins,
                "source_payload_writes": 0
            }))
            .unwrap(),
        )
        .unwrap();
        drop(writer);
        // A recovery reopens it in a process of its own: another scratch.
        let recovery = scratch();
        let reopened =
            reopen_source_fingerprint(conversion.path(), &expected, &inspection, &recovery)
                .unwrap();
        let hash = |bytes: &[u8]| {
            reopened
                .hash_partition_reader(&mut std::io::Cursor::new(bytes), 16384)
                .unwrap()
        };
        assert_eq!(hash(&image), expected, "the restored source as it was");
        let mut changed = image.clone();
        changed[4096 + 100] ^= 1;
        assert_ne!(hash(&changed), expected, "a covered byte changed");
        // A record of another source is refused, before anything is read.
        let Err(foreign) =
            reopen_source_fingerprint(conversion.path(), &"ef".repeat(32), &inspection, &recovery)
        else {
            panic!("a record of another source was accepted");
        };
        assert!(
            foreign.to_string().contains("not the record"),
            "{foreign:#}"
        );
        // A run without its records is refused too.
        let empty = tempfile::tempdir().unwrap();
        assert!(
            reopen_source_fingerprint(empty.path(), &expected, &inspection, &recovery).is_err()
        );
    }

    #[test]
    fn the_volume_fingerprint_covers_every_byte_of_the_partition() {
        let scratch = scratch();
        let length = (crate::parallel_digest::MAX_CHUNK_BYTES * 3 + 4096) as u64;
        let mut bytes = vec![7u8; length as usize];
        let first =
            volume_fingerprint(&mut std::io::Cursor::new(&bytes), length, &scratch).unwrap();
        assert_eq!(
            first,
            volume_fingerprint(&mut std::io::Cursor::new(&bytes), length, &scratch).unwrap()
        );
        // A change anywhere, the last piece's tail included, is seen.
        for at in [
            0,
            crate::parallel_digest::MAX_CHUNK_BYTES + 1,
            length as usize - 1,
        ] {
            bytes[at] ^= 1;
            assert_ne!(
                first,
                volume_fingerprint(&mut std::io::Cursor::new(&bytes), length, &scratch).unwrap(),
                "a change at {at} is not seen"
            );
            bytes[at] ^= 1;
        }
    }
}
