//! Native ordinary-file allocation reproduction. No source/disk/VM arguments.
#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("artifact allocation probe stopped: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{file_storage, reference_file, tree_resources::ResourceBudget};
    use ntfs2refs::artifact_arena::{ArtifactArena, ArtifactGroup, ArtifactLease};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };
    const ACTUAL_LITERAL_BYTES: u64 = 86_695_936;
    const INDEX_ROWS: u64 = 7054;
    const INDEX_BYTES: u64 = 128 + INDEX_ROWS * 80 + 128;
    const GROUP_BYTES: u64 = 256 << 20;
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        acknowledge_new_disposable_staging: bool,
        /// Actual failed-run literal length by default; keep the native probe bounded.
        #[arg(long, default_value_t = ACTUAL_LITERAL_BYTES)]
        literal_bytes: u64,
    }
    struct CappedWriter {
        file: File,
        remaining: u64,
    }
    impl Write for CappedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() as u64 > self.remaining {
                return Err(io::Error::other("allocation probe metadata bound exceeded"));
            }
            let count = self.file.write(bytes)?;
            self.remaining -= count as u64;
            Ok(count)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    struct Case {
        report: serde_json::Value,
        _readonly: File,
        _arena: ArtifactArena,
        _artifact: Option<ArtifactLease>,
    }
    fn route_finish_case(root: &Path) -> Result<serde_json::Value> {
        use ntfs2refs::ntfs_inspect::{
            SourceMetadataBudget,
            paged_storage::SourceScratch,
            record_store::{SortedRecordStore, SortedRecordWriter},
        };
        fs::create_dir(root)?;
        let budget = ResourceBudget {
            schema_version: 1,
            ram_bytes: 64 << 20,
            scratch_bytes: 512 << 20,
            page_bytes: 4 << 20,
            max_row_bytes: 65536,
            retained_index_bytes: 1 << 20,
            handle_slots: 64,
        };
        let arena = ArtifactArena::new(root, budget, &[])?;
        let group = arena.reserve_group(ArtifactGroup::Capture, GROUP_BYTES)?;
        let scratch = SourceScratch::new_auxiliary_in_arena(
            SourceMetadataBudget::from_resource_budget(budget)?,
            group,
        )?;
        let mut writer = SortedRecordWriter::new(&root.join("routes"), *b"N2RROUT1", &scratch)?;
        for ordinal in 0u64..2400 {
            let mut key = [0u8; 16];
            key[..8].copy_from_slice(&ordinal.to_be_bytes());
            writer.push(
                key,
                &serde_json::json!({"ordinal":ordinal,"offset":ordinal*4096,
                "length":4096,"padding":"r".repeat(240+(ordinal%97)as usize)}),
            )?;
        }
        // Exercise the real production page/index/footer writer and its true
        // writer-close-before-path-reopen artifact seal, without normalization.
        let pin = writer.finish()?;
        let store = SortedRecordStore::open(&pin, &scratch)?;
        store.revalidate()?;
        let mut snapshots = Vec::new();
        for page in [&pin.data, &pin.directory] {
            let file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(&page.path)?;
            snapshots.push(reference_file::observe_reference_file_handle_with_limit(
                &file,
                GROUP_BYTES,
            )?);
        }
        let _seal = scratch.seal()?;
        Ok(
            serde_json::json!({"production_writer_path":"SortedRecordWriter/SourceRangeWriter/metadata_pages::Writer::finish",
            "normalization_used":false,"actual_closed_store_and_group_sealed":true,
            "records":pin.records,"pin":pin,"post_true_writer_close_snapshots":snapshots,
            "same_as_original_route_contents_or_exact_lengths":false,"source_payload_io_issued":false}),
        )
    }
    fn case(root: &Path, normalize: bool, index_pattern: bool, literal_bytes: u64) -> Result<Case> {
        let bytes = if index_pattern {
            INDEX_BYTES
        } else {
            literal_bytes
        };
        fs::create_dir(root)?;
        let budget = ResourceBudget {
            schema_version: 1,
            ram_bytes: 64 << 20,
            scratch_bytes: 512 << 20,
            page_bytes: 4096,
            max_row_bytes: 65536,
            retained_index_bytes: 1 << 20,
            handle_slots: 64,
        };
        let arena = ArtifactArena::new(root, budget, &[])?;
        let group = arena.reserve_group(ArtifactGroup::Capture, GROUP_BYTES)?;
        let path = root.join(if index_pattern {
            "capture.index"
        } else {
            "literal.bin"
        });
        let mut permit = group.reserve_file(&path, if index_pattern { 256 } else { 0 })?;
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        let fresh = reference_file::observe_reference_file_handle_with_limit(&writer, bytes)?;
        ensure!(
            fresh.file_bytes == 0 && fresh.number_of_links == 1,
            "fresh exclusive probe writer required"
        );
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 4096];
        let mut maximum_sampled_allocation = 0;
        if index_pattern {
            let image = 52u64 << 30;
            let mut header = [0u8; 128];
            header[..8].copy_from_slice(b"N2RCAP02");
            header[8..12].copy_from_slice(&2u32.to_le_bytes());
            header[12..16].copy_from_slice(&80u32.to_le_bytes());
            header[16..24].copy_from_slice(&image.to_le_bytes());
            writer.write_all(&header)?;
            digest.update(header);
            for ordinal in 0..INDEX_ROWS {
                // Match flush_tail's small append and prior-row seek/read use.
                if ordinal >= 2 && ordinal % 4 == 0 {
                    let mut prior = [0u8; 80];
                    writer.seek(SeekFrom::Start(128 + (ordinal / 2) * 80))?;
                    writer.read_exact(&mut prior)?;
                }
                let at = 128 + ordinal * 80;
                ensure!(
                    writer.metadata()?.len() == at,
                    "index append prefix changed"
                );
                writer.seek(SeekFrom::Start(at))?;
                let mut row = [0u8; 80];
                row[..8].copy_from_slice(&(4096 + ordinal * 8192).to_le_bytes());
                row[8..16].copy_from_slice(&4096u64.to_le_bytes());
                row[24..32].copy_from_slice(&1u64.to_le_bytes()); // NEW_ZERO, no other flags.
                row[40..48].copy_from_slice(&ordinal.to_le_bytes());
                let mut row_hash = Sha256::new();
                row_hash.update(b"n2r-owned-capture-index-row-v2\0");
                row_hash.update(image.to_le_bytes());
                row_hash.update(&row[..48]);
                row[48..].copy_from_slice(&row_hash.finalize());
                permit.extend(80)?;
                writer.write_all(&row)?;
                digest.update(row);
                maximum_sampled_allocation = maximum_sampled_allocation.max(
                    reference_file::observe_reference_file_handle_with_limit(&writer, bytes)?
                        .allocation_bytes,
                );
            }
            let mut footer = [0u8; 128];
            footer[..8].copy_from_slice(b"N2RCEND2");
            footer[8..16].copy_from_slice(&INDEX_ROWS.to_le_bytes());
            footer[16..24].copy_from_slice(&(INDEX_ROWS * 4096).to_le_bytes());
            footer[32..40].copy_from_slice(&image.to_le_bytes());
            footer[40..72].copy_from_slice(&digest.clone().finalize());
            writer.seek(SeekFrom::Start(bytes - 128))?;
            writer.write_all(&footer)?;
            digest.update(footer);
        } else {
            for ordinal in 0..bytes / 4096 {
                // Same write/grant size as capture; ordinary uncompressed bytes.
                for (index, byte) in buffer.iter_mut().enumerate() {
                    *byte = (ordinal.wrapping_mul(131).wrapping_add(index as u64 * 17) & 255) as u8;
                }
                permit.extend(4096)?;
                writer.write_all(&buffer)?;
                digest.update(buffer);
                if ordinal % 1024 == 1023 {
                    maximum_sampled_allocation = maximum_sampled_allocation.max(
                        reference_file::observe_reference_file_handle_with_limit(&writer, bytes)?
                            .allocation_bytes,
                    );
                }
            }
        }
        writer.sync_all()?;
        let hash = hex::encode(digest.finalize());
        let before = reference_file::observe_reference_file_handle_with_limit(&writer, bytes)?;
        maximum_sampled_allocation = maximum_sampled_allocation.max(before.allocation_bytes);
        let slack = arena.allocation_slack_bytes();
        let normalization = if normalize {
            Some(file_storage::normalize_allocation_at_eof(
                &writer, bytes, bytes, slack,
            )?)
        } else {
            None
        };
        let after_writer =
            reference_file::observe_reference_file_handle_with_limit(&writer, bytes)?;
        let readonly = file_storage::duplicate_readonly(&writer)?;
        drop(writer);
        let after_duplicate =
            reference_file::observe_reference_file_handle_with_limit(&readonly, bytes)?;
        ensure!(
            before.volume_serial_number == after_duplicate.volume_serial_number
                && before.file_id_128 == after_duplicate.file_id_128
                && before.final_path == after_duplicate.final_path
                && after_duplicate.file_bytes == bytes,
            "probe file identity/EOF changed across live readonly handoff"
        );
        let verification = permit.verify_closed_handle(&readonly, &hash);
        let error = verification.as_ref().err().map(|e| format!("{e:#}"));
        let actual_guard_refused = error
            .as_ref()
            .is_some_and(|e| e.contains("artifact physical allocation exceeds reserved slack"));
        let artifact = match verification {
            Ok(artifact) => {
                let _seal = group.seal()?;
                Some(artifact)
            }
            Err(_error) if !normalize && actual_guard_refused => None,
            Err(error) => return Err(error),
        };
        ensure!(
            !normalize || artifact.is_some(),
            "normalized native arena did not seal"
        );
        let report = serde_json::json!({
            "normalize":normalize,"write_pattern":if index_pattern { "N2RCAP02-128-header-7054x80-row-128-footer-with-prior-reads" } else { "literal-4096-byte-appends" },
            "wire_bytes":bytes,"planned_and_full_arena_sha256":hash,
            "index_rows":if index_pattern { Some(INDEX_ROWS) } else { None },
            "fixture_index_flags":"NEW_ZERO only; no source/replay authority",
            "reserved_slack":slack,"capture_group_capacity_bytes":GROUP_BYTES,
            "before_normalization":before,"normalization":normalization,
            "after_writer_normalization":after_writer,"after_writer_drop_same_file_object":after_duplicate,
            "sampled_maximum_allocation_bytes":maximum_sampled_allocation,
            "sampled_allocation_within_prepaid_group_capacity":maximum_sampled_allocation<=GROUP_BYTES,
            "samples_are_not_a_hard_transient_peak_or_quota":true,
            "actual_original_arena_guard_refused":actual_guard_refused,"arena_error":error,
            "actual_closed_artifact_and_group_sealed":artifact.is_some(),
            "source_payload_io_issued":false
        });
        Ok(Case {
            report,
            _readonly: readonly,
            _arena: arena,
            _artifact: artifact,
        })
    }
    let args = Args::parse();
    ensure!(
        args.literal_bytes >= 4096
            && args.literal_bytes <= 128 << 20
            && args.literal_bytes.is_multiple_of(4096),
        "literal fixture must be4KiB-aligned and at most128MiB"
    );
    ensure!(
        args.acknowledge_new_disposable_staging
            && args.directory.is_absolute()
            && !args.directory.exists(),
        "fresh disposable ordinary probe directory required"
    );
    for component in args.directory.components() {
        match component {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                anyhow::bail!("local probe directory required")
            }
            Component::CurDir | Component::ParentDir => {
                anyhow::bail!("probe directory traversal refused")
            }
            Component::Normal(p)
                if p.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                anyhow::bail!("ambiguous probe directory")
            }
            _ => {}
        }
    }
    let parent = args.directory.parent().context("probe parent absent")?;
    for path in parent.ancestors() {
        let m = fs::symlink_metadata(path)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "ordinary probe ancestry required"
        );
    }
    let sampled = n2r_win32::resource_native::observe_available_resources(parent)?;
    ensure!(
        sampled.scratch_available_bytes >= 5 * (512 << 20) + (1 << 30),
        "probe must admit five bounded arena ceilings plus1GiB free reserve"
    );
    fs::create_dir(&args.directory)?;
    let baseline = case(
        &args.directory.join("unmodified"),
        false,
        false,
        args.literal_bytes,
    )?;
    let normalized = case(
        &args.directory.join("normalized"),
        true,
        false,
        args.literal_bytes,
    )?;
    let index_baseline = case(
        &args.directory.join("index-unmodified"),
        false,
        true,
        args.literal_bytes,
    )?;
    let index_normalized = case(
        &args.directory.join("index-normalized"),
        true,
        true,
        args.literal_bytes,
    )?;
    let routes = route_finish_case(&args.directory.join("paged-routes"))?;
    let reproduced = baseline.report["actual_original_arena_guard_refused"] == true
        || index_baseline.report["actual_original_arena_guard_refused"] == true;
    let success = reproduced
        && normalized.report["actual_closed_artifact_and_group_sealed"] == true
        && index_normalized.report["actual_closed_artifact_and_group_sealed"] == true;
    let mut output = CappedWriter {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.directory.join("result.json"))?,
        remaining: 512 << 10,
    };
    serde_json::to_writer_pretty(
        &mut output,
        &serde_json::json!({
            "schema_version":1,"kind":"native-exclusive-artifact-allocation-normalization","success":success,
        "baseline_reproduced":reproduced,"unmodified":baseline.report,"normalized":normalized.report,
        "index_unmodified":index_baseline.report,"index_normalized":index_normalized.report,"paged_routes":routes,
            "observed_resources_before":sampled,"source_disk_argument_supplied":false,
            "conversion_or_recovery_qualified":false,"automatic_cleanup_attempted":false
        }),
    )?;
    output.write_all(b"\n")?;
    output.file.sync_all()?;
    ensure!(
        success,
        "native allocation fixture did not reproduce baseline refusal and normalized seal; actual results preserved"
    );
    println!(
        "Native allocation probe passed. Records: {}",
        args.directory.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("artifact allocation probe requires Windows");
    std::process::exit(1);
}
