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
        io::{self, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };
    const BYTES: u64 = (100 << 20) + 4096;
    const GROUP_BYTES: u64 = 256 << 20;
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        acknowledge_new_disposable_staging: bool,
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
    fn case(root: &Path, normalize: bool) -> Result<Case> {
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
        let path = root.join("literal.bin");
        let mut permit = group.reserve_file(&path, 0)?;
        let mut writer = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&path)?;
        let fresh = reference_file::observe_reference_file_handle_with_limit(&writer, BYTES)?;
        ensure!(
            fresh.file_bytes == 0 && fresh.number_of_links == 1,
            "fresh exclusive probe writer required"
        );
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 4096];
        let mut maximum_sampled_allocation = 0;
        for ordinal in 0..BYTES / 4096 {
            // Same write/grant size as capture; ordinary uncompressed bytes.
            for (index, byte) in buffer.iter_mut().enumerate() {
                *byte = (ordinal.wrapping_mul(131).wrapping_add(index as u64 * 17) & 255) as u8;
            }
            permit.extend(4096)?;
            writer.write_all(&buffer)?;
            digest.update(buffer);
            if ordinal % 1024 == 1023 {
                maximum_sampled_allocation = maximum_sampled_allocation.max(
                    reference_file::observe_reference_file_handle_with_limit(&writer, BYTES)?
                        .allocation_bytes,
                );
            }
        }
        writer.sync_all()?;
        let hash = hex::encode(digest.finalize());
        let before = reference_file::observe_reference_file_handle_with_limit(&writer, BYTES)?;
        maximum_sampled_allocation = maximum_sampled_allocation.max(before.allocation_bytes);
        let slack = arena.allocation_slack_bytes();
        let normalization = if normalize {
            Some(file_storage::normalize_allocation_at_eof(
                &writer, BYTES, BYTES, slack,
            )?)
        } else {
            None
        };
        let after_writer =
            reference_file::observe_reference_file_handle_with_limit(&writer, BYTES)?;
        let readonly = file_storage::duplicate_readonly(&writer)?;
        drop(writer);
        let after_duplicate =
            reference_file::observe_reference_file_handle_with_limit(&readonly, BYTES)?;
        ensure!(
            before.volume_serial_number == after_duplicate.volume_serial_number
                && before.file_id_128 == after_duplicate.file_id_128
                && before.final_path == after_duplicate.final_path
                && after_duplicate.file_bytes == BYTES,
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
            "normalize":normalize,"wire_bytes":BYTES,"planned_and_full_arena_sha256":hash,
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
        sampled.scratch_available_bytes >= 2 * (512 << 20) + (1 << 30),
        "probe must admit both arena ceilings plus1GiB free reserve"
    );
    fs::create_dir(&args.directory)?;
    let baseline = case(&args.directory.join("unmodified"), false)?;
    let normalized = case(&args.directory.join("normalized"), true)?;
    let reproduced = baseline.report["actual_original_arena_guard_refused"] == true;
    let success =
        reproduced && normalized.report["actual_closed_artifact_and_group_sealed"] == true;
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
