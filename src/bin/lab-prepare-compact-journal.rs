//! Compact candidate journal preparation. Never activates a source writer.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::GeneralFrozenPartition;
    use ntfs2refs::{
        general_reconstruct, ntfs_admission::ResourceProfile,
        refs_hybrid::delta::VerifiedDeltaArtifact,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        template: PathBuf,
        #[arg(long)]
        template_sha256: String,
        #[arg(long)]
        capture: PathBuf,
        #[arg(long)]
        capture_sha256: String,
        #[arg(long)]
        packed: PathBuf,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long, default_value_t = 536870912)]
        max_journal_bytes: u64,
    }
    fn input(path: &Path, pin: &str, limit: u64) -> Result<(File, Vec<u8>)> {
        let m = std::fs::symlink_metadata(path)?;
        ensure!(
            m.is_file() && m.file_attributes() & 0x400 == 0,
            "ordinary pinned input required"
        );
        let mut f = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x00200000)
            .open(path)?;
        ensure!(
            f.metadata()?.is_file() && f.metadata()?.len() <= limit,
            "input bound exceeded"
        );
        let mut b = Vec::new();
        (&mut f).take(limit + 1).read_to_end(&mut b)?;
        ensure!(
            b.len() as u64 <= limit && hex::encode(Sha256::digest(&b)) == pin,
            "input pin differs"
        );
        Ok((f, b))
    }
    fn save(path: &Path, value: &impl serde::Serialize) -> Result<()> {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        f.write_all(&serde_json::to_vec_pretty(value)?)?;
        f.sync_all()?;
        Ok(())
    }
    fn progress(file: &mut File, value: &impl serde::Serialize) -> std::io::Result<()> {
        let b = serde_json::to_vec(value).map_err(std::io::Error::other)?;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&b)?;
        file.set_len(b.len() as u64)?;
        file.flush()
    }
    let a = Args::parse();
    let (_template_file, b) = input(&a.template, &a.template_sha256, 131072)?;
    let mut request: general_reconstruct::Request = serde_json::from_slice(&b)?;
    request.experiment_id = a.experiment_id.clone();
    ensure!(
        request.schema_version == 2
            && request.source_resource_profile
                == Some(ResourceProfile::ExperimentalStreamingTreeV2),
        "streaming/v2 template required"
    );
    let (_expectation_file, b) = input(&a.expectation, &a.expectation_sha256, 16 * 1024 * 1024)?;
    let expectation: ntfs2refs::shadow_tree::ExpectedTree = serde_json::from_slice(&b)?;
    expectation.validate_with_resource_profile(ResourceProfile::ExperimentalStreamingTreeV2)?;
    let mut artifact = VerifiedDeltaArtifact::open(
        &a.capture,
        &a.capture_sha256,
        &a.packed,
        request.pair.source.identity.partition_bytes,
        768 * 1024 * 1024,
    )?;
    let envelope: serde_json::Value = serde_json::from_slice(artifact.report_bytes())?;
    ensure!(
        envelope["tree_sha256"].as_str() == Some(a.expectation_sha256.as_str()),
        "capture tree pin differs"
    );
    let captured: ntfs2refs::general_shadow::Request =
        serde_json::from_value(envelope["request"].clone())?;
    captured.validate_with_resource_profile(ResourceProfile::ExperimentalStreamingTreeV2)?;
    ensure!(
        captured.pair.source == request.pair.source,
        "capture/template source differs"
    );
    let metadata = &envelope["native"]["source_metadata_restoration"];
    ensure!(
        metadata["metadata_readback_verified"] == true
            && metadata["metadata_objects_verified"].as_u64()
                == Some(expectation.objects.len() as u64),
        "metadata-preserving receipt required; receipt grants no authority"
    );
    request.pair = captured.pair;
    request.expected_tree_sha256 = a.expectation_sha256.clone();
    request.comparison.source_sha256 = captured.source_sha256;
    request.comparison.retained_ranges.clear();
    request.comparison.max_ranges = 65536;
    request.comparison.max_change_bytes = artifact.layout().changed_bytes();
    request.max_journal_bytes = a.max_journal_bytes;
    request.validate()?;
    ensure!(!a.output_dir.exists(), "fresh output directory required");
    std::fs::create_dir(&a.output_dir)?;
    let artifact_pins = serde_json::to_value(artifact.pins())?;
    let artifact_identity = hex::encode(Sha256::digest(serde_json::to_vec(&artifact_pins)?));
    save(
        &a.output_dir.join("intent.json"),
        &serde_json::json!({"kind":"compact-journal-preparation-intent","artifact":artifact_pins,"artifact_identity_sha256":artifact_identity,"source_writes_authorized":false,"max_journal_bytes":a.max_journal_bytes}),
    )?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let mut original = GeneralFrozenPartition::reopen(request.pair.source.clone(), &mut events)?;
    let native_shadow = GeneralFrozenPartition::reopen(request.pair.shadow.clone(), &mut events)?;
    let before = original.state(&mut events)?;
    let mut status = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(a.output_dir.join("progress.json"))?;
    let mut image = artifact.image(&mut original)?;
    let mut hash = n2r_win32::sha256_native::Sha256::new()?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut done = 0u64;
    image.seek(SeekFrom::Start(0))?;
    let length = request.comparison.expected_length;
    while done < length {
        let count = (length - done).min(buffer.len() as u64) as usize;
        image.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count])?;
        done += count as u64;
        if done % (64 * 1024 * 1024) == 0 || done == length {
            progress(
                &mut status,
                &serde_json::json!({"phase":"hash-compact-target","completed_bytes":done,"total_bytes":length}),
            )?;
        }
    }
    request.comparison.shadow_sha256 = hex::encode(hash.finish()?);
    request.validate()?;
    save(&a.output_dir.join("request.json"), &request)?;
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(a.output_dir.join("journal.bin"))?;
    let mut progress_error = None;
    let prepared = general_reconstruct::prepare_compact_with_progress(
        &request,
        &mut source,
        &native_shadow,
        &mut image,
        &mut journal,
        &artifact_identity,
        &mut |p| {
            if let Err(e) = progress(&mut status, &p) {
                progress_error.get_or_insert(e);
            }
        },
    )?;
    drop(image);
    ensure!(
        original.state(&mut events)? == before,
        "compact base state changed"
    );
    artifact.revalidate()?;
    let descriptor = ntfs2refs::lab_reconstruct::inspect_journal(
        &mut journal,
        &prepared.journal.ticket,
        &prepared.observed_binding,
    )?;
    let patches: Vec<_> = descriptor
        .patches
        .iter()
        .map(|p| (p.offset, p.length))
        .collect();
    artifact.layout().require_exact_write_ranges(&patches)?;
    if let Some(e) = progress_error {
        return Err(e.into());
    }
    save(&a.output_dir.join("ticket.json"), &prepared.journal.ticket)?;
    save(
        &a.output_dir.join("prepare.json"),
        &serde_json::json!({"artifact":artifact_pins,"artifact_identity_sha256":artifact_identity,"preparation":prepared,"open_events":events,"source_writes_authorized":false,"conversion_qualified":false}),
    )?;
    println!("Compact journal durably prepared; source remains excluded and read-only.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("compact native preparation requires Windows");
    std::process::exit(1);
}
