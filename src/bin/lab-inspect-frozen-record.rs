//! Read-only bounded MFT diagnosis of an already excluded enrolled source.
//! No isolator, writer, certificate, native content scan or journal API.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{GeneralFrozenPartition, general_layout::GeneralDiskBinding};
    use ntfs2refs::{
        ntfs_admission::ResourceProfile, ntfs_inspect, verification_policy::VerificationPolicy,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeSet,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long, required = true, num_args = 1..=16)]
        record: Vec<u64>,
        #[arg(long)]
        output: PathBuf,
    }
    fn ordinary(path: &Path, existing: bool) -> Result<()> {
        let text = path
            .to_str()
            .context("Unicode lab metadata path required")?;
        ensure!(
            text.starts_with("C:\\ntfs2refs\\")
                && !text[3..].contains(':')
                && !text.contains(['/', '"'])
                && !text.contains("..")
                && !text.chars().any(char::is_control)
                && path.extension().is_some_and(|s| s == "json"),
            "ordinary owned C lab JSON path required"
        );
        for (index, parent) in path.ancestors().enumerate() {
            if index == 0 && !existing {
                ensure!(!parent.exists(), "fresh diagnostic output required");
                continue;
            }
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.file_attributes() & 0x400 == 0
                    && if index == 0 { m.is_file() } else { m.is_dir() },
                "ordinary metadata file and ancestry required"
            );
        }
        Ok(())
    }
    struct Hash(Sha256);
    impl Write for Hash {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    // Diagnostic convenience only, with the same strict single-name ancestry
    // rules as the ordinary raw source path resolver. Ambiguity remains None.
    fn path(
        raw: &ntfs_inspect::NtfsInspection,
        file: &ntfs_inspect::FileInventory,
    ) -> Option<Vec<String>> {
        let mut cursor = file;
        let mut parts = Vec::new();
        let mut seen = BTreeSet::new();
        loop {
            if !seen.insert((cursor.record_number, cursor.sequence_number)) || parts.len() > 16 {
                return None;
            }
            if cursor.record_number == 5 {
                parts.reverse();
                return Some(parts);
            }
            if cursor.names.len() != 1 {
                return None;
            }
            let name = &cursor.names[0];
            if !matches!(name.namespace, 0 | 1 | 3) {
                return None;
            }
            parts.push(String::from_utf16(&name.name_utf16).ok()?);
            let mut parents = raw.files.iter().filter(|p| {
                p.record_number == name.parent_record_number
                    && p.sequence_number == name.parent_sequence_number
            });
            cursor = parents.next()?;
            if parents.next().is_some() || !cursor.is_directory {
                return None;
            }
        }
    }
    #[derive(Serialize)]
    struct Selected<'a> {
        raw_file: &'a ntfs_inspect::FileInventory,
        resolved_single_name_path: Option<Vec<String>>,
        standard_information_attributes_hex: Option<String>,
    }
    struct Bounded<W> {
        inner: W,
        bytes: usize,
    }
    impl<W: Write> Write for Bounded<W> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let next = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= 8 * 1024 * 1024)
                .ok_or_else(|| std::io::Error::other("selected diagnostic exceeds 8MiB"))?;
            self.inner.write_all(bytes)?;
            self.bytes = next;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.inner.flush()
        }
    }
    let args = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME")?.eq_ignore_ascii_case("N2R-WIN11"),
        "enrolled lab guest required"
    );
    let records: BTreeSet<_> = args.record.iter().copied().collect();
    ensure!(
        !records.is_empty() && records.len() <= 16 && records.len() == args.record.len(),
        "one to sixteen unique selected MFT records required"
    );
    ensure!(
        args.binding_sha256.len() == 64
            && args
                .binding_sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "canonical binding SHA required"
    );
    ordinary(&args.binding, true)?;
    ordinary(&args.output, false)?;
    let mut binding_file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.binding)?;
    let binding_meta = binding_file.metadata()?;
    ensure!(
        binding_meta.len() > 0 && binding_meta.len() <= 16384,
        "bounded binding JSON required"
    );
    let mut binding_bytes = Vec::new();
    (&mut binding_file)
        .take(16385)
        .read_to_end(&mut binding_bytes)?;
    ensure!(
        binding_bytes.len() as u64 == binding_meta.len()
            && hex::encode(Sha256::digest(&binding_bytes)) == args.binding_sha256,
        "held binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&binding_bytes)?;
    binding.validate()?;
    ensure!(
        binding.disk_number == 1
            && binding.identity.partition_number == 2
            && binding
                .identity
                .disk_guid
                .eq_ignore_ascii_case("1b191872-c372-41ee-a416-e18863996f54")
            && binding
                .identity
                .partition_guid
                .eq_ignore_ascii_case("f06075a8-67a2-46b9-8fac-4af4da809617")
            && binding.identity.partition_offset == 16 * 1024 * 1024
            && binding.identity.partition_bytes == 52 * 1024 * 1024 * 1024,
        "exact enrolled mixed source required"
    );
    // Reserve the sole ordinary output before opening the already protected
    // source. An error leaves diagnostic evidence, never a success prefix.
    let output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x0020_0000)
        .open(&args.output)?;
    let mut events = Vec::new();
    let mut source = GeneralFrozenPartition::reopen(binding.clone(), &mut events)?;
    let before = source.state(&mut events)?;
    ensure!(
        before.disk_attributes == 3,
        "already excluded read-only source required"
    );
    let resources = ResourceProfile::ExperimentalObjectEnvelopeV3(None);
    let policy = VerificationPolicy::ExtentIdentityV1;
    let raw = ntfs_inspect::inspect_with_limits_and_policy(
        &mut source,
        binding.identity.partition_bytes,
        ntfs_inspect::limits_for_resource_profile(resources),
        policy,
    )?;
    ensure!(
        raw.files.len() <= n2r_win32::tree_resources::RAW_IDENTITIES,
        "complete raw identity domain exceeds2048"
    );
    let mut raw_hash = Hash(Sha256::new());
    serde_json::to_writer(&mut raw_hash, &raw)?;
    let inventory_sha256 = hex::encode(raw_hash.0.finalize());
    let mut selected = Vec::new();
    for number in &records {
        let mut matches = raw.files.iter().filter(|f| f.record_number == *number);
        let file = matches.next().context("requested raw record is absent")?;
        ensure!(
            matches.next().is_none(),
            "requested raw record is ambiguous"
        );
        selected.push(Selected {
            raw_file: file,
            resolved_single_name_path: path(&raw, file),
            standard_information_attributes_hex: file
                .standard_information
                .as_ref()
                .map(|s| format!("0x{:08x}", s.file_attributes)),
        });
    }
    source.revalidate_route(&mut events)?;
    let after = source.state(&mut events)?;
    ensure!(
        before == after && after.disk_attributes == 3 && source.binding() == &binding,
        "diagnostic source identity or persistent read-only state changed"
    );
    ensure!(
        binding_file.metadata()?.len() == binding_meta.len()
            && binding_file.metadata()?.modified()? == binding_meta.modified()?,
        "held binding metadata changed"
    );
    let security = raw.security_reconciliation.as_ref().map(|s| serde_json::json!({
        "status":s.status,"metadata_bytes_read":s.metadata_bytes_read,"central_descriptors":s.central_descriptors,
        "legacy_descriptors":s.legacy_descriptors,"sii_entries":s.sii_entries,"sdh_entries":s.sdh_entries,
        "index_blocks":s.index_blocks,"bound_files":s.bound_files,"evidence_sha256":s.evidence_sha256,"detail":s.detail}));
    let report = serde_json::json!({"schema_version":1,"kind":"lab-read-only-frozen-record-diagnostic",
        "binding":binding,"binding_path":args.binding,"binding_sha256":args.binding_sha256,
        "selected_records":selected,"geometry":raw.geometry,"volume_version":raw.volume_version,
        "volume_flags":raw.volume_flags,"dirty":raw.dirty,"records_scanned":raw.records_scanned,
        "raw_identities":raw.files.len(),"raw_identity_limit":n2r_win32::tree_resources::RAW_IDENTITIES,
        "inventory_complete":raw.inventory_complete,"inventory_sha256":inventory_sha256,
        "inventory_memory_bytes":raw.inventory_memory_bytes,"inventory_memory_limit_bytes":raw.inventory_memory_limit_bytes,
        "allocation_reconciliation":raw.allocation_reconciliation,"namespace_reconciliation":raw.namespace_reconciliation,
        "security_reconciliation_summary":security,"inspection_blockers":raw.blockers,
        "requested_inspection_policy":policy,"actual_stream_hash_bytes":raw.stream_hash_bytes,
        "full_payload_scan_requested":false,"full_image_hashed":false,"native_content_observation_requested":false,
        "native_bytes_read":source.native_bytes_read(),"before":before,"after":after,"events":events,
        "source_payload_writes":0,"protection_changed":false,"source_admitted":false,
        "certificate_issued":false,"journal_opened":false,"conversion_authorized":false,"replay_authorized":false});
    let mut bounded = Bounded {
        inner: output,
        bytes: 0,
    };
    serde_json::to_writer_pretty(&mut bounded, &report)?;
    bounded.flush()?;
    bounded.inner.sync_all()?;
    println!(
        "{}",
        serde_json::json!({"success":true,"output":args.output,"bytes":bounded.bytes,
        "selected_records":records,"inventory_sha256":inventory_sha256,"source_admitted":false,"source_payload_writes":0})
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("frozen native record inspection requires Windows")
}
