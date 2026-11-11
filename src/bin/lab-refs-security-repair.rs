//! Hidden bounded native ReFS security-repair qualification. Never selects the
//! original Windows source, and is not the public conversion entry point.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{
        discovery::{self, Role},
        journal_file::GeneralJournalStorageBinding,
    };
    use std::{
        collections::{BTreeMap, BTreeSet},
        fs::OpenOptions,
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        volume: String,
        #[arg(long)]
        expected_disk_guid: String,
        #[arg(long)]
        descriptor: Option<PathBuf>,
        #[arg(long)]
        descriptor_sha256: Option<String>,
        #[arg(long)]
        corpus: Option<PathBuf>,
        #[arg(long)]
        corpus_sha256: Option<String>,
        #[arg(long)]
        creator_manifest: Option<PathBuf>,
        #[arg(long)]
        creator_manifest_sha256: Option<String>,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Corpus {
        schema_version: u32,
        kind: String,
        source_extraction_sha256: String,
        expected_pages_sha256: String,
        source_assessment_sha256: String,
        file_payload_hex: String,
        file_payload_sha256: String,
        descriptors: Vec<CorpusRow>,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct CorpusRow {
        id: String,
        file_name: String,
        directory: bool,
        original_sha256: String,
        original_hex: String,
        placeholder_sha256: String,
        placeholder_hex: String,
        descriptor_hash32: u32,
        ace_offset: usize,
        placeholder_mask: u32,
        source_context: serde_json::Value,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Creator {
        schema_version: u32,
        kind: String,
        corpus_sha256: String,
        target_disk_guid: String,
        target_volume_guid: String,
        fresh_root_component: String,
        files: Vec<ntfs2refs::refs_security_oracle::OracleCreatorFile>,
    }
    struct HeldInput {
        file: std::fs::File,
        snapshot: n2r_win32::reference_file::ReferenceFileSnapshot,
        modified: std::time::SystemTime,
        sha256: String,
    }
    impl HeldInput {
        fn open(path: &PathBuf, sha: &str, volume: &str) -> anyhow::Result<(Self, Vec<u8>)> {
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(path)?;
            n2r_win32::file_storage::require_readonly_access(&file)?;
            let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &file,
                2 << 20,
            )?;
            let prefix = format!("{volume}\\");
            ensure!(
                snapshot.number_of_links == 1
                    && snapshot.file_bytes > 0
                    && snapshot
                        .final_path
                        .get(..prefix.len())
                        .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)),
                "corpus and creator manifest must be bounded ordinary current-C files"
            );
            let modified = file.metadata()?.modified()?;
            let mut bytes = Vec::with_capacity(snapshot.file_bytes as usize);
            (&mut file)
                .take(snapshot.file_bytes)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == snapshot.file_bytes
                    && ntfs2refs::ntfs_security::hash(&bytes) == sha,
                "independent corpus/creator input SHA differs"
            );
            let held = Self {
                file,
                snapshot,
                modified,
                sha256: sha.into(),
            };
            held.revalidate()?;
            Ok((held, bytes))
        }
        fn revalidate(&self) -> anyhow::Result<()> {
            ensure!(
                n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file,
                    2 << 20
                )? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held corpus/creator input identity changed"
            );
            let mut file = self.file.try_clone()?;
            file.seek(SeekFrom::Start(0))?;
            ensure!(
                hex::encode(n2r_win32::sha256_native::hash_range(
                    &mut file,
                    0,
                    self.snapshot.file_bytes
                )?) == self.sha256,
                "held corpus/creator input bytes changed"
            );
            Ok(())
        }
    }
    let args = Args::parse();
    ensure!(
        args.descriptor.is_some() != args.corpus.is_some(),
        "choose exactly one original descriptor or explicit corpus"
    );
    let target = discovery::discover(&args.volume, Role::Shadow)?;
    ensure!(
        target.label == "N2R_TRUST_ORACLE"
            && target.filesystem == "ReFS"
            && target.binding.disk_number != 0
            && !target.disk_is_windows_disk,
        "only the explicitly created disposable ReFS oracle may be selected"
    );
    let current = discovery::discover(
        "C:\\",
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        current.disk_is_windows_disk
            && current.binding.disk_number == 1
            && current.filesystem == "ReFS",
        "actual independent control1 C: journal required"
    );
    let journal = GeneralJournalStorageBinding {
        disk: current.binding,
        externally_enrolled_disk_unique_id: "60022480D091C4251B5FFD619706C2B5".into(),
        allow_additional_partitions: true,
    };
    let mut held_inputs = Vec::new();
    let mut creator_root = None;
    let mut creator_files = Vec::new();
    let mut corpus_context_count = 0usize;
    let replacements = if let Some(path) = &args.corpus {
        ensure!(
            args.descriptor_sha256.is_none(),
            "single-descriptor SHA cannot accompany corpus mode"
        );
        let sha = args
            .corpus_sha256
            .as_deref()
            .context("independent corpus SHA required")?;
        let (held, bytes) = HeldInput::open(path, sha, &journal.disk.volume_path()?)?;
        let corpus: Corpus = serde_json::from_slice(&bytes)?;
        corpus_context_count = corpus.descriptors.len();
        held_inputs.push(held);
        ensure!(
            corpus.schema_version == 1
                && corpus.kind == "native-trust-full-sd-corpus-v1"
                && (1..=512).contains(&corpus.descriptors.len()),
            "bounded complete corpus schema required"
        );
        for pin in [
            &corpus.source_extraction_sha256,
            &corpus.expected_pages_sha256,
            &corpus.source_assessment_sha256,
        ] {
            ensure!(
                pin.len() == 64
                    && pin
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "source corpus SHA syntax differs"
            );
        }
        let payload = hex::decode(&corpus.file_payload_hex)?;
        ensure!(
            payload.len() == 47
                && ntfs2refs::ntfs_security::hash(&payload) == corpus.file_payload_sha256,
            "corpus file sentinel differs"
        );
        let mut stored_cases = 0usize;
        for row in &corpus.descriptors {
            if row
                .source_context
                .get("stored_object_references")
                .and_then(|v| v.as_u64())
                .context("stored descriptor context count required")?
                > 0
            {
                stored_cases += 1;
            }
        }
        ensure!(
            stored_cases > 0,
            "corpus has no physical stored descriptor cases"
        );
        let (held, bytes) = HeldInput::open(
            args.creator_manifest
                .as_ref()
                .context("pinned creator manifest required")?,
            args.creator_manifest_sha256
                .as_deref()
                .context("creator manifest SHA required")?,
            &journal.disk.volume_path()?,
        )?;
        let creator: Creator = serde_json::from_slice(&bytes)?;
        held_inputs.push(held);
        ensure!(
            creator.schema_version == 1
                && creator.kind == "native-trust-corpus-created-v1"
                && creator.corpus_sha256 == sha
                && n2r_win32::layout::guid_bytes(&creator.target_disk_guid)?
                    == n2r_win32::layout::guid_bytes(&args.expected_disk_guid)?
                && n2r_win32::layout::guid_bytes(&creator.target_volume_guid)?
                    == n2r_win32::layout::guid_bytes(&target.binding.volume_guid)?
                && creator.files.len() == stored_cases,
            "creator scope or complete corpus coverage differs"
        );
        let mut created = BTreeMap::new();
        for file in creator.files {
            ensure!(
                created.insert(file.id.clone(), file).is_none(),
                "duplicate creator case ID"
            );
        }
        let mut originals = BTreeSet::new();
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut replacements = Vec::new();
        for row in corpus.descriptors {
            ensure!(
                row.id.len() <= 80
                    && row
                        .id
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    && ids.insert(row.id.clone())
                    && names.insert(row.file_name.clone()),
                "unique pinned corpus IDs/names required"
            );
            let original = hex::decode(&row.original_hex)?;
            ensure!(
                (20..=65_536).contains(&original.len())
                    && ntfs2refs::ntfs_security::hash(&original) == row.original_sha256
                    && originals.insert(row.original_sha256.clone()),
                "corpus originals are not distinct exact full descriptors"
            );
            let replacement = ntfs2refs::refs_security_descriptor::prepare_trust_label_placeholder(
                &original, 65_536,
            )?
            .context("corpus original has no eligible process trust ACE")?;
            ensure!(
                replacement.placeholder == hex::decode(&row.placeholder_hex)?
                    && ntfs2refs::ntfs_security::hash(&replacement.placeholder)
                        == row.placeholder_sha256
                    && replacement.descriptor_hash == row.descriptor_hash32
                    && replacement.ace_offset == row.ace_offset
                    && replacement.placeholder_mask == row.placeholder_mask,
                "corpus carrier differs from actual SDK preparation"
            );
            if row
                .source_context
                .get("stored_object_references")
                .and_then(|v| v.as_u64())
                .context("stored descriptor context count required")?
                == 0
            {
                ensure!(
                    !created.contains_key(&row.id),
                    "API-only context cannot be a physical stored case"
                );
                continue;
            }
            let file = created
                .remove(&row.id)
                .context("corpus case has no creator binding")?;
            let flat_components = vec![creator.fresh_root_component.clone(), row.file_name];
            let mut source_components = vec![creator.fresh_root_component.clone()];
            for component in row
                .source_context
                .get("first_source")
                .and_then(|v| v.get("path"))
                .and_then(|v| v.as_array())
                .context("corpus source path context required")?
            {
                source_components.push(
                    component
                        .as_str()
                        .context("corpus source component is not text")?
                        .to_owned(),
                );
            }
            ensure!(
                file.original_sha256 == row.original_sha256
                    && file.directory == row.directory
                    && (file.components == flat_components || file.components == source_components),
                "creator row does not match exact corpus case"
            );
            let _source_context = row.source_context; // Retained in the held, independently hashed input.
            creator_files.push(file);
            replacements.push(replacement);
        }
        ensure!(created.is_empty(), "extra creator rows outside corpus");
        creator_root = Some(creator.fresh_root_component);
        replacements
    } else {
        ensure!(
            args.corpus_sha256.is_none()
                && args.creator_manifest.is_none()
                && args.creator_manifest_sha256.is_none(),
            "corpus/creator options require corpus mode"
        );
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(args.descriptor.as_ref().context("descriptor required")?)?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file()
                && metadata.file_attributes() & 0x400 == 0
                && (20..=65_536).contains(&metadata.len()),
            "bounded ordinary original descriptor required"
        );
        let mut descriptor = Vec::with_capacity(metadata.len() as usize);
        file.read_to_end(&mut descriptor)?;
        ensure!(
            descriptor.len() as u64 == metadata.len()
                && ntfs2refs::ntfs_security::hash(&descriptor)
                    == args
                        .descriptor_sha256
                        .as_deref()
                        .context("descriptor SHA required")?,
            "descriptor SHA differs"
        );
        vec![
            ntfs2refs::refs_security_descriptor::prepare_trust_label_placeholder(
                &descriptor,
                65_536,
            )?
            .context("original descriptor has no supported process-trust label")?,
        ]
    };
    for held in &held_inputs {
        held.revalidate()?;
    }
    let receipt = if let Some(root) = creator_root.as_deref() {
        let input_pins = ntfs2refs::refs_security_oracle::OracleCorpusInputPins {
            corpus_sha256: held_inputs[0].sha256.clone(),
            creator_manifest_sha256: held_inputs[1].sha256.clone(),
            corpus_snapshot: held_inputs[0].snapshot.clone(),
            creator_manifest_snapshot: held_inputs[1].snapshot.clone(),
            corpus_descriptor_contexts: corpus_context_count,
            physical_stored_descriptors: replacements.len(),
        };
        ntfs2refs::refs_security_oracle::qualify_owned_shadow_corpus(
            target.binding,
            &args.expected_disk_guid,
            &journal,
            &args.output,
            &replacements,
            root,
            &creator_files,
            &input_pins,
        )?
    } else {
        ntfs2refs::refs_security_oracle::qualify_owned_shadow(
            target.binding,
            &args.expected_disk_guid,
            &journal,
            &args.output,
            &replacements,
        )?
    };
    for held in &held_inputs {
        held.revalidate()?;
    }
    let encoded = serde_json::to_vec_pretty(&receipt)?;
    ensure!(
        encoded.len() <= 1024 * 1024,
        "oracle receipt exceeds metadata bound"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(args.output.join("cli-result.json"))?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "kind": receipt.kind,
            "changed_clusters": receipt.changed_clusters,
            "native_bytes_written": receipt.native_bytes_written,
            "journal_handoff_closed": receipt.journal_handoff_closed,
            "target_brought_online": receipt.target_brought_online,
            "native_security_preservation_qualified": receipt.native_security_preservation_qualified,
            "receipt": args.output.join("cli-result.json"),
        })
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This native ReFS laboratory helper requires Windows.");
    std::process::exit(1);
}
