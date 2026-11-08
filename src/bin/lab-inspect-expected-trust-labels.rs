//! Read-only trust-ACE inventory from CLOSED authenticated expected pages.
//! Opens ordinary metadata files only; no source volume/device or setters.
#[cfg(windows)]
mod windows {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        metadata_pages::Reader,
        reference_file::ReferenceFileSnapshot,
        security_descriptor::{self, AclLayout},
        tree_resources::SourceResourceAdmission,
    };
    use ntfs2refs::{
        ntfs_security, refs_security_descriptor,
        shadow_tree::{ExpectedTreePageHeader, Object},
    };
    use serde::{Deserialize, Serialize};
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeMap,
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf},
        time::SystemTime,
    };
    const PURPOSE: [u8; 8] = *b"N2REXP01";
    const MAX_SD: u64 = 65_536;
    const METADATA_CAP: u64 = 1 << 20;

    #[derive(Parser)]
    #[command(about = "Inventory process-trust ACEs in closed expected.pages; metadata files only")]
    struct Args {
        #[arg(long)]
        expected_pages: PathBuf,
        #[arg(long)]
        expected_sha256: String,
        #[arg(long)]
        source_assessment: PathBuf,
        #[arg(long)]
        source_assessment_sha256: String,
        /// Independent working/control filesystem GUID, never source0's volume.
        #[arg(long)]
        metadata_volume_guid: String,
        #[arg(long, default_value_t = 536_870_912)]
        max_file_bytes: u64,
        #[arg(long, default_value_t = 134_217_728)]
        max_row_bytes: u64,
        #[arg(long, default_value_t = 16_384)]
        max_unique_descriptors: usize,
        #[arg(long, default_value_t = 8_388_608)]
        max_output_bytes: usize,
        #[arg(long, default_value_t = 1_073_741_824)]
        ram_bytes: u64,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(Deserialize)]
    struct Assessment {
        binding: n2r_win32::general_layout::GeneralDiskBinding,
        resource_admission: SourceResourceAdmission,
    }
    struct Held {
        file: File,
        snapshot: ReferenceFileSnapshot,
        modified: SystemTime,
        sha256: [u8; 32],
    }
    fn digest(value: &str) -> Result<[u8; 32]> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "canonical lowercase SHA-256 required"
        );
        hex::decode(value)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("SHA width differs"))
    }
    fn ordinary_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::CurDir | Component::ParentDir)),
            "absolute ordinary metadata path required"
        );
        for parent in path.parent().context("metadata parent absent")?.ancestors() {
            if parent.as_os_str().is_empty() {
                continue;
            }
            let m = fs::symlink_metadata(parent)?;
            ensure!(
                m.is_dir() && m.file_attributes() & 0x400 == 0,
                "metadata ancestry is not ordinary"
            );
        }
        Ok(())
    }
    fn on_volume(path: &str, guid: &str) -> Result<bool> {
        n2r_win32::layout::guid_bytes(guid)?;
        let prefix = format!("\\\\?\\Volume{{{}}}\\", guid.trim_matches(['{', '}']));
        Ok(path
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)))
    }
    impl Held {
        fn open(path: &Path, hash: &str, maximum: u64, volume: &str) -> Result<Self> {
            ordinary_path(path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(path)?;
            n2r_win32::file_storage::require_readonly_access(&file)?;
            let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &file, maximum,
            )?;
            ensure!(
                snapshot.number_of_links == 1
                    && snapshot.file_bytes > 0
                    && on_volume(&snapshot.final_path, volume)?,
                "metadata must be on the explicit independent working filesystem"
            );
            let modified = file.metadata()?.modified()?;
            let sha256 = digest(hash)?;
            ensure!(
                n2r_win32::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == sha256,
                "closed metadata does not match its independent full SHA-256"
            );
            let held = Self {
                file,
                snapshot,
                modified,
                sha256,
            };
            held.revalidate(maximum)?;
            Ok(held)
        }
        fn revalidate(&self, maximum: u64) -> Result<()> {
            ensure!(
                n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file, maximum
                )? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held metadata identity changed"
            );
            let mut file = self.file.try_clone()?;
            ensure!(
                n2r_win32::sha256_native::hash_range(&mut file, 0, self.snapshot.file_bytes)?
                    == self.sha256,
                "held metadata bytes changed"
            );
            Ok(())
        }
    }
    fn decode_chunk(payload: &[u8], maximum: usize) -> Result<Vec<u8>> {
        // Same canonical chunk format as shadow_tree/pages.rs; this diagnostic
        // cannot call its private decoder or infer semantic/write authority.
        let text: &str = serde_json::from_slice(payload)?;
        let input = text.as_bytes();
        ensure!(
            input.len().is_multiple_of(4),
            "expected chunk base64 width differs"
        );
        let padding = input.iter().rev().take_while(|b| **b == b'=').count();
        ensure!(padding <= 2, "expected chunk padding differs");
        let length = input
            .len()
            .checked_div(4)
            .and_then(|n| n.checked_mul(3))
            .and_then(|n| n.checked_sub(padding))
            .context("expected chunk length overflow")?;
        ensure!(
            length > 0 && length <= maximum,
            "expected chunk exceeds admitted size"
        );
        let digit = |b: u8| -> Result<u8> {
            Ok(match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => anyhow::bail!("noncanonical expected base64 alphabet"),
            })
        };
        let mut result = Vec::new();
        result.try_reserve_exact(length)?;
        for (index, c) in input.chunks_exact(4).enumerate() {
            let last = index + 1 == input.len() / 4;
            let a = digit(c[0])?;
            let b = digit(c[1])?;
            result.push((a << 2) | (b >> 4));
            if c[2] == b'=' {
                ensure!(
                    last && c[3] == b'=' && b & 15 == 0,
                    "noncanonical expected padding bits"
                );
            } else {
                let d = digit(c[2])?;
                result.push((b << 4) | (d >> 2));
                if c[3] == b'=' {
                    ensure!(last && d & 3 == 0, "noncanonical expected padding bits");
                } else {
                    result.push((d << 6) | digit(c[3])?);
                }
            }
        }
        ensure!(
            result.len() == length,
            "expected decoded chunk width differs"
        );
        Ok(result)
    }
    #[derive(Serialize)]
    struct SourceObject {
        record_number: u64,
        sequence_number: u16,
        path: Vec<String>,
        directory: bool,
        stored_security_sha256: String,
        api_security_sha256: Option<String>,
        api_security_hex_if_different: Option<String>,
    }
    #[derive(Serialize)]
    struct Ace {
        acl: &'static str,
        ordinal: u16,
        offset: usize,
        length: usize,
        flags: u8,
        mask: u32,
        sid: String,
        raw_hex: String,
        sha256: String,
        descriptor_prefix_ntfs_hash: u32,
        diagnostic_carrier_type: u8,
        diagnostic_solved_audit_mask: u32,
    }
    #[derive(Serialize)]
    struct Descriptor {
        sha256: String,
        full_sd_hex: String,
        stored_object_references: u64,
        api_object_references: u64,
        first_source: SourceObject,
        control: Option<u16>,
        rm_control: Option<u8>,
        sacl_revision: Option<u8>,
        dacl_revision: Option<u8>,
        sacl_presence: Option<security_descriptor::Presence>,
        dacl_presence: Option<security_descriptor::Presence>,
        layout_error: Option<String>,
        aces: Vec<Ace>,
        placeholder_accepted: bool,
        placeholder_error: Option<String>,
        placeholder_mask: Option<u32>,
    }
    #[derive(Serialize)]
    struct Variant {
        raw_hex: String,
        sha256: String,
        acl: &'static str,
        length: usize,
        flags: u8,
        mask: u32,
        sid: String,
        stored_occurrences: u64,
        api_occurrences: u64,
        first_record_number: u64,
        first_path: Vec<String>,
    }
    struct CorpusBudget {
        used: usize,
        maximum: usize,
    }
    impl CorpusBudget {
        fn charge(&mut self, value: &impl Serialize) -> Result<()> {
            let mut count = Count {
                bytes: 0,
                maximum: self.maximum,
            };
            serde_json::to_writer(&mut count, value)?;
            self.used = self
                .used
                .checked_add(count.bytes)
                .filter(|n| *n <= self.maximum)
                .context("retained trust corpus exceeds explicit encoded-byte budget")?;
            Ok(())
        }
    }
    fn sid(entry: &[u8]) -> Result<String> {
        ensure!(
            entry.len() >= 16 && entry[8] == 1 && entry[9] <= 15,
            "trust ACE SID header differs"
        );
        let count = usize::from(entry[9]);
        ensure!(
            16 + 4 * count == entry.len(),
            "trust ACE SID length differs"
        );
        let authority = entry[10..16]
            .iter()
            .fold(0u64, |n, b| (n << 8) | u64::from(*b));
        let mut text = format!("S-1-{authority}");
        for value in entry[16..].chunks_exact(4) {
            text.push_str(&format!("-{}", u32::from_le_bytes(value.try_into()?)));
        }
        Ok(text)
    }
    fn trust_aces(sd: &[u8], acl: AclLayout, name: &'static str) -> Result<Vec<Ace>> {
        let Some(start) = acl.offset else {
            return Ok(Vec::new());
        };
        let end = start
            .checked_add(acl.length)
            .context("ACL bound overflow")?;
        let mut at = start + 8;
        let mut entries = Vec::new();
        for ordinal in 0..acl.ace_count {
            let head = sd.get(at..at + 8).context("short expected ACE")?;
            let length = usize::from(u16::from_le_bytes(head[2..4].try_into()?));
            ensure!(
                length >= 16 && at.checked_add(length).is_some_and(|n| n <= end),
                "expected ACE exceeds ACL"
            );
            if head[0] == 0x14 {
                let raw = sd
                    .get(at..at + length)
                    .context("trust ACE exceeds descriptor")?;
                let prefix = ntfs_security::ntfs_hash(&sd[..at])?;
                let original_header = u32::from_le_bytes(raw[..4].try_into()?);
                let audit_header = (original_header & !0xff) | 0x0d;
                let mask = u32::from_le_bytes(raw[4..8].try_into()?);
                let original_state = prefix.rotate_left(3).wrapping_add(original_header);
                let audit_state = prefix.rotate_left(3).wrapping_add(audit_header);
                let solved = original_state
                    .rotate_left(3)
                    .wrapping_add(mask)
                    .wrapping_sub(audit_state.rotate_left(3));
                entries.push(Ace {
                    acl: name,
                    ordinal,
                    offset: at,
                    length,
                    flags: raw[1],
                    mask,
                    sid: sid(raw)?,
                    raw_hex: hex::encode(raw),
                    sha256: hex::encode(Sha256::digest(raw)),
                    descriptor_prefix_ntfs_hash: prefix,
                    diagnostic_carrier_type: 0x0d,
                    diagnostic_solved_audit_mask: solved,
                });
            }
            at += length;
        }
        Ok(entries)
    }
    fn observe_sd(
        object: &Object,
        sd: &[u8],
        api: bool,
        corpus: &mut BTreeMap<String, Descriptor>,
        variants: &mut BTreeMap<String, Variant>,
        maximum: usize,
        retained: &mut CorpusBudget,
    ) -> Result<()> {
        ensure!(
            sd.len() as u64 <= MAX_SD,
            "descriptor exceeds the explicit 64 KiB diagnostic cap"
        );
        let hash = hex::encode(Sha256::digest(sd));
        if let Some(entry) = corpus.get_mut(&hash) {
            if api {
                entry.api_object_references += 1;
            } else {
                entry.stored_object_references += 1;
            }
            for ace in &entry.aces {
                let key = format!("{}:{}", ace.acl, ace.sha256);
                let variant = variants
                    .get_mut(&key)
                    .context("missing inventoried ACE variant")?;
                if api {
                    variant.api_occurrences += 1;
                } else {
                    variant.stored_occurrences += 1;
                }
            }
            return Ok(());
        }
        let layout = security_descriptor::validate_with_limit(sd, MAX_SD);
        let mut aces = Vec::new();
        if let Ok(layout) = &layout {
            aces.extend(trust_aces(sd, layout.sacl, "sacl")?);
            aces.extend(trust_aces(sd, layout.dacl, "dacl")?);
            if aces.is_empty() {
                return Ok(());
            }
        }
        ensure!(
            corpus.len() < maximum,
            "trust descriptor corpus exceeds explicit descriptor count cap"
        );
        for ace in &aces {
            let key = format!("{}:{}", ace.acl, ace.sha256);
            if !variants.contains_key(&key) {
                let value = Variant {
                    raw_hex: ace.raw_hex.clone(),
                    sha256: ace.sha256.clone(),
                    acl: ace.acl,
                    length: ace.length,
                    flags: ace.flags,
                    mask: ace.mask,
                    sid: ace.sid.clone(),
                    stored_occurrences: 0,
                    api_occurrences: 0,
                    first_record_number: object.record_number,
                    first_path: object.path.clone(),
                };
                retained.charge(&value)?;
                variants.insert(key.clone(), value);
            }
            let value = variants.get_mut(&key).context("new ACE variant absent")?;
            if api {
                value.api_occurrences += 1;
            } else {
                value.stored_occurrences += 1;
            }
        }
        let prepared = refs_security_descriptor::prepare_trust_label_placeholder(sd, MAX_SD);
        let (accepted, mask, error) = match prepared {
            Ok(Some(value)) => (true, Some(value.placeholder_mask), None),
            Ok(None) => (
                false,
                None,
                Some("no measured process-trust ACE selected".into()),
            ),
            Err(error) => (false, None, Some(error.to_string())),
        };
        let parsed = layout.as_ref().ok();
        let api_different = object
            .api_security
            .as_ref()
            .filter(|api| *api != &object.security);
        let entry = Descriptor {
            sha256: hash.clone(),
            full_sd_hex: hex::encode(sd),
            stored_object_references: u64::from(!api),
            api_object_references: u64::from(api),
            first_source: SourceObject {
                record_number: object.record_number,
                sequence_number: object.sequence_number,
                path: object.path.clone(),
                directory: object.directory,
                stored_security_sha256: hex::encode(Sha256::digest(&object.security)),
                api_security_sha256: api_different.map(|bytes| hex::encode(Sha256::digest(bytes))),
                api_security_hex_if_different: api_different.map(hex::encode),
            },
            control: parsed.map(|p| p.control),
            rm_control: parsed.and_then(|p| p.rm_control),
            sacl_revision: parsed.and_then(|p| p.sacl.revision),
            dacl_revision: parsed.and_then(|p| p.dacl.revision),
            sacl_presence: parsed.map(|p| p.sacl.presence),
            dacl_presence: parsed.map(|p| p.dacl.presence),
            layout_error: layout.err().map(|e| e.to_string()),
            aces,
            placeholder_accepted: accepted,
            placeholder_error: error,
            placeholder_mask: mask,
        };
        retained.charge(&entry)?;
        corpus.insert(hash, entry);
        Ok(())
    }
    struct Count {
        bytes: usize,
        maximum: usize,
    }
    impl Write for Count {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes = self
                .bytes
                .checked_add(bytes.len())
                .filter(|n| *n <= self.maximum)
                .ok_or_else(|| {
                    std::io::Error::other("trust corpus exceeds explicit output byte cap")
                })?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    pub fn run() -> Result<()> {
        let args = Args::parse();
        ensure!(
            (1..=16_384).contains(&args.max_unique_descriptors)
                && (4096..=16 * 1024 * 1024).contains(&args.max_output_bytes)
                && args.max_file_bytes > 192
                && args.max_row_bytes > 0,
            "explicit extractor limits differ"
        );
        n2r_win32::layout::guid_bytes(&args.metadata_volume_guid)?;
        let mut assessment = Held::open(
            &args.source_assessment,
            &args.source_assessment_sha256,
            METADATA_CAP,
            &args.metadata_volume_guid,
        )?;
        assessment.file.seek(SeekFrom::Start(0))?;
        let data: Assessment =
            serde_json::from_reader((&mut assessment.file).take(assessment.snapshot.file_bytes))?;
        let admission = data.resource_admission;
        admission.validate()?;
        ensure!(
            data.binding.disk_number == 0
                && data.binding.layout_profile
                    == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
                && n2r_win32::layout::guid_bytes(&data.binding.volume_guid)?
                    != n2r_win32::layout::guid_bytes(&args.metadata_volume_guid)?,
            "extractor metadata filesystem must be independent of original source0"
        );
        ensure!(
            admission.budget.max_row_bytes <= args.max_row_bytes,
            "admitted object row exceeds explicit extractor cap"
        );
        let ram = admission
            .budget
            .max_row_bytes
            .checked_mul(8)
            .and_then(|n| n.checked_add(u64::from(admission.budget.page_bytes) * 4))
            .and_then(|n| n.checked_add(args.max_output_bytes as u64 * 16))
            .and_then(|n| n.checked_add(METADATA_CAP * 32 + 4 * 1024 * 1024))
            .context("extractor RAM bound overflow")?;
        ensure!(
            ram <= args.ram_bytes,
            "extractor working/corpus envelope exceeds explicit RAM cap"
        );
        let expected = Held::open(
            &args.expected_pages,
            &args.expected_sha256,
            args.max_file_bytes,
            &args.metadata_volume_guid,
        )?;
        let budget = admission.expected_page_budget()?;
        let mut reader = Reader::open_held(
            expected.file.try_clone()?,
            &args.expected_sha256,
            PURPOSE,
            budget,
        )?;
        let first = reader.get(0)?;
        ensure!(first.key.is_empty(), "expected scalar header key differs");
        let header: ExpectedTreePageHeader = serde_json::from_slice(&first.payload)?;
        ensure!(
            header.schema_version == 3
                && header.resource_admission == Some(admission)
                && header.total_objects == admission.objects()?,
            "expected header/source admission mismatch"
        );
        drop(first);
        let maximum_chunk =
            usize::try_from(((budget.max_page_bytes - 90) / 4 * 3).min(768 * 1024))?;
        let mut corpus = BTreeMap::new();
        let mut variants = BTreeMap::new();
        let mut retained = CorpusBudget {
            used: 0,
            maximum: args.max_output_bytes,
        };
        let (mut cursor, mut compact, mut files, mut directories, mut streams) =
            (1u64, 0u64, 0u64, 0u64, 0u64);
        for ordinal in 0..header.total_objects {
            let mut bytes = Vec::new();
            let mut chunks = 0u64;
            let mut previous = maximum_chunk;
            while cursor < reader.len() {
                let item = reader.get(cursor)?;
                ensure!(item.key.len() == 16, "expected object key width differs");
                let object = u64::from_be_bytes(item.key[..8].try_into()?);
                if object != ordinal {
                    ensure!(
                        chunks > 0 && object == ordinal + 1,
                        "expected object sequence differs"
                    );
                    break;
                }
                ensure!(
                    u64::from_be_bytes(item.key[8..].try_into()?) == chunks
                        && previous == maximum_chunk,
                    "expected chunk order/nonfinal size differs"
                );
                let raw = decode_chunk(&item.payload, maximum_chunk)?;
                previous = raw.len();
                let length = bytes
                    .len()
                    .checked_add(raw.len())
                    .context("expected object size overflow")?;
                ensure!(
                    length as u64 <= admission.budget.max_row_bytes,
                    "expected object exceeds admitted row"
                );
                bytes.try_reserve_exact(raw.len())?;
                bytes.extend_from_slice(&raw);
                chunks += 1;
                cursor += 1;
            }
            ensure!(chunks > 0, "expected object has no complete chunks");
            compact = compact
                .checked_add(bytes.len() as u64)
                .filter(|n| *n <= admission.semantic_byte_budget())
                .context("expected compact domain exceeds admitted semantic bytes")?;
            let object: Object = serde_json::from_slice(&bytes)?;
            if object.directory {
                directories += 1;
            } else {
                files += 1;
            }
            streams += object.data_streams().count() as u64;
            observe_sd(
                &object,
                &object.security,
                false,
                &mut corpus,
                &mut variants,
                args.max_unique_descriptors,
                &mut retained,
            )?;
            if let Some(api) = &object.api_security {
                observe_sd(
                    &object,
                    api,
                    true,
                    &mut corpus,
                    &mut variants,
                    args.max_unique_descriptors,
                    &mut retained,
                )?;
            }
        }
        ensure!(
            cursor == reader.len(),
            "unaccounted expected objects/chunks"
        );
        admission.validate_tree(files, directories, streams)?;
        reader.revalidate()?;
        expected.revalidate(args.max_file_bytes)?;
        assessment.revalidate(METADATA_CAP)?;
        let report = serde_json::json!({"kind":"closed-expected-process-trust-inventory-v1",
            "expected_file":expected.snapshot,"expected_sha256":args.expected_sha256,
            "assessment_sha256":args.source_assessment_sha256,"source_inspection_sha256":hex::encode(admission.source_inspection_sha256),
            "objects":header.total_objects,"files":files,"directories":directories,"streams":streams,
            "unique_descriptors_with_trust_aces_or_layout_errors":corpus.len(),"ace_variant_count":variants.len(),
            "ace_variants":variants.into_values().collect::<Vec<_>>(),"descriptors":corpus.into_values().collect::<Vec<_>>(),
            "source_device_opens":0,"source_volume_opens":0,"setter_calls":0,"metadata_only":true,
            "native_preservation_qualified":false,"resource_admission_is_expectation_metadata_only":true,
            "explicit_ram_cap":args.ram_bytes,"working_ram_envelope":ram,"max_output_bytes":args.max_output_bytes});
        let mut count = Count {
            bytes: 0,
            maximum: args.max_output_bytes - 1,
        };
        serde_json::to_writer_pretty(&mut count, &report)?;
        ordinary_path(&args.output)?;
        ensure!(!args.output.exists(), "fresh extractor output required");
        let parent = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x0220_0000)
            .open(args.output.parent().context("output parent absent")?)?;
        let route = n2r_win32::file_storage::final_path_guid(&parent)?;
        ensure!(
            on_volume(&route, &args.metadata_volume_guid)?
                || route.trim_end_matches('\\').eq_ignore_ascii_case(&format!(
                    "\\\\?\\Volume{{{}}}",
                    args.metadata_volume_guid.trim_matches(['{', '}'])
                )),
            "output must remain on the explicit metadata filesystem"
        );
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(&args.output)?;
        serde_json::to_writer_pretty(&mut output, &report)?;
        output.write_all(b"\n")?;
        output.sync_all()?;
        println!(
            "{}",
            serde_json::to_string(
                &serde_json::json!({"output":args.output,"bytes":count.bytes+1,
            "objects":header.total_objects,"source_device_opens":0,"setter_calls":0})
            )?
        );
        Ok(())
    }
}
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows::run()
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Expected trust-label extraction requires Windows.");
    std::process::exit(2);
}
