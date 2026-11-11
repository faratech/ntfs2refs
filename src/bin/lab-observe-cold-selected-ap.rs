//! Standalone read-only cold-AP progress evidence for the original Windows disk.
//! This binary neither replays a journal nor changes disk attributes. It proves
//! only two distinct complete-row endpoints, not that every other byte is valid.
#![recursion_limit = "256"]
#[cfg(windows)]
mod windows {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        general_layout::{
            GeneralDiskBinding, GeneralDiskLayoutProfile, GeneralSourceShadowBinding,
        },
        journal_file::{GeneralJournalStorageBinding, JournalFileIdentity, JournalProfile},
        reference_file::ReferenceFileSnapshot,
        tree_resources::SourceResourceAdmission,
    };
    use ntfs2refs::selected_journal::{
        self as sj, SelectedCopyRange, SelectedLifecycle, SelectedPlan, SelectedRange,
        SelectedTicket,
    };
    use serde::{Deserialize, Serialize, de::DeserializeOwned};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        mem,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf},
        time::SystemTime,
    };

    const G: u64 = 4096;
    const BODY: u64 = 8192;
    const BUFFER: usize = 1024 * 1024;
    const MAX_RANGES: u32 = 65_536; // Existing public selected_journal limit.
    const REPORT_CAP: usize = 64 * 1024;
    const FILE_FLAGS: u32 = 0x0020_0000;

    #[derive(Parser)]
    #[command(
        about = "Observe cold AP endpoints using read-only handles; never recover or write a source"
    )]
    struct Args {
        #[arg(long)]
        publication: PathBuf,
        #[arg(long)]
        publication_sha256: String,
        #[arg(long)]
        expected_source_disk_guid: String,
        #[arg(long)]
        expected_source_partition_guid: String,
        #[arg(long)]
        max_journal_bytes: u64,
        #[arg(long)]
        max_selected_read_bytes: u64,
        #[arg(long, default_value_t = MAX_RANGES)]
        max_ranges: u32,
        #[arg(long, default_value_t = 1_048_576)]
        max_metadata_bytes: u64,
        #[arg(long, default_value_t = 268_435_456)]
        ram_bytes: u64,
        #[arg(long)]
        output: PathBuf,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct FilePin {
        path: PathBuf,
        sha256: String,
        bytes: u64,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct ExpectedPin {
        file: FilePin,
        semantic_sha256: String,
        objects: u64,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct MapPin {
        file: FilePin,
        records: u64,
    }
    #[allow(dead_code)] // Decode the complete pinned publication schema.
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Publication {
        schema_version: u32,
        kind: String,
        #[serde(default)]
        source_scope: Option<serde_json::Value>,
        source: GeneralDiskBinding,
        shadow: GeneralDiskBinding,
        resource_admission: SourceResourceAdmission,
        verification_policy: serde_json::Value,
        source_fingerprint_kind: String,
        source_sha256: String,
        source_inspection_sha256: String,
        source_views_sha256: String,
        locator: FilePin,
        expected: ExpectedPin,
        #[serde(default)]
        recovery_maps: Option<MapPin>,
        #[serde(default)]
        windows_aliases: Option<serde_json::Value>,
        #[serde(default)]
        windows_alias_plan_sha256: Option<String>,
        #[serde(default)]
        early_preparation_guard: Option<serde_json::Value>,
        ticket_sha256: String,
        expected_mount_paths: Vec<String>,
        expected_source_label: serde_json::Value,
        serialized_publication_grants_authority: bool,
    }
    #[derive(Clone, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct IdentityWire {
        volume_serial_number: u64,
        file_id_128: [u8; 16],
        volume_guid: [u8; 16],
        disk_guid: [u8; 16],
        partition_guid: [u8; 16],
        partition_number: u32,
        disk_bytes: u64,
        partition_offset: u64,
        partition_bytes: u64,
        logical_sector_bytes: u32,
        physical_sector_bytes: u32,
    }
    impl IdentityWire {
        fn identity(&self) -> JournalFileIdentity {
            JournalFileIdentity {
                volume_serial_number: self.volume_serial_number,
                file_id_128: self.file_id_128,
                volume_guid: self.volume_guid,
                disk_guid: self.disk_guid,
                partition_guid: self.partition_guid,
                partition_number: self.partition_number,
                disk_bytes: self.disk_bytes,
                partition_offset: self.partition_offset,
                partition_bytes: self.partition_bytes,
                logical_sector_bytes: self.logical_sector_bytes,
                physical_sector_bytes: self.physical_sector_bytes,
            }
        }
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Locator {
        schema_version: u32,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_scope: Option<serde_json::Value>,
        source: GeneralDiskBinding,
        journal_binding: GeneralJournalStorageBinding,
        journal_identity: IdentityWire,
        journal_path: PathBuf,
        journal_profile_version: u32,
        journal_profile_max_bytes: u64,
        marker_native_qualified_observation: Option<bool>,
        marker_lab_observation: bool,
        ticket: SelectedTicket,
        serialized_locator_grants_authority: bool,
    }

    struct HeldMetadata {
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
            .map_err(|_| anyhow::anyhow!("SHA-256 width differs"))
    }
    fn same_guid(a: &str, b: &str) -> Result<bool> {
        Ok(n2r_win32::layout::guid_bytes(a)? == n2r_win32::layout::guid_bytes(b)?)
    }
    fn add(a: u64, b: u64) -> Result<u64> {
        a.checked_add(b).context("observer range overflow")
    }
    fn u32le(b: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
    }
    fn u64le(b: &[u8], at: usize) -> u64 {
        u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
    }
    fn source_state(
        source: &GeneralDiskBinding,
        history: &mut Vec<n2r_win32::NativeEvent>,
    ) -> Result<n2r_win32::GeneralDiskState> {
        // Keep earlier audit batches outside the next native operation's
        // bounded event vector; preserve success and error observations alike.
        let mut batch = Vec::new();
        let result = n2r_win32::observe_general_disk_state_readonly(source.clone(), &mut batch);
        history.try_reserve(batch.len())?;
        history.extend(batch);
        Ok(result?)
    }
    fn json_sha(value: &impl Serialize) -> Result<String> {
        struct Sink(Sha256);
        impl Write for Sink {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.update(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut sink = Sink(Sha256::new());
        serde_json::to_writer(&mut sink, value)?;
        Ok(hex::encode(sink.0.finalize()))
    }
    fn ordinary_path(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute()
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "absolute ordinary path required"
        );
        for parent in path.parent().context("artifact parent absent")?.ancestors() {
            if parent.as_os_str().is_empty() {
                continue;
            }
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "reparse or non-directory artifact ancestry refused"
            );
        }
        Ok(())
    }
    fn on_volume(path: &str, binding: &GeneralDiskBinding) -> Result<bool> {
        let prefix = format!("{}\\", binding.volume_path()?);
        Ok(path
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(&prefix)))
    }
    impl HeldMetadata {
        fn open(path: &Path, sha256: [u8; 32], bytes: Option<u64>, maximum: u64) -> Result<Self> {
            ordinary_path(path)?;
            let mut file = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(FILE_FLAGS)
                .open(path)?;
            n2r_win32::file_storage::require_readonly_access(&file)?;
            let snapshot = n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &file, maximum,
            )?;
            let modified = file.metadata()?.modified()?;
            ensure!(
                snapshot.number_of_links == 1
                    && snapshot.file_bytes > 0
                    && bytes.is_none_or(|n| n == snapshot.file_bytes),
                "pinned metadata length/link count differs"
            );
            ensure!(
                n2r_win32::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)? == sha256,
                "metadata differs from independently trusted pin"
            );
            let result = Self {
                file,
                snapshot,
                modified,
                sha256,
            };
            result.revalidate(maximum)?;
            Ok(result)
        }
        fn revalidate(&self, maximum: u64) -> Result<()> {
            ensure!(
                n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                    &self.file, maximum
                )? == self.snapshot
                    && self.file.metadata()?.modified()? == self.modified,
                "held pinned metadata identity changed"
            );
            // A cloned File shares the Windows seek position. Every later read
            // explicitly seeks; the complete hash remains on the held object.
            let mut file = self.file.try_clone()?;
            ensure!(
                n2r_win32::sha256_native::hash_range(&mut file, 0, self.snapshot.file_bytes)?
                    == self.sha256,
                "held pinned metadata bytes changed"
            );
            Ok(())
        }
        fn json<T: DeserializeOwned>(&mut self) -> Result<T> {
            self.file.seek(SeekFrom::Start(0))?;
            let mut bytes = Vec::new();
            bytes.try_reserve_exact(usize::try_from(self.snapshot.file_bytes)?)?;
            (&mut self.file)
                .take(self.snapshot.file_bytes)
                .read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == self.snapshot.file_bytes,
                "short metadata read"
            );
            Ok(serde_json::from_slice(&bytes)?)
        }
    }

    fn read_locator(held: &mut HeldMetadata, maximum: u64) -> Result<Locator> {
        ensure!(held.snapshot.file_bytes >= 64, "short N2RANC01 locator");
        held.file.seek(SeekFrom::Start(0))?;
        let mut header = [0; 64];
        held.file.read_exact(&mut header)?;
        let length = u64le(&header, 16);
        ensure!(
            &header[..8] == b"N2RANC01"
                && u32le(&header, 8) == 1
                && header[12..16] == [0; 4]
                && header[56..] == [0; 8]
                && length > 0
                && add(64, length)? == held.snapshot.file_bytes
                && length <= maximum,
            "locator framing differs"
        );
        let mut payload = Vec::new();
        payload.try_reserve_exact(usize::try_from(length)?)?;
        (&mut held.file).take(length).read_to_end(&mut payload)?;
        ensure!(
            payload.len() as u64 == length
                && Sha256::digest(&payload).as_slice() == &header[24..56],
            "locator payload hash differs"
        );
        let locator: Locator = serde_json::from_slice(&payload)?;
        ensure!(
            serde_json::to_vec(&locator)? == payload,
            "locator canonical payload encoding differs"
        );
        Ok(locator)
    }

    #[derive(Clone)]
    struct Row {
        ordinal: u32,
        offset: u64,
        length: u64,
        old_kind: u64,
        new_kind: u64,
        old_payload: u64,
        old_sha256: [u8; 32],
        new_sha256: [u8; 32],
    }
    fn parse_plan(
        journal: &mut File,
        ticket: &SelectedTicket,
        max_ranges: u32,
        max_journal_bytes: u64,
    ) -> Result<(SelectedPlan, Vec<Row>, u32)> {
        ensure!(
            ticket.marker_profile.is_none()
                && ticket.range_count > 0
                && ticket.range_count <= max_ranges
                && max_ranges <= MAX_RANGES,
            "observer supports markerless public journals with at most 65,536 ranges"
        );
        let mut header = [0; 80];
        journal.seek(SeekFrom::Start(BODY))?;
        journal.read_exact(&mut header)?;
        let version = u32le(&header, 8);
        let (magic, record_bytes, hashes): (&[u8; 8], usize, usize) = match version {
            1 => (b"N2RSEL01", 80, 16),
            2 => (b"N2RZERO1", 88, 24),
            3 => (b"N2RCPY01", 96, 32),
            4 => (b"N2ROLD01", 104, 40),
            5 => (b"N2RFRE01", 104, 40),
            _ => anyhow::bail!("unsupported markerless selected format"),
        };
        ensure!(
            &header[..8] == magic
                && u32le(&header, 12) == ticket.range_count
                && u64le(&header, 16) == ticket.image_length
                && u64le(&header, 24) == ticket.selected_bytes
                && u64le(&header, 32) == ticket.journal_length,
            "journal header differs from trusted ticket"
        );
        let mut plan = SelectedPlan {
            image_length: ticket.image_length,
            ranges: Vec::new(),
            max_selected_bytes: ticket.selected_bytes,
            max_journal_bytes,
            new_zero_ranges: Vec::new(),
            new_copy_ranges: Vec::new(),
            old_zero_ranges: Vec::new(),
            source_free_ranges: Vec::new(),
        };
        let mut rows = Vec::new();
        rows.try_reserve_exact(ticket.range_count as usize)?;
        for vector in [
            &mut plan.ranges,
            &mut plan.new_zero_ranges,
            &mut plan.old_zero_ranges,
            &mut plan.source_free_ranges,
        ] {
            vector.try_reserve_exact(ticket.range_count as usize)?;
        }
        plan.new_copy_ranges
            .try_reserve_exact(ticket.range_count as usize)?;
        let mut position = BODY + 80;
        let mut previous_end = 0;
        let mut selected = 0u64;
        for ordinal in 0..ticket.range_count {
            ensure!(
                add(position, record_bytes as u64)? <= ticket.journal_length.saturating_sub(80),
                "journal descriptor exceeds footer"
            );
            let mut descriptor = [0; 104];
            journal.seek(SeekFrom::Start(position))?;
            journal.read_exact(&mut descriptor[..record_bytes])?;
            let offset = u64le(&descriptor, 0);
            let length = u64le(&descriptor, 8);
            let new_kind = if version >= 2 {
                u64le(&descriptor, 16)
            } else {
                0
            };
            let copy = if version >= 3 {
                u64le(&descriptor, 24)
            } else {
                0
            };
            let old_kind = if version >= 4 {
                u64le(&descriptor, 32)
            } else {
                0
            };
            let end = add(offset, length)?;
            ensure!(
                length > 0
                    && offset.is_multiple_of(G)
                    && length.is_multiple_of(G)
                    && offset >= previous_end
                    && end <= ticket.image_length
                    && new_kind <= if version >= 3 { 2 } else { 1 }
                    && old_kind <= if version >= 5 { 2 } else { 1 }
                    && (new_kind == 2 || copy == 0),
                "selected row geometry or kind differs"
            );
            let range = SelectedRange { offset, length };
            plan.ranges.push(range.clone());
            if new_kind == 1 {
                plan.new_zero_ranges.push(range.clone());
            }
            if new_kind == 2 {
                plan.new_copy_ranges.push(SelectedCopyRange {
                    offset,
                    length,
                    source_offset: copy,
                });
            }
            if old_kind == 1 {
                plan.old_zero_ranges.push(range.clone());
            }
            if old_kind == 2 {
                plan.source_free_ranges.push(range);
            }
            let old_payload = add(position, record_bytes as u64)?;
            let old_bytes = match old_kind {
                0 => length,
                1 => 0,
                2 => length / G * 16,
                _ => unreachable!(),
            };
            position = add(
                add(old_payload, old_bytes)?,
                if new_kind == 0 { length } else { 0 },
            )?;
            ensure!(
                position <= ticket.journal_length.saturating_sub(80),
                "selected payload exceeds footer"
            );
            rows.push(Row {
                ordinal,
                offset,
                length,
                old_kind,
                new_kind,
                old_payload,
                old_sha256: descriptor[hashes..hashes + 32].try_into()?,
                new_sha256: descriptor[hashes + 32..hashes + 64].try_into()?,
            });
            selected = add(selected, length)?;
            previous_end = end;
        }
        ensure!(
            position == ticket.journal_length - 80 && selected == ticket.selected_bytes,
            "selected descriptors do not close the trusted body"
        );
        let (_, length) = plan.validate()?;
        ensure!(
            length == ticket.journal_length,
            "derived selected plan has another wire length"
        );
        Ok((plan, rows, version))
    }

    #[derive(Serialize)]
    struct Witness {
        ordinal: u32,
        offset: u64,
        length: u64,
        old_kind: u64,
        new_kind: u64,
        current_sha256: String,
        stored_old_sha256: String,
        stored_old_hash_encoding: &'static str,
        stored_new_sha256: String,
        source_free_granules_different_from_old: u64,
    }
    fn current_hash(
        source: &mut File,
        journal: &mut File,
        partition: u64,
        row: &Row,
        buffer: &mut [u8],
    ) -> Result<([u8; 32], u64)> {
        source.seek(SeekFrom::Start(add(partition, row.offset)?))?;
        let mut hash = n2r_win32::sha256_native::Sha256::new()?;
        let mut done = 0;
        let mut different = 0u64;
        let mut table = [0u8; BUFFER / G as usize * 16];
        while done < row.length {
            let count = usize::try_from((row.length - done).min(buffer.len() as u64))?;
            source.read_exact(&mut buffer[..count])?;
            hash.update(&buffer[..count])?;
            if row.old_kind == 2 {
                let bytes = count / G as usize * 16;
                journal.seek(SeekFrom::Start(add(row.old_payload, done / G * 16)?))?;
                journal.read_exact(&mut table[..bytes])?;
                for (granule, old) in buffer[..count]
                    .chunks_exact(G as usize)
                    .zip(table[..bytes].chunks_exact(16))
                {
                    different += u64::from(
                        xxhash_rust::xxh3::xxh3_128(granule)
                            .to_le_bytes()
                            .as_slice()
                            != old,
                    );
                }
            }
            done = add(done, count as u64)?;
        }
        Ok((hash.finish()?, different))
    }

    fn save_receipt(
        path: &Path,
        value: &impl Serialize,
        journal: &GeneralJournalStorageBinding,
    ) -> Result<()> {
        ordinary_path(path)?;
        ensure!(!path.exists(), "fresh observer receipt path required");
        let parent = OpenOptions::new()
            .access_mode(0x80)
            .share_mode(1)
            .custom_flags(0x0220_0000)
            .open(path.parent().context("receipt parent absent")?)?;
        ensure!(
            on_volume(
                &n2r_win32::file_storage::final_path_guid(&parent)?,
                &journal.disk
            )? || n2r_win32::file_storage::final_path_guid(&parent)?
                .trim_end_matches('\\')
                .eq_ignore_ascii_case(&journal.disk.volume_path()?),
            "receipt must be on the independently bound journal volume"
        );
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= REPORT_CAP,
            "small observer receipt cap exceeded"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(FILE_FLAGS)
            .open(path)?;
        file.write_all(&bytes)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        Ok(())
    }

    pub fn run() -> Result<bool> {
        let args = Args::parse();
        ensure!(
            (1..=MAX_RANGES).contains(&args.max_ranges)
                && (4096..=16 * 1024 * 1024).contains(&args.max_metadata_bytes)
                && args.max_journal_bytes >= BODY + 160
                && args.max_selected_read_bytes >= G
                && args.max_selected_read_bytes.is_multiple_of(G),
            "observer resource caps differ"
        );
        // Includes parser expansions, all bounded descriptor/plan vectors, the
        // public lifecycle validator's records/workers, and fixed IO buffers.
        let ram_required = args
            .max_metadata_bytes
            .checked_mul(48)
            .and_then(|n| {
                n.checked_add(u64::from(args.max_ranges) * (mem::size_of::<Row>() as u64 + 256))
            })
            .and_then(|n| n.checked_add(64 * 1024 * 1024))
            .context("observer RAM bound overflow")?;
        ensure!(
            ram_required <= args.ram_bytes,
            "observer allocation envelope exceeds explicit RAM cap"
        );
        let mut publication_file = HeldMetadata::open(
            &args.publication,
            digest(&args.publication_sha256)?,
            None,
            args.max_metadata_bytes,
        )?;
        let publication: Publication = publication_file.json()?;
        publication.resource_admission.validate()?;
        let source = &publication.source;
        ensure!(
            publication.schema_version == 1
                && publication.kind == "resource-allocation-recovery-envelope-v1"
                && publication.source_scope.is_none()
                && !publication.serialized_publication_grants_authority
                && source.disk_number == 0
                && source.layout_profile == GeneralDiskLayoutProfile::OfflineWindows
                && same_guid(&source.identity.disk_guid, &args.expected_source_disk_guid)?
                && same_guid(
                    &source.identity.partition_guid,
                    &args.expected_source_partition_guid
                )?
                && digest(&publication.source_inspection_sha256)?
                    == publication.resource_admission.source_inspection_sha256,
            "publication is not the exact independently pinned original Windows source0"
        );
        let pair = GeneralSourceShadowBinding {
            source: source.clone(),
            shadow: publication.shadow.clone(),
        };
        pair.validate_with_resource_profile(Some(
            n2r_win32::attestation::ResourceProfile::ResourceBoundedV4(Some(
                publication.resource_admission,
            )),
        ))?;
        digest(&publication.source_sha256)?;
        digest(&publication.source_views_sha256)?;
        digest(&publication.expected.file.sha256)?;
        digest(&publication.expected.semantic_sha256)?;
        if let Some(map) = &publication.recovery_maps {
            digest(&map.file.sha256)?;
            ensure!(map.records > 0, "empty map pin");
        }
        if let Some(plan) = &publication.windows_alias_plan_sha256 {
            digest(plan)?;
        }
        let mut locator_file = HeldMetadata::open(
            &publication.locator.path,
            digest(&publication.locator.sha256)?,
            Some(publication.locator.bytes),
            args.max_metadata_bytes,
        )?;
        let locator = read_locator(&mut locator_file, args.max_metadata_bytes)?;
        locator.journal_binding.validate()?;
        let ticket = &locator.ticket;
        ensure!(
            locator.schema_version == 1
                && locator.kind == "resource-recovery-locator-v1"
                && locator.source_scope.is_none()
                && locator.source == *source
                && !locator.serialized_locator_grants_authority
                && !locator.marker_lab_observation
                && locator.marker_native_qualified_observation.is_none()
                && ticket.marker_profile.is_none()
                && !ticket.whole_image_verified
                && ticket.image_length == source.identity.partition_bytes
                && <[u8; 32]>::from(Sha256::digest(serde_json::to_vec(ticket)?))
                    == digest(&publication.ticket_sha256)?
                && ticket.journal_length >= BODY + 160
                && ticket.journal_length <= args.max_journal_bytes
                && ticket.journal_length <= locator.journal_profile_max_bytes,
            "locator/ticket does not match the original public markerless source"
        );
        let journal_binding = &locator.journal_binding;
        ensure!(
            journal_binding.disk.disk_number != source.disk_number
                && journal_binding.disk.disk_number != publication.shadow.disk_number
                && !same_guid(
                    &journal_binding.disk.identity.disk_guid,
                    &source.identity.disk_guid
                )?
                && !same_guid(
                    &journal_binding.disk.identity.disk_guid,
                    &publication.shadow.identity.disk_guid
                )?
                && on_volume(&publication_file.snapshot.final_path, &journal_binding.disk)?
                && on_volume(&locator_file.snapshot.final_path, &journal_binding.disk)?,
            "metadata/J storage aliases a data device"
        );
        let profile = JournalProfile::from_schema_and_capacity(
            locator.journal_profile_version,
            (locator.journal_profile_version == 3).then_some(locator.journal_profile_max_bytes),
        )?;
        ensure!(
            profile.max_journal_bytes() == locator.journal_profile_max_bytes,
            "journal capacity profile changed"
        );
        ordinary_path(&locator.journal_path)?;
        let mut journal = OpenOptions::new()
            .read(true)
            .share_mode(0)
            .custom_flags(FILE_FLAGS)
            .open(&locator.journal_path)?;
        n2r_win32::file_storage::require_readonly_access(&journal)?;
        let journal_before = n2r_win32::journal_file::observe_general_journal_file_with_profile(
            &journal,
            journal_binding,
            profile,
        )?;
        let journal_modified = journal.metadata()?.modified()?;
        ensure!(
            journal_before.identity == locator.journal_identity.identity()
                && journal_before.file_bytes == ticket.journal_length
                && on_volume(&journal_before.final_path, &journal_binding.disk)?,
            "actual read-only journal native identity differs from locator"
        );
        let (plan, rows, version) = parse_plan(
            &mut journal,
            ticket,
            args.max_ranges,
            args.max_journal_bytes,
        )?;
        // Existing full immutable/payload/footer/COPY authentication. COPY
        // resolution reads this J only; no current-source bytes are involved.
        ensure!(
            sj::lifecycle(&mut journal, &plan, ticket)? == SelectedLifecycle::ApplyIntent,
            "cold observer requires actual AP, never clear/RB/HND/ABT"
        );
        publication_file.revalidate(args.max_metadata_bytes)?;
        locator_file.revalidate(args.max_metadata_bytes)?;
        let mut events = Vec::new();
        let before = source_state(source, &mut events)?;
        ensure!(
            matches!(before.disk_attributes, 1 | 3),
            "original source0 is not excluded"
        );
        // Buffered, kernel READ_ONLY primary handle, denying concurrent writers.
        // Do not use GeneralExclusiveRecoveryTarget: its physical handle is RW.
        let mut target = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(format!("\\\\.\\PhysicalDrive{}", source.disk_number))?;
        n2r_win32::file_storage::require_readonly_access(&target)?;
        ensure!(
            source_state(source, &mut events)? == before,
            "source0 changed while acquiring read-only primary handle"
        );
        let mut buffer = vec![0; BUFFER];
        let mut old = None;
        let mut new = None;
        let (mut read_bytes, mut read_rows, mut unknown, mut equal_endpoints, mut skipped_budget) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        for row in &rows {
            if old.is_some() && new.is_some() {
                break;
            }
            if row.old_kind != 2 && row.old_sha256 == row.new_sha256 {
                equal_endpoints += 1;
                continue;
            }
            if row.old_kind == 2 && new.is_some() {
                continue;
            }
            if add(read_bytes, row.length)? > args.max_selected_read_bytes {
                skipped_budget += 1;
                continue;
            }
            let (current, free_differences) = current_hash(
                &mut target,
                &mut journal,
                source.identity.partition_offset,
                row,
                &mut buffer,
            )?;
            read_bytes = add(read_bytes, row.length)?;
            read_rows += 1;
            let is_old =
                row.old_kind != 2 && current == row.old_sha256 && current != row.new_sha256;
            let is_new = current == row.new_sha256
                && if row.old_kind == 2 {
                    free_differences > 0
                } else {
                    current != row.old_sha256
                };
            let witness = || Witness {
                ordinal: row.ordinal,
                offset: row.offset,
                length: row.length,
                old_kind: row.old_kind,
                new_kind: row.new_kind,
                current_sha256: hex::encode(current),
                stored_old_sha256: hex::encode(row.old_sha256),
                stored_old_hash_encoding: if row.old_kind == 2 {
                    "sha256-of-xxh3-128-le-per-4096-byte-old-granule-table"
                } else {
                    "sha256-of-raw-old-range"
                },
                stored_new_sha256: hex::encode(row.new_sha256),
                source_free_granules_different_from_old: free_differences,
            };
            if is_old && old.is_none() {
                old = Some(witness());
            }
            if is_new && new.is_none() {
                new = Some(witness());
            }
            if !is_old && !is_new {
                unknown += 1;
            }
        }
        ensure!(
            source_state(source, &mut events)? == before,
            "source0 identity or exclusion changed during selected reads"
        );
        ensure!(
            sj::lifecycle(&mut journal, &plan, ticket)? == SelectedLifecycle::ApplyIntent,
            "actual AP/immutable journal changed during cold observation"
        );
        let journal_after = n2r_win32::journal_file::observe_general_journal_file_with_profile(
            &journal,
            journal_binding,
            profile,
        )?;
        ensure!(
            journal_after.identity == journal_before.identity
                && journal_after.file_bytes == journal_before.file_bytes
                && journal_after.allocation_bytes == journal_before.allocation_bytes
                && journal_after.final_path == journal_before.final_path
                && journal.metadata()?.modified()? == journal_modified,
            "held native journal identity changed"
        );
        publication_file.revalidate(args.max_metadata_bytes)?;
        locator_file.revalidate(args.max_metadata_bytes)?;
        ensure!(
            source_state(source, &mut events)? == before,
            "source0 changed before observation closure"
        );
        let success = old.is_some() && new.is_some();
        let state_sha = json_sha(&before)?;
        let receipt = serde_json::json!({
            "kind":"lab-cold-resource-ap-endpoints-v1","success":success,
            "scope":"Two distinct complete-row OLD/NEW endpoints; unclassified rows are not declared foreign",
            "publication_path":publication_file.snapshot.final_path,"publication_sha256":args.publication_sha256,
            "locator_sha256":publication.locator.sha256,"ticket_sha256":publication.ticket_sha256,
            "source":source,"source_state_sha256":state_sha,"source_disk_attributes":before.disk_attributes,
            "journal_path":journal_before.final_path,"journal_identity":locator.journal_identity,
            "journal_length":ticket.journal_length,"journal_immutable_sha256":hex::encode(ticket.immutable_sha256),
            "journal_format":version,"lifecycle_before":"apply_intent","lifecycle_after":"apply_intent",
            "journal_full_authentication_passes":2,"copy_authentication_reads_journal_only":true,
            "range_count":ticket.range_count,"selected_bytes":ticket.selected_bytes,"rows_read":read_rows,
            "source_selected_bytes_read":read_bytes,"max_source_selected_bytes_read":args.max_selected_read_bytes,
            "unclassified_rows_read":unknown,"equal_endpoint_rows_skipped":equal_endpoints,"rows_skipped_by_read_budget":skipped_budget,
            "stopped_after_two_witnesses":success,"old_witness":old,"new_witness":new,
            "all_selected_bytes_verified_old_or_new":false,"foreign_byte_absence_claimed":false,
            "source_handle_readonly":true,"journal_handle_readonly":true,
            "source_write_calls":0,"journal_write_calls":0,"disk_attribute_set_calls":0,
            "recovery_or_write_authority_issued":false,"whole_image_verified":false,
            "native_event_count":events.len(),"native_events_sha256":json_sha(&events)?,
            "explicit_ram_cap":args.ram_bytes,"observer_ram_envelope":ram_required,
        });
        drop(target);
        drop(journal);
        save_receipt(&args.output, &receipt, journal_binding)?;
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"receipt":args.output,"success":success,
            "source_selected_bytes_read":read_bytes,"source_write_calls":0,"journal_write_calls":0}))?
        );
        Ok(success)
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<std::process::ExitCode> {
    Ok(if windows::run()? {
        std::process::ExitCode::SUCCESS
    } else {
        std::process::ExitCode::from(2)
    })
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The cold AP observer requires Windows; no operation performed.");
}
