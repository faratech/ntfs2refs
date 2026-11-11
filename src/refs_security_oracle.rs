//! Hidden, bounded native-driver oracle on one explicitly selected lab shadow.
//! No original source argument, source admission, or additional raw writer.
use crate::{
    lab_reconstruct::ReadSeek,
    refs_security_descriptor::TrustLabelPlaceholder,
    refs_security_patch::{SecurityClusterPatch, SecurityPatchPlan},
    selected_journal::{self as sj, SelectedLifecycle, SelectedPlan, SelectedRange},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::{
    GeneralFrozenPartition, NativeEvent, WritePolicy,
    discovery::{self, Role},
    general_layout::{GeneralDiskBinding, GeneralDiskLayoutProfile},
    journal_file::{
        GeneralJournalStorageBinding, JournalFileSnapshot, JournalProfile,
        observe_general_journal_file_with_profile,
    },
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::{
    fs::{File, OpenOptions},
    io::{self, BufWriter, Read, Seek, SeekFrom, Write},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
    path::{Component, Path, PathBuf},
};

const CLUSTER: u64 = 4096;
const IMAGE_BYTES: u64 = 52 << 30;
const JOURNAL_BYTES: u64 = 32 << 20;
const PIN_BYTES: u64 = 40 << 20;
const ARTIFACT_BYTES: u64 = 64 << 20;
const RAM_BYTES: u64 = 128 << 20;
const MINIMUM_FREE: u64 = 256 << 20;
const FILE_FLAGS: u32 = 0x8020_0000; // WRITE_THROUGH | OPEN_REPARSE_POINT.

// Preserve complete audit history while giving each SDK operation its own
// bounded batch, including an operation that returns an error.
fn native_step<T, E>(
    history: &mut Vec<NativeEvent>,
    operation: impl FnOnce(&mut Vec<NativeEvent>) -> std::result::Result<T, E>,
) -> std::result::Result<T, E> {
    let mut batch = Vec::new();
    let result = operation(&mut batch);
    history.append(&mut batch);
    result
}

#[derive(Debug, Serialize)]
pub struct ShadowSecurityOracleReceipt {
    pub kind: &'static str,
    pub target: GeneralDiskBinding,
    pub expected_created_disk_guid: String,
    pub journal: JournalFileSnapshot,
    pub journal_sha256: String,
    pub prepared_pin_path: PathBuf,
    pub prepared_pin_sha256: String,
    pub plan_profile: String,
    pub plan_vbr_sha256: String,
    pub plan_volume_serial: u64,
    pub plan_page_reads: u32,
    pub changed_clusters: usize,
    pub selected_bytes: u64,
    pub new_selected_sha256: String,
    pub native_write_bytes_requested: u64,
    pub native_bytes_written: u64,
    pub journal_handoff_closed: bool,
    pub target_brought_online: bool,
    pub native_security_preservation_qualified: bool,
    pub requires_remounted_security_and_payload_readback: bool,
    pub admitted_ram_bytes: u64,
    pub maximum_artifact_bytes: u64,
    pub native_events: Vec<NativeEvent>,
    pub requested_descriptors: usize,
    pub creator_files_verified: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub creator_file_bindings: Vec<OracleCreatorFile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus_input_pins: Option<OracleCorpusInputPins>,
}

#[derive(Clone, Debug, Serialize)]
pub struct OracleCorpusInputPins {
    pub corpus_sha256: String,
    pub creator_manifest_sha256: String,
    pub corpus_snapshot: n2r_win32::reference_file::ReferenceFileSnapshot,
    pub creator_manifest_snapshot: n2r_win32::reference_file::ReferenceFileSnapshot,
    pub corpus_descriptor_contexts: usize,
    pub physical_stored_descriptors: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OracleCreatorFile {
    pub id: String,
    pub original_sha256: String,
    pub components: Vec<String>,
    pub directory: bool,
    pub file_id_info_hex: String,
}

fn verify_creator_files(
    target: &GeneralDiskBinding,
    root: &str,
    files: &[OracleCreatorFile],
    replacements: &[TrustLabelPlaceholder],
) -> Result<()> {
    ensure!(
        n2r_win32::shadow_names::valid_unicode_component(root)
            && root.encode_utf16().count() <= 128
            && files.len() == replacements.len(),
        "bounded complete fresh creator root required"
    );
    let volume = target.volume_path()?;
    let root_path = format!("{volume}\\{root}");
    let open = |path: &str| {
        OpenOptions::new()
            .access_mode(0x80)
            .share_mode(3)
            .custom_flags(0x0220_0000)
            .open(path)
    };
    let held_root = open(&root_path)?;
    ensure!(
        held_root.metadata()?.is_dir()
            && held_root.metadata()?.file_attributes() & 0x400 == 0
            && n2r_win32::file_storage::final_path_guid(&held_root)?
                .eq_ignore_ascii_case(&root_path),
        "fresh creator root is not the actual ordinary target directory"
    );
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for (file, replacement) in files.iter().zip(replacements) {
        ensure!(
            (2..=32).contains(&file.components.len())
                && file.components[0] == root
                && file
                    .components
                    .iter()
                    .all(|s| n2r_win32::shadow_names::valid_unicode_component(s)
                        && s.encode_utf16().count() <= 255)
                && file.file_id_info_hex.len() == 48
                && file
                    .file_id_info_hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && file.original_sha256 == hex::encode(Sha256::digest(&replacement.original))
                && ids.insert(file.file_id_info_hex.clone())
                && names.insert(file.components.clone()),
            "creator file mapping, identity uniqueness or original descriptor differs"
        );
        let path = format!("{volume}\\{}", file.components.join("\\"));
        ensure!(
            path.encode_utf16().count() < 32767,
            "creator path exceeds native bound"
        );
        // Context-faithful cases retain their original parent hierarchy. Hold
        // and check each actual ancestor so a nested path cannot escape this
        // owned oracle root through a reparse point or directory replacement.
        let mut parents = Vec::new();
        for end in 2..file.components.len() {
            let parent_path = format!("{volume}\\{}", file.components[..end].join("\\"));
            let parent = open(&parent_path)?;
            let metadata = parent.metadata()?;
            ensure!(
                metadata.is_dir()
                    && metadata.file_attributes() & 0x400 == 0
                    && n2r_win32::file_storage::final_path_guid(&parent)?
                        .eq_ignore_ascii_case(&parent_path),
                "creator parent hierarchy is not the actual ordinary oracle subtree"
            );
            parents.push(parent);
        }
        let held = open(&path)?;
        let metadata = held.metadata()?;
        ensure!(
            metadata.is_dir() == file.directory
                && metadata.file_attributes() & 0x400 == 0
                && n2r_win32::file_storage::file_id_info(&held)? == file.file_id_info_hex
                && n2r_win32::file_storage::final_path_guid(&held)?.eq_ignore_ascii_case(&path),
            "actual fresh creator file ID, type, root or no-reparse binding differs"
        );
    }
    Ok(())
}

struct Candidate<'a> {
    patches: &'a [SecurityClusterPatch],
    position: u64,
}
impl Read for Candidate<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() || self.position == IMAGE_BYTES {
            return Ok(0);
        }
        let i = self.patches.partition_point(|p| p.offset <= self.position);
        let patch = i
            .checked_sub(1)
            .and_then(|i| self.patches.get(i))
            .ok_or_else(|| io::Error::other("oracle candidate read outside selected metadata"))?;
        let at = self.position - patch.offset;
        if at >= CLUSTER {
            return Err(io::Error::other("oracle candidate complement read refused"));
        }
        let count = output.len().min(CLUSTER as usize - at as usize);
        output[..count].copy_from_slice(&patch.after[at as usize..at as usize + count]);
        self.position += count as u64;
        Ok(count)
    }
}
impl Seek for Candidate<'_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(IMAGE_BYTES) + i128::from(n),
        };
        if !(0..=i128::from(IMAGE_BYTES)).contains(&next) {
            return Err(io::Error::other("oracle candidate seek outside image"));
        }
        self.position = next as u64;
        Ok(self.position)
    }
}
impl ReadSeek for Candidate<'_> {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(IMAGE_BYTES)
    }
}

struct PinWriter {
    file: BufWriter<File>,
    count: u64,
    maximum: u64,
    hash: Sha256,
}
impl Write for PinWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let end = self
            .count
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| io::Error::other("oracle pin budget exhausted"))?;
        self.file.write_all(bytes)?;
        self.hash.update(bytes);
        self.count = end;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

fn persist(path: &Path, value: &impl Serialize, maximum: u64) -> Result<(File, String, u64)> {
    ensure!(
        maximum > 0 && maximum <= PIN_BYTES,
        "oracle metadata pin bound differs"
    );
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAGS)
        .open(path)?;
    let identity = n2r_win32::file_storage::file_id_info(&file)?;
    let mut writer = PinWriter {
        file: BufWriter::with_capacity(256 * 1024, file),
        count: 0,
        maximum,
        hash: Sha256::new(),
    };
    serde_json::to_writer(&mut writer, value)?;
    writer.file.flush()?;
    writer.file.get_ref().sync_all()?;
    let expected: [u8; 32] = writer.hash.finalize().into();
    let count = writer.count;
    drop(writer.file);
    let mut held = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(path)?;
    ensure!(
        n2r_win32::file_storage::file_id_info(&held)? == identity
            && held.metadata()?.len() == count
            && held.metadata()?.is_file()
            && held.metadata()?.file_attributes() & 0x400 == 0
            && n2r_win32::file_storage::number_of_links(&held)? == 1
            && n2r_win32::sha256_native::hash_range(&mut held, 0, count)? == expected,
        "oracle metadata pin identity, EOF or durable readback differs"
    );
    Ok((held, hex::encode(expected), count))
}

fn hold_parents(parent: &Path) -> Result<Vec<File>> {
    parent
        .ancestors()
        .map(|path| {
            let file = OpenOptions::new()
                .access_mode(0x80)
                .share_mode(3)
                .custom_flags(0x0220_0000)
                .open(path)?;
            let metadata = file.metadata()?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "oracle output ancestors must be ordinary held directories"
            );
            Ok(file)
        })
        .collect()
}

/// Laboratory hook only. `expected_created_disk_guid` must be read from the
/// actual fresh R: creator record. The target is independently rediscovered;
/// this string and the request binding never substitute for native isolation.
#[doc(hidden)]
pub fn qualify_owned_shadow(
    target: GeneralDiskBinding,
    expected_created_disk_guid: &str,
    journal_binding: &GeneralJournalStorageBinding,
    output: &Path,
    replacements: &[TrustLabelPlaceholder],
) -> Result<ShadowSecurityOracleReceipt> {
    ensure!(
        replacements.len() == 1,
        "legacy oracle requires one descriptor"
    );
    qualify_owned_shadow_inner(
        target,
        expected_created_disk_guid,
        journal_binding,
        output,
        replacements,
        None,
        None,
    )
}

#[doc(hidden)]
pub fn qualify_owned_shadow_corpus(
    target: GeneralDiskBinding,
    expected_created_disk_guid: &str,
    journal_binding: &GeneralJournalStorageBinding,
    output: &Path,
    replacements: &[TrustLabelPlaceholder],
    creator_root: &str,
    creator_files: &[OracleCreatorFile],
    input_pins: &OracleCorpusInputPins,
) -> Result<ShadowSecurityOracleReceipt> {
    ensure!(
        (1..=512).contains(&replacements.len()) && creator_files.len() == replacements.len(),
        "complete one-to-512 descriptor corpus and creator bindings required"
    );
    qualify_owned_shadow_inner(
        target,
        expected_created_disk_guid,
        journal_binding,
        output,
        replacements,
        Some((creator_root, creator_files)),
        Some(input_pins),
    )
}

fn qualify_owned_shadow_inner(
    target: GeneralDiskBinding,
    expected_created_disk_guid: &str,
    journal_binding: &GeneralJournalStorageBinding,
    output: &Path,
    replacements: &[TrustLabelPlaceholder],
    creators: Option<(&str, &[OracleCreatorFile])>,
    input_pins: Option<&OracleCorpusInputPins>,
) -> Result<ShadowSecurityOracleReceipt> {
    target.validate()?;
    journal_binding.validate()?;
    let guid = n2r_win32::layout::guid_bytes;
    ensure!(
        target.layout_profile == GeneralDiskLayoutProfile::DedicatedData
            // Windows may renumber this same persistent oracle after reboot.
            // The original Windows disk remains explicitly excluded; the
            // creator GUID, dedicated geometry and independent journal bind R.
            && target.disk_number != 0
            && target.identity.partition_offset == 16 << 20
            && target.identity.partition_bytes == IMAGE_BYTES
            && target.identity.logical_sector_bytes == 512
            && target.identity.physical_sector_bytes == 4096
            && guid(&target.identity.disk_guid)? == guid(expected_created_disk_guid)?
            && journal_binding.disk.disk_number != 0
            && journal_binding.disk.disk_number != target.disk_number
            && guid(&journal_binding.disk.identity.disk_guid)? != guid(&target.identity.disk_guid)?
            && guid(&journal_binding.disk.volume_guid)? != guid(&target.volume_guid)?
            && (1..=512).contains(&replacements.len()),
        "oracle scope differs from the explicitly created independent dedicated R: disk"
    );
    let current = n2r_win32::current_windows_directory()?;
    let text = output.to_str().context("Unicode oracle output required")?;
    ensure!(
        current
            .to_str()
            .is_some_and(|s| s.get(..3).is_some_and(|r| r.eq_ignore_ascii_case("C:\\")))
            && output.is_absolute()
            && !output.exists()
            && text.encode_utf16().count() <= 1024
            && output.components().count() <= 32
            && text
                .get(..3)
                .is_some_and(|s| s.eq_ignore_ascii_case("C:\\"))
            && !text[3..].contains(':')
            && !output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
        "fresh ordinary oracle output on actual current C: required"
    );
    let parent = output.parent().context("oracle output parent absent")?;
    let mut parents = hold_parents(parent)?;
    let c_guid =
        n2r_win32::file_storage::final_path_guid(parents.first().context("held parent absent")?)?;
    let journal_prefix = format!("{}\\", journal_binding.disk.volume_path()?);
    ensure!(
        c_guid
            .to_ascii_lowercase()
            .starts_with(&journal_prefix.to_ascii_lowercase()),
        "actual C: output parent differs from enrolled independent journal volume"
    );
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    ensure!(
        available.available_physical_bytes >= RAM_BYTES
            && available.scratch_available_bytes >= ARTIFACT_BYTES + MINIMUM_FREE,
        "oracle cannot preserve its bounded RAM, artifacts and remaining free-space reserve"
    );
    let discovered = discovery::discover(&(target.volume_path()? + "\\"), Role::Shadow)?;
    ensure!(
        discovered.binding == target
            && discovered.filesystem == "ReFS"
            && discovered.observed_twice_unchanged
            && discovered.windows_disk_number == journal_binding.disk.disk_number,
        "fresh target or actual current C: native binding differs"
    );
    if let Some((root, files)) = creators {
        verify_creator_files(&target, root, files, replacements)?;
    }
    std::fs::create_dir(output)?;
    parents.insert(0, hold_parents(output)?.remove(0));
    let profile = JournalProfile::from_schema_and_capacity(3, Some(JOURNAL_BYTES))?;
    let journal_path = output.join("security-oracle.journal");
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(FILE_FLAGS)
        .open(&journal_path)?;
    let initial_journal =
        observe_general_journal_file_with_profile(&journal, journal_binding, profile)?;
    ensure!(
        initial_journal.file_bytes == 0 && initial_journal.number_of_links == 1,
        "fresh native ordinary oracle journal required"
    );
    let mut events = Vec::new();
    let mut frozen = native_step(&mut events, |batch| {
        GeneralFrozenPartition::isolate(target.clone(), batch)
    })?;
    let before = native_step(&mut events, |batch| frozen.state(batch))?;
    let mut vbr = [0u8; 512];
    frozen.seek(SeekFrom::Start(0))?;
    frozen.read_exact(&mut vbr)?;
    let geometry = crate::refs_inspect::inspect_boot_sector(&vbr, IMAGE_BYTES)?;
    let vbr_sha256 = hex::encode(Sha256::digest(vbr));
    let plan = crate::refs_security_patch::plan_native_canonical_trust_label_restoration(
        &mut frozen,
        IMAGE_BYTES,
        &vbr_sha256,
        geometry.volume_serial,
        replacements,
        4096,
        1024,
    )?;
    let mut end = CLUSTER;
    for patch in &plan.clusters {
        ensure!(
            patch.before.len() == CLUSTER as usize
                && patch.after.len() == CLUSTER as usize
                && patch.before != patch.after
                && patch.offset >= end
                && patch.offset.is_multiple_of(CLUSTER)
                && patch
                    .offset
                    .checked_add(CLUSTER)
                    .is_some_and(|n| n <= IMAGE_BYTES - CLUSTER),
            "oracle patch clusters overlap or escape the exact metadata selection"
        );
        end = patch.offset + CLUSTER;
        let mut actual = [0u8; 4096];
        frozen.seek(SeekFrom::Start(patch.offset))?;
        frozen.read_exact(&mut actual)?;
        ensure!(
            actual.as_slice() == patch.before,
            "oracle native OLD metadata changed"
        );
    }
    ensure!(
        !plan.clusters.is_empty()
            && plan.clusters.len() <= 1024
            && native_step(&mut events, |batch| frozen.state(batch))? == before,
        "oracle has no bounded stable graph repair"
    );
    let selected = SelectedPlan {
        image_length: IMAGE_BYTES,
        ranges: plan
            .clusters
            .iter()
            .map(|p| SelectedRange {
                offset: p.offset,
                length: CLUSTER,
            })
            .collect(),
        max_selected_bytes: 1024 * CLUSTER,
        max_journal_bytes: JOURNAL_BYTES,
        new_zero_ranges: vec![],
        new_copy_ranges: vec![],
        old_zero_ranges: vec![],
        source_free_ranges: vec![],
    };
    let mut candidate = Candidate {
        patches: &plan.clusters,
        position: 0,
    };
    let (_, expected_journal_bytes) = selected.validate()?;
    n2r_win32::file_storage::preallocate_empty_file(
        &journal,
        expected_journal_bytes,
        JOURNAL_BYTES,
    )?;
    let ticket = sj::prepare_exclusive(&mut frozen, &mut candidate, &mut journal, &selected)?;
    let prepared_journal =
        observe_general_journal_file_with_profile(&journal, journal_binding, profile)?;
    ensure!(
        prepared_journal.identity == initial_journal.identity
            && prepared_journal.file_bytes == ticket.journal_length,
        "oracle prepared native journal identity or EOF differs"
    );
    #[derive(Serialize)]
    struct Pin<'a> {
        kind: &'static str,
        target: &'a GeneralDiskBinding,
        expected_created_disk_guid: &'a str,
        journal: &'a JournalFileSnapshot,
        ticket: &'a sj::SelectedTicket,
        plan: &'a SecurityPatchPlan,
        creator_root: Option<&'a str>,
        creator_files: Option<&'a [OracleCreatorFile]>,
        corpus_input_pins: Option<&'a OracleCorpusInputPins>,
    }
    let pin_path = output.join("security-oracle-prepared.json");
    let (_pin, pin_sha256, pin_bytes) = persist(
        &pin_path,
        &Pin {
            kind: "owned-native-shadow-security-oracle-prepared-v1",
            target: &target,
            expected_created_disk_guid,
            journal: &prepared_journal,
            ticket: &ticket,
            plan: &plan,
            creator_root: creators.map(|(root, _)| root),
            creator_files: creators.map(|(_, files)| files),
            corpus_input_pins: input_pins,
        },
        PIN_BYTES,
    )?;
    ensure!(
        pin_bytes + ticket.journal_length + (2 << 20) <= ARTIFACT_BYTES
            && n2r_win32::resource_native::observe_available_resources(output)?
                .scratch_available_bytes
                >= MINIMUM_FREE
            && native_step(&mut events, |batch| frozen.state(batch))? == before,
        "oracle actual prepared storage or native identity exceeds its bounds"
    );
    let mut writer = native_step(&mut events, |batch| {
        frozen.activate_for_journal_exclusive(batch)
    })?;
    native_step(&mut events, |batch| {
        writer.arm_encoded_selected_writes(
            WritePolicy {
                allowed: selected
                    .ranges
                    .iter()
                    .map(|r| (r.offset, r.length))
                    .collect(),
                retained: vec![],
                maximum_bytes: ticket.selected_bytes,
                journal_profile: profile,
            },
            ticket.journal_length,
            batch,
        )
    })?;
    let (_applied_pin, _applied, handed_off) = {
        let mut applied_pin = None;
        let (applied, handed_off) = sj::apply_and_handoff_exclusive(
            &mut writer,
            &mut journal,
            &selected,
            &ticket,
            |result| {
                applied_pin = Some(persist(
                    &output.join("security-oracle-applied.json"),
                    result,
                    64 << 10,
                )?);
                Ok(())
            },
        )?;
        (
            applied_pin.context("actual applied metadata pin absent")?,
            applied,
            handed_off,
        )
    };
    let (lifecycle, closed) = sj::verify_closed(&mut writer, &mut journal, &selected, &ticket)?;
    ensure!(
        lifecycle == SelectedLifecycle::Handoff
            && closed.replay_closed
            && handed_off.replay_closed
            && closed.selected_sha256 == ticket.new_selected_sha256,
        "oracle native HND/NEW verification failed"
    );
    let native_write_bytes_requested = writer.native_write_bytes_requested;
    let native_bytes_written = writer.native_bytes_written;
    let final_journal =
        observe_general_journal_file_with_profile(&journal, journal_binding, profile)?;
    ensure!(
        final_journal.identity == initial_journal.identity
            && final_journal.file_bytes == ticket.journal_length,
        "oracle closed journal identity differs"
    );
    let journal_sha256 = hex::encode(n2r_win32::sha256_native::hash_range(
        &mut journal,
        0,
        ticket.journal_length,
    )?);
    native_step(&mut events, |batch| writer.bring_online(batch))?;
    if let Some((root, files)) = creators {
        verify_creator_files(&target, root, files, replacements)?;
    }
    let receipt = ShadowSecurityOracleReceipt {
        kind: "owned-native-shadow-security-oracle-HND-online-v1",
        target,
        expected_created_disk_guid: expected_created_disk_guid.to_owned(),
        journal: final_journal,
        journal_sha256,
        prepared_pin_path: pin_path,
        prepared_pin_sha256: pin_sha256,
        plan_profile: plan.profile.to_owned(),
        plan_vbr_sha256: plan.vbr_sha256,
        plan_volume_serial: plan.volume_serial,
        plan_page_reads: plan.page_reads,
        changed_clusters: plan.clusters.len(),
        selected_bytes: ticket.selected_bytes,
        new_selected_sha256: hex::encode(ticket.new_selected_sha256),
        native_write_bytes_requested,
        native_bytes_written,
        journal_handoff_closed: true,
        target_brought_online: true,
        native_security_preservation_qualified: false,
        requires_remounted_security_and_payload_readback: true,
        admitted_ram_bytes: RAM_BYTES,
        maximum_artifact_bytes: ARTIFACT_BYTES,
        native_events: events,
        requested_descriptors: replacements.len(),
        creator_files_verified: creators.map_or(0, |(_, files)| files.len()),
        creator_file_bindings: creators.map_or_else(Vec::new, |(_, files)| files.to_vec()),
        corpus_input_pins: input_pins.cloned(),
    };
    let _closed = persist(
        &output.join("security-oracle-closed.json"),
        &receipt,
        1 << 20,
    )?;
    Ok(receipt)
}
