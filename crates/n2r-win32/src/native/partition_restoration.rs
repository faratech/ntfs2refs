//! Actual terminal partition restoration. No JSON flag issues a writer.
//! All source fields below arrive by consuming the validated ORIGINAL owner.
use super::partition_isolation::{PartitionObservationBudget, PartitionSourceBinding};
use super::*;
use crate::attestation::NativeObservationDomain;
use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Seek, SeekFrom},
    os::windows::fs::OpenOptionsExt,
};

use super::partition_owner::{PartitionDataProfile, PartitionPhysicalDataOwner};
mod physical_profile;
pub use physical_profile::open_readonly_physical_recovery;
mod basic_ro;
pub use basic_ro::PartitionBasicReadonlyTerminal;
mod operational;
pub use operational::{OperationalPartitionMetadata, PartitionOperationalTerminal};

// Actual terminal metadata only: no private-owner/admission/loaded flags.
struct TerminalMetadataBaseline {
    partition: partition_isolation::PartitionIsolationObservation,
    configured_dump_locations: partition_dump_locations::ConfiguredDumpObservation,
    storage_current_partition_roles:
        super::partition_storage_roles::PartitionStorageRoleObservation,
}
impl From<PartitionOwnerState> for TerminalMetadataBaseline {
    fn from(value: PartitionOwnerState) -> Self {
        Self {
            partition: value.partition,
            configured_dump_locations: value.configured_dump_locations,
            storage_current_partition_roles: value.storage_current_partition_roles,
        }
    }
}

const RO: u64 = 0x1000_0000_0000_0000;
const BASIC: &str = "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7";
const PRIVATE: &str = "b627aadb-a893-48b6-aa0b-71e5f30ee370";
const MAX_JSON: u64 = 4 * 1024 * 1024;
const MAX_INTENT: u64 = 16 * 1024 * 1024;
fn bad(m: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, m)
}
fn need(ok: bool, m: &str) -> io::Result<()> {
    if ok { Ok(()) } else { Err(bad(m)) }
}
fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn str_field<'a>(v: &'a Value, n: &str) -> io::Result<&'a str> {
    v.get(n)
        .and_then(Value::as_str)
        .ok_or_else(|| bad("required string routing field absent"))
}
fn num_field(v: &Value, n: &str) -> io::Result<u64> {
    v.get(n)
        .and_then(Value::as_u64)
        .ok_or_else(|| bad("required integer routing field absent"))
}
fn json_bytes(v: &Value) -> io::Result<Vec<u8>> {
    serde_json::from_value(v.clone()).map_err(io::Error::other)
}
fn digest(v: &Value, n: &str) -> io::Result<[u8; 32]> {
    let s = str_field(v, n)?;
    need(
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "noncanonical metadata SHA256",
    )?;
    hex::decode(s)
        .map_err(io::Error::other)?
        .try_into()
        .map_err(|_| bad("SHA-256 pin length differs"))
}
fn crc(b: &[u8]) -> u32 {
    let mut c = !0u32;
    for byte in b {
        c ^= u32::from(*byte);
        for _ in 0..8 {
            c = (c >> 1) ^ (0xedb8_8320u32 & 0u32.wrapping_sub(c & 1));
        }
    }
    !c
}
fn header(original: &[u8], entries: &[u8]) -> io::Result<Vec<u8>> {
    let mut b = original.to_vec();
    let n = crate::layout::u32_at(&b, 12)? as usize;
    need(n >= 92 && n <= b.len(), "original GPT header bound differs")?;
    b[88..92].copy_from_slice(&crc(entries).to_le_bytes());
    b[16..20].fill(0);
    let h = crc(&b[..n]);
    b[16..20].copy_from_slice(&h.to_le_bytes());
    Ok(b)
}
fn physical_read(binding: &PartitionSourceBinding, at: u64, n: usize) -> io::Result<Vec<u8>> {
    need(
        n <= 65536
            && at
                .checked_add(n as u64)
                .is_some_and(|e| e <= binding.storage.identity.disk_bytes),
        "restoration metadata read bound differs",
    )?;
    let mut f = device_file(
        &format!("\\\\.\\PhysicalDrive{}", binding.storage.disk_number),
        false,
        false,
    )?;
    need(
        f.seek(SeekFrom::Start(at))? == at,
        "restoration metadata seek differs",
    )?;
    let mut b = vec![0; n];
    f.read_exact(&mut b)?;
    Ok(b)
}

/// Held metadata files are routing inputs until open_authenticated checks their
/// exact content/identity and actual J/source lineage. No flag is authority.
pub struct PartitionRestartFiles {
    pub publication: File,
    pub locator: File,
    pub preparation_intent: File,
    pub native_metadata: File,
}
struct Artifact {
    file: File,
    snapshot: crate::reference_file::ReferenceFileSnapshot,
    sha: [u8; 32],
}
impl Artifact {
    fn hold(
        file: File,
        expected: [u8; 32],
        limit: u64,
        binding: &PartitionSourceBinding,
        windows: &partition_isolation::PartitionVolumeExtent,
        require_c: bool,
    ) -> io::Result<Self> {
        crate::file_storage::require_readonly_access(&file)?;
        let before = crate::reference_file::observe_reference_file_handle_with_limit(&file, limit)?;
        need(
            before.file_bytes > 0 && before.number_of_links == 1,
            "ordinary nonempty single-link restoration artifact required",
        )?;
        // Acquire our own readonly/write-delete-excluding FileObject on the
        // actual observed GUID path, then prove it is the same supplied file.
        let mut held = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x0020_0000)
            .open(&before.final_path)?;
        let actual = crate::reference_file::observe_reference_file_handle_with_limit(&held, limit)?;
        need(
            actual == before,
            "restoration artifact route changed while holding it",
        )?;
        let end = actual
            .final_path
            .find("}\\")
            .ok_or_else(|| bad("artifact GUID route absent"))?
            + 1;
        let volume = device_file(&actual.final_path[..end], false, false)?;
        let ext = control(
            &volume,
            "partition-restoration-artifact-extents",
            VOLUME_EXTENTS,
            &[],
            32,
            &mut Vec::new(),
        )?;
        need(
            ext.len() == 32 && crate::layout::u32_at(&ext, 0)? == 1,
            "restoration artifact extent is not a complete basic volume",
        )?;
        let disk = crate::layout::u32_at(&ext, 8)?;
        let at = crate::layout::u64_at(&ext, 16)?;
        let bytes = crate::layout::u64_at(&ext, 24)?;
        let target = &binding.storage.identity;
        let end = at
            .checked_add(bytes)
            .ok_or_else(|| bad("artifact extent overflow"))?;
        let te = target
            .partition_offset
            .checked_add(target.partition_bytes)
            .ok_or_else(|| bad("target extent overflow"))?;
        need(
            disk != binding.storage.disk_number || end <= target.partition_offset || at >= te,
            "restoration metadata overlaps target",
        )?;
        if require_c {
            need(
                disk == windows.disk_number && at == windows.offset && bytes == windows.length,
                "preparation intent is not on actual Windows C",
            )?;
        }
        let observed = crate::sha256_native::hash_range(&mut held, 0, actual.file_bytes)?;
        need(
            observed == expected
                && crate::reference_file::observe_reference_file_handle_with_limit(&held, limit)?
                    == actual,
            "restoration artifact hash/identity differs",
        )?;
        Ok(Self {
            file: held,
            snapshot: actual,
            sha: observed,
        })
    }
    fn adopt_held(
        file: File,
        expected: [u8; 32],
        limit: u64,
        binding: &PartitionSourceBinding,
        windows: &partition_isolation::PartitionVolumeExtent,
        require_c: bool,
    ) -> io::Result<Self> {
        crate::file_storage::require_readonly_access(&file)?;
        let before = crate::reference_file::observe_reference_file_handle_with_limit(&file, limit)?;
        need(
            before.file_bytes > 0 && before.number_of_links == 1,
            "ordinary nonempty single-link restoration artifact required",
        )?;
        // Actual SDK live transfer retains its original FileObject. Prove
        // that object still denies an ordinary compatible RW contender.
        match OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(3)
            .custom_flags(0x0020_0000)
            .open(&before.final_path)
        {
            Err(error) if error.raw_os_error() == Some(32) => (),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("held live artifact sharing is unknown: {error}"),
                ));
            }
            Ok(contender) => {
                drop(contender);
                return Err(bad("held live artifact permits another RW writer"));
            }
        }
        let mut held = file;
        let actual = crate::reference_file::observe_reference_file_handle_with_limit(&held, limit)?;
        need(actual == before, "actual live artifact metadata changed")?;
        let end = actual
            .final_path
            .find("}\\")
            .ok_or_else(|| bad("artifact GUID route absent"))?
            + 1;
        let volume = device_file(&actual.final_path[..end], false, false)?;
        let ext = control(
            &volume,
            "partition-restoration-artifact-extents",
            VOLUME_EXTENTS,
            &[],
            32,
            &mut Vec::new(),
        )?;
        need(
            ext.len() == 32 && crate::layout::u32_at(&ext, 0)? == 1,
            "restoration artifact extent is not a complete basic volume",
        )?;
        let disk = crate::layout::u32_at(&ext, 8)?;
        let at = crate::layout::u64_at(&ext, 16)?;
        let bytes = crate::layout::u64_at(&ext, 24)?;
        let target = &binding.storage.identity;
        let end = at
            .checked_add(bytes)
            .ok_or_else(|| bad("artifact extent overflow"))?;
        let te = target
            .partition_offset
            .checked_add(target.partition_bytes)
            .ok_or_else(|| bad("target extent overflow"))?;
        need(
            disk != binding.storage.disk_number || end <= target.partition_offset || at >= te,
            "restoration metadata overlaps target",
        )?;
        if require_c {
            need(
                disk == windows.disk_number && at == windows.offset && bytes == windows.length,
                "preparation intent is not on actual Windows C",
            )?;
        }
        let observed = crate::sha256_native::hash_range(&mut held, 0, actual.file_bytes)?;
        need(
            observed == expected
                && crate::reference_file::observe_reference_file_handle_with_limit(&held, limit)?
                    == actual,
            "restoration artifact hash/identity differs",
        )?;
        Ok(Self {
            file: held,
            snapshot: actual,
            sha: observed,
        })
    }
    fn read(&mut self, max: u64) -> io::Result<Vec<u8>> {
        need(
            self.snapshot.file_bytes <= max,
            "restoration metadata exceeds parsing bound",
        )?;
        self.file.seek(SeekFrom::Start(0))?;
        let mut b = vec![0; self.snapshot.file_bytes as usize];
        self.file.read_exact(&mut b)?;
        Ok(b)
    }
    fn revalidate(&mut self) -> io::Result<()> {
        need(
            crate::reference_file::observe_reference_file_handle_with_limit(
                &self.file,
                self.snapshot.file_bytes,
            )? == self.snapshot
                && crate::sha256_native::hash_range(&mut self.file, 0, self.snapshot.file_bytes)?
                    == self.sha,
            "held restoration artifact changed",
        )
    }
}

fn protected_info(original: &[u8], profile: PartitionDataProfile) -> io::Result<Vec<u8>> {
    need(
        original.len() == 144,
        "original native partition info width differs",
    )?;
    let mut info = original.to_vec();
    let (kind, attrs) = match profile {
        PartitionDataProfile::PrivateVolumeV2 => (PRIVATE, 0),
        PartitionDataProfile::BasicReadonlyPhysicalV3 => (BASIC, RO),
    };
    info[32..48].copy_from_slice(&crate::layout::guid_bytes(kind)?);
    info[64..72].copy_from_slice(&attrs.to_le_bytes());
    Ok(info)
}
struct Origin {
    data_profile: PartitionDataProfile,
    scope: Value,
    original_info: Vec<u8>,
    original_gpt: Value,
    original_mbr: Vec<u8>,
    original_primary: [u8; 32],
    original_label: crate::volume_label::VolumeLabel,
    mount_paths: Vec<String>,
    publication: Artifact,
    locator: Artifact,
    intent: Artifact,
    native_file: Option<Artifact>,
    native_pages: crate::observation_pages::PagedNativeObservation,
}

/// Recovered metadata/physical origin only. Actual held publication, locator,
/// intent frames and native pages are authenticated; no live NTFS admission,
/// all-OLD assertion, replay direction or source writer is created here.
/// The independent SDK MIXED/closed-J gates remain mandatory.
pub struct PartitionRecoveredOrigin {
    origin: Origin,
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    token: PartitionOwnerToken,
    journal_pins: super::paged_recovery::OwnedPartitionJournalPins,
}
impl PartitionRecoveredOrigin {
    pub fn open_authenticated(
        owner: &mut PartitionScopedOwner,
        budget: PartitionObservationBudget,
        files: PartitionRestartFiles,
        published_sha256: [u8; 32],
        pins: &super::paged_recovery::PagedRecoveryPins<'_>,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        budget.validate()?;
        owner.revalidate(events)?;
        let binding = owner.binding().clone();
        let token = owner.owner_token();
        let origin = Origin::authenticate(
            files,
            published_sha256,
            &binding,
            budget,
            &owner.state().partition.windows_volume,
            pins,
        )?;
        let mut recovered = Self {
            origin,
            binding,
            budget,
            token,
            journal_pins: super::paged_recovery::OwnedPartitionJournalPins::capture(pins),
        };
        recovered.revalidate_private(owner, events)?;
        Ok(recovered)
    }
    pub fn binding(&self) -> &PartitionSourceBinding {
        &self.binding
    }
    pub fn owner_token(&self) -> &PartitionOwnerToken {
        &self.token
    }
    pub fn require_journal_pins(
        &self,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>,
    ) -> io::Result<()> {
        self.journal_pins.require(pins)
    }
    /// Validated routing DTO, not the SDK's process-live preparation guard.
    pub fn original_pin(&self) -> &Value {
        &self.origin.scope["complete_preparation_guard"]
    }
    pub fn routing_scope(&self) -> &Value {
        &self.origin.scope
    }
    pub fn native_metadata(&self) -> &crate::observation_pages::PagedNativeObservation {
        &self.origin.native_pages
    }
    pub fn revalidate_private(
        &mut self,
        owner: &mut PartitionScopedOwner,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        need(
            self.token.same_owner(&owner.owner_token()) && self.binding == *owner.binding(),
            "recovered origin lost its actual private owner",
        )?;
        owner.revalidate(events)?;
        self.origin.revalidate()?;
        need(
            self.origin.data_profile == owner.data_profile(),
            "authenticated source scope and actual owner data profile differ",
        )?;
        let current_info = owner.expected_protected_partition_info(&self.origin.original_info)?;
        validate_origin_layout(
            &self.origin,
            &self.binding,
            &current_info,
            &owner.state().partition,
        )?;
        need(
            physical_read(&self.binding, 0, 512)? == self.origin.original_mbr,
            "recovered origin protective MBR differs",
        )?;
        owner.revalidate(events)
    }
    pub fn into_terminal<'journal, 'pins>(
        mut self,
        mut owner: PartitionScopedOwner,
        policy: &'journal HeldPagedWritePolicy,
        journal: &'journal mut File,
        pins: super::paged_recovery::PagedRecoveryPins<'pins>,
        kind: PartitionTerminalKind,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionTerminalRestorationGuard<'journal, 'pins>> {
        self.revalidate_private(&mut owner, events)?;
        self.journal_pins.require(&pins)?;
        let closed = authenticate_partition_closed_journal(
            &mut owner, policy, journal, &pins, kind, events,
        )?;
        need(
            self.origin.data_profile == owner.data_profile(),
            "recovered terminal source profile differs",
        )?;
        let current_info = owner.expected_protected_partition_info(&self.origin.original_info)?;
        let parts = owner.into_terminal_restoration_parts(&closed, events)?;
        let mut guard = PartitionTerminalRestorationGuard {
            file: Some(parts.file),
            data_profile: parts.data_profile,
            physical_data: parts.physical_data,
            physical: parts.physical_readonly,
            binding: parts.binding.clone(),
            budget: parts.budget,
            baseline: parts.state.into(),
            token: parts.token,
            origin: self.origin,
            closed,
            policy,
            journal,
            pins,
            kind,
            stage: if parts.data_profile == PartitionDataProfile::BasicReadonlyPhysicalV3 {
                PartitionTerminalStage::ProtectedPhysical
            } else {
                PartitionTerminalStage::Private
            },
            current_info,
            mounted_binding: parts.binding.storage,
            mounted: None,
        };
        guard.revalidate_metadata(events)?;
        guard.revalidate_closed(events)?;
        Ok(guard)
    }
}
impl Origin {
    fn authenticate(
        files: PartitionRestartFiles,
        published_sha: [u8; 32],
        binding: &PartitionSourceBinding,
        budget: PartitionObservationBudget,
        windows: &partition_isolation::PartitionVolumeExtent,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>,
    ) -> io::Result<Self> {
        Self::authenticate_owned(
            files.publication,
            files.locator,
            IntentInput::Reopened(files.preparation_intent),
            NativeInput::Reopened(files.native_metadata),
            published_sha,
            binding,
            budget,
            windows,
            pins,
        )
    }
    fn authenticate_owned(
        publication_file: File,
        locator_file: File,
        intent_input: IntentInput,
        native_input: NativeInput,
        published_sha: [u8; 32],
        binding: &PartitionSourceBinding,
        budget: PartitionObservationBudget,
        windows: &partition_isolation::PartitionVolumeExtent,
        pins: &super::paged_recovery::PagedRecoveryPins<'_>,
    ) -> io::Result<Self> {
        let mut publication = Artifact::adopt_held(
            publication_file,
            published_sha,
            MAX_JSON,
            binding,
            windows,
            false,
        )?;
        need(
            publication
                .snapshot
                .file_bytes
                .checked_mul(32)
                .is_some_and(|n| n <= budget.ram_bytes),
            "publication parsing exceeds explicit RAM budget",
        )?;
        let envelope: Value =
            serde_json::from_slice(&publication.read(MAX_JSON)?).map_err(io::Error::other)?;
        let data_profile = match (
            num_field(&envelope, "schema_version")?,
            str_field(&envelope, "kind")?,
        ) {
            (2, "resource-partition-recovery-envelope-v2") => PartitionDataProfile::PrivateVolumeV2,
            (3, "resource-partition-readonly-physical-recovery-envelope-v3") => {
                PartitionDataProfile::BasicReadonlyPhysicalV3
            }
            _ => {
                return Err(bad(
                    "terminal restoration requires an explicit supported partition protocol",
                ));
            }
        };
        let scope = envelope
            .get("source_scope")
            .ok_or_else(|| bad("partition scope missing"))?
            .clone();
        need(
            match data_profile {
                PartitionDataProfile::PrivateVolumeV2 => {
                    str_field(&scope, "kind")? == "partition-v2"
                        && num_field(&scope, "scope_version")? == 2
                }
                PartitionDataProfile::BasicReadonlyPhysicalV3 => {
                    str_field(&scope, "kind")? == "partition-ro-physical-v3"
                        && num_field(&scope, "scope_version")? == 3
                }
            },
            "unknown terminal restoration source scope",
        )?;
        let actual_binding: PartitionSourceBinding =
            serde_json::from_value(scope["binding"].clone()).map_err(io::Error::other)?;
        need(
            &actual_binding == binding
                && serde_json::from_value::<crate::general_layout::GeneralDiskBinding>(
                    envelope["source"].clone(),
                )
                .map_err(io::Error::other)?
                    == binding.storage,
            "publication source differs from actual private target",
        )?;
        let lp = &envelope["locator"];
        let mut locator = Artifact::adopt_held(
            locator_file,
            digest(lp, "sha256")?,
            MAX_JSON + 64,
            binding,
            windows,
            false,
        )?;
        need(
            locator.snapshot.file_bytes == num_field(lp, "bytes")?,
            "locator length differs",
        )?;
        let raw = locator.read(MAX_JSON + 64)?;
        need(
            raw.len() >= 64
                && &raw[..8] == b"N2RANC01"
                && crate::layout::u32_at(&raw, 8)? == 1
                && crate::layout::u64_at(&raw, 16)? == raw.len() as u64 - 64
                && raw[24..56] == sha(&raw[64..]),
            "actual framed locator length/hash differs",
        )?;
        let loc: Value = serde_json::from_slice(&raw[64..]).map_err(io::Error::other)?;
        need(
            (match data_profile {
                PartitionDataProfile::PrivateVolumeV2 => {
                    num_field(&loc, "schema_version")? == 2
                        && str_field(&loc, "kind")? == "resource-partition-recovery-locator-v2"
                }
                PartitionDataProfile::BasicReadonlyPhysicalV3 => {
                    num_field(&loc, "schema_version")? == 3
                        && str_field(&loc, "kind")?
                            == "resource-partition-readonly-physical-recovery-locator-v3"
                }
            }) && loc["source_scope"] == scope,
            "locator/publication source scope differs",
        )?;
        let ticket = &loc["ticket"];
        need(
            loc["source"] == serde_json::to_value(&binding.storage).map_err(io::Error::other)?
                && loc["journal_binding"]
                    == serde_json::to_value(pins.journal_binding).map_err(io::Error::other)?
                && num_field(ticket, "image_length")? == binding.storage.identity.partition_bytes
                && ticket
                    .get("old_restored_selected_sha256")
                    .cloned()
                    .unwrap_or(Value::Null)
                    == serde_json::to_value(pins.old_restored_selected_sha256)
                        .map_err(io::Error::other)?,
            "locator source/journal/restored-OLD lineage differs",
        )?;
        need(
            json_bytes(&ticket["immutable_sha256"])? == pins.immutable_sha256
                && json_bytes(&ticket["old_selected_sha256"])? == pins.old_selected_sha256
                && json_bytes(&ticket["new_selected_sha256"])? == pins.new_selected_sha256,
            "published ticket differs from actual closed-J pins",
        )?;
        need(
            loc["journal_identity"]
                == serde_json::to_value(pins.journal_identity).map_err(io::Error::other)?,
            "actual journal identity differs from locator",
        )?;
        let pin = &scope["complete_preparation_guard"];
        need(
            match data_profile {
                PartitionDataProfile::PrivateVolumeV2 => {
                    num_field(pin, "version")? == 1
                        && str_field(pin, "kind")? == "partition-target-only-preparation-v1"
                        && str_field(pin, "observed_stage")? == "PrivateLocked"
                }
                PartitionDataProfile::BasicReadonlyPhysicalV3 => {
                    num_field(pin, "version")? == 2
                        && str_field(pin, "kind")? == "partition-readonly-physical-preparation-v2"
                        && str_field(pin, "observed_stage")? == "ReadonlyPhysicalLocked"
                }
            },
            "original preparation protocol differs",
        )?;
        let ip = &pin["intent_file"];
        let intent_snapshot = crate::reference_file::ReferenceFileSnapshot {
            final_path: str_field(ip, "final_path")?.into(),
            volume_serial_number: num_field(ip, "volume_serial_number")?,
            file_id_128: json_bytes(&ip["file_id_128"])?
                .try_into()
                .map_err(|_| bad("intent file ID length differs"))?,
            file_bytes: num_field(ip, "file_bytes")?,
            allocation_bytes: num_field(ip, "allocation_bytes")?,
            file_attributes: u32::try_from(num_field(ip, "file_attributes")?)
                .map_err(io::Error::other)?,
            number_of_links: u32::try_from(num_field(ip, "number_of_links")?)
                .map_err(io::Error::other)?,
        };
        let reopened_intent = matches!(&intent_input, IntentInput::Reopened(_));
        let mut intent = match intent_input {
            IntentInput::Reopened(file) => Artifact::hold(
                file,
                digest(pin, "intent_prefix_sha256")?,
                MAX_INTENT,
                binding,
                windows,
                true,
            )?,
            IntentInput::Live { file, pin: actual } => {
                need(
                    serde_json::to_value(&actual).map_err(io::Error::other)? == *pin,
                    "published preparation pin differs from consumed actual live guard",
                )?;
                Artifact::adopt_held(
                    file,
                    digest(pin, "intent_prefix_sha256")?,
                    MAX_INTENT,
                    binding,
                    windows,
                    true,
                )?
            }
        };
        // NTFS may trim allocation slack on last close. Reopening the SAME
        // authenticated ordinary file can therefore have less allocation than
        // the live publication recorded. Its identity, EOF, attributes, links
        // and complete content must still match; live-owner adoption stays exact.
        let mut expected_intent = intent_snapshot.clone();
        if reopened_intent
            && intent.snapshot.file_attributes & 0x0a00 == 0
            && intent.snapshot.allocation_bytes >= intent.snapshot.file_bytes
            && intent.snapshot.allocation_bytes <= intent_snapshot.allocation_bytes
        {
            expected_intent.allocation_bytes = intent.snapshot.allocation_bytes;
        }
        need(
            intent.snapshot == expected_intent,
            "actual held preparation intent identity differs",
        )?;
        let mut consumed = 0;
        let mut sequence = 0;
        let mut latest = None;
        intent.file.seek(SeekFrom::Start(0))?;
        while consumed < intent.snapshot.file_bytes {
            let mut len = [0; 8];
            let mut expected = [0; 32];
            intent.file.read_exact(&mut len)?;
            intent.file.read_exact(&mut expected)?;
            let n = u64::from_le_bytes(len);
            need(
                n > 0
                    && n <= MAX_JSON
                    && n.checked_mul(32).is_some_and(|n| n <= budget.ram_bytes)
                    && consumed + 40 + n <= intent.snapshot.file_bytes,
                "preparation frame exceeds bounds",
            )?;
            let mut body = vec![0; n as usize];
            intent.file.read_exact(&mut body)?;
            need(sha(&body) == expected, "preparation frame digest differs")?;
            let frame: Value = serde_json::from_slice(&body).map_err(io::Error::other)?;
            sequence += 1;
            need(
                sequence <= 4
                    && num_field(&frame, "sequence")? == sequence
                    && (match (data_profile, sequence) {
                        (PartitionDataProfile::BasicReadonlyPhysicalV3, 2) => {
                            num_field(&frame, "version")? == 2
                                && str_field(&frame, "kind")?
                                    == "partition-readonly-physical-pre-AP-intent-v2"
                        }
                        _ => {
                            num_field(&frame, "version")? == 1
                                && str_field(&frame, "kind")?
                                    == "partition-target-only-pre-AP-intent"
                        }
                    }),
                "preparation frame protocol differs",
            )?;
            latest = Some(frame);
            consumed += 40 + n;
        }
        let frame = latest.ok_or_else(|| bad("preparation intent has no actual frame"))?;
        need(
            sequence == num_field(pin, "sequence")? && frame["binding"] == scope["binding"],
            "preparation sequence/source binding differs",
        )?;
        let original_info = json_bytes(&frame["original_partition_info"])?;
        need(
            original_info == json_bytes(&pin["original_partition_info"])?
                && original_info.len() == 144
                && original_info[32..48] == crate::layout::guid_bytes(BASIC)?
                && crate::layout::u64_at(&original_info, 64)? == 0,
            "authenticated original Basic0 native info differs",
        )?;
        let desired = json_bytes(&frame["desired_partition_info"])?;
        need(
            match data_profile {
                PartitionDataProfile::PrivateVolumeV2 => {
                    desired.len() == 144
                        && desired[32..48] == crate::layout::guid_bytes(PRIVATE)?
                        && crate::layout::u64_at(&desired, 64)? == 0
                }
                PartitionDataProfile::BasicReadonlyPhysicalV3 => {
                    desired == protected_info(&original_info, data_profile)? && sequence == 2
                }
            },
            "last authenticated intent does not target the exact protected profile",
        )?;
        if data_profile == PartitionDataProfile::BasicReadonlyPhysicalV3 {
            need(
                str_field(&scope, "readonly_type_guid")?.eq_ignore_ascii_case(BASIC)
                    && num_field(&scope, "readonly_attributes")? == RO
                    && str_field(&scope, "original_basic_type_guid")?.eq_ignore_ascii_case(BASIC)
                    && num_field(&scope, "original_attributes")? == 0
                    && json_bytes(&scope["original_name_utf16le"])? == original_info[72..144],
                "physical source scope does not preserve original Basic0/native name",
            )?;
        }
        let original_gpt = frame["original_gpt"].clone();
        let original_mbr = json_bytes(&frame["original_mbr"])?;
        need(
            original_mbr.len() == 512 && sha(&original_mbr) == digest(pin, "original_mbr_sha256")?,
            "original MBR pin differs",
        )?;
        let np = &scope["native_metadata"];
        let native_sha = digest(np, "sha256")?;
        let nb: crate::observation_pages::NativeObservationBudget =
            serde_json::from_value(np["budget"].clone()).map_err(io::Error::other)?;
        nb.validate()?;
        let (native_file, native_pages) = match native_input {
            NativeInput::Reopened(file) => {
                let held = Artifact::hold(
                    file,
                    native_sha,
                    num_field(np, "bytes")?,
                    binding,
                    windows,
                    false,
                )?;
                need(
                    held.snapshot.file_bytes == num_field(np, "bytes")?,
                    "actual native metadata length differs",
                )?;
                let pages = crate::observation_pages::PagedNativeObservation::open(
                    std::path::Path::new(&held.snapshot.final_path),
                    &hex::encode(native_sha),
                    nb,
                )?;
                (Some(held), pages)
            }
            NativeInput::Live(native) => {
                let pages = native.into_terminal_domain();
                pages.revalidate()?;
                need(
                    pages.sha256() == str_field(np, "sha256")?
                        && pages.final_path() == str_field(np, "path")?
                        && pages.byte_len() == num_field(np, "bytes")?
                        && pages.budget() == nb,
                    "published native metadata pin differs from actual transferred domain",
                )?;
                (None, pages)
            }
        };
        let request = &native_pages.header().request;
        need(
            request.disk_number == binding.storage.disk_number
                && request.partition_offset == binding.storage.identity.partition_offset
                && request.partition_length == binding.storage.identity.partition_bytes
                && request.source_inspection_sha256
                    == str_field(&envelope, "source_inspection_sha256")?,
            "authenticated native metadata source request differs",
        )?;
        let original_label: crate::volume_label::VolumeLabel =
            serde_json::from_value(envelope["expected_source_label"].clone())
                .map_err(io::Error::other)?;
        original_label.validate()?;
        let mount_paths: Vec<String> =
            serde_json::from_value(envelope["expected_mount_paths"].clone())
                .map_err(io::Error::other)?;
        need(
            mount_paths.len() <= 128,
            "original mount-path count exceeds bound",
        )?;
        intent.file.seek(SeekFrom::Start(0))?;
        let original_primary = digest(pin, "ntfs_primary_sha256")?;
        Ok(Self {
            data_profile,
            scope,
            original_info,
            original_gpt,
            original_mbr,
            original_primary,
            original_label,
            mount_paths,
            publication,
            locator,
            intent,
            native_file,
            native_pages,
        })
    }
    fn revalidate(&mut self) -> io::Result<()> {
        self.publication.revalidate()?;
        self.locator.revalidate()?;
        self.intent.revalidate()?;
        if let Some(file) = self.native_file.as_mut() {
            file.revalidate()?;
        }
        self.native_pages.revalidate()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum PartitionTerminalStage {
    Private,
    ProtectedPhysical,
    Readonly,
    Restored,
    Poisoned,
}
#[derive(Debug, Serialize)]
pub struct PartitionRestorationReceipt {
    pub kind: &'static str,
    pub binding: PartitionSourceBinding,
    pub source_type_restored: bool,
    pub original_attributes_restored: bool,
    pub label_restored: bool,
    pub mount_paths_restored: bool,
    pub journal_raw_replay_closed: bool,
    pub source_payload_write_calls: u64,
}
pub trait PartitionRestorationObserver {
    /// Durably preserve and drain each bounded metadata attempt. Clearing
    /// without preservation, or silently retaining128 events, is not success.
    fn checkpoint_native_events(
        &mut self,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()>;
    /// Persist this real before-change observation durably outside the target.
    /// The SDK still retains/authenticates actual closed-J and intent owners.
    fn before_partition_change(
        &mut self,
        kind: PartitionTerminalKind,
        current: &[u8],
        desired: &[u8],
    ) -> io::Result<()>;
}
pub struct PartitionTerminalRestorationGuard<'journal, 'pins> {
    file: Option<File>,
    data_profile: PartitionDataProfile,
    physical_data: Option<PartitionPhysicalDataOwner>,
    physical: File,
    binding: PartitionSourceBinding,
    budget: PartitionObservationBudget,
    baseline: TerminalMetadataBaseline,
    token: PartitionOwnerToken,
    origin: Origin,
    closed: PartitionClosedJournalObservation,
    policy: &'journal HeldPagedWritePolicy,
    journal: &'journal mut File,
    pins: super::paged_recovery::PagedRecoveryPins<'pins>,
    kind: PartitionTerminalKind,
    stage: PartitionTerminalStage,
    current_info: Vec<u8>,
    mounted_binding: crate::general_layout::GeneralDiskBinding,
    mounted: Option<File>,
}
impl PartitionTerminalRestorationGuard<'static, 'static> {
    /// Actual fresh-HND transfer. The closure is scoped to the owned journal,
    /// index and captured pins; none of their borrows can escape as T. Intent
    /// and native page owners are consumed from admission, never reopened.
    pub fn with_fresh_handoff<T>(
        mut owner: PartitionScopedOwner,
        admission: super::partition_lifecycle::PartitionNtfsAdmission,
        handoff: PartitionHandoffWitness,
        files: PartitionLivePublicationFiles,
        published_sha256: [u8; 32],
        events: &mut Vec<NativeEvent>,
        consume: impl for<'journal, 'pins> FnOnce(
            PartitionTerminalRestorationGuard<'journal, 'pins>,
            &mut Vec<NativeEvent>,
        ) -> io::Result<T>,
    ) -> io::Result<T> {
        handoff.require_owner(&owner.owner_token())?;
        let journal_owners = handoff.into_terminal_journal_owners(&mut owner, events)?;
        let preparation = admission.into_terminal_preparation_owners(&mut owner, events)?;
        let parts = owner.into_terminal_restoration_parts(&journal_owners.closed, events)?;
        let PartitionLiveJournalOwners {
            closed,
            mut journal,
            policy,
            pins: owned_pins,
        } = journal_owners;
        let pins = owned_pins.pins();
        let PartitionLivePreparationOwners {
            intent,
            native,
            pin,
            label,
            mount_paths,
        } = preparation;
        let origin = Origin::authenticate_owned(
            files.publication,
            files.locator,
            IntentInput::Live { file: intent, pin },
            NativeInput::Live(native),
            published_sha256,
            &parts.binding,
            parts.budget,
            &parts.state.partition.windows_volume,
            &pins,
        )?;
        need(
            origin.original_label == label && origin.mount_paths == mount_paths.paths,
            "publication label/mounts differ from consumed actual preparation guard",
        )?;
        need(
            origin.data_profile == parts.data_profile,
            "terminal scope and consumed owner profile differ",
        )?;
        let current_info = protected_info(&origin.original_info, parts.data_profile)?;
        let mut guard = PartitionTerminalRestorationGuard {
            file: Some(parts.file),
            data_profile: parts.data_profile,
            physical_data: parts.physical_data,
            physical: parts.physical_readonly,
            binding: parts.binding.clone(),
            budget: parts.budget,
            baseline: parts.state.into(),
            token: parts.token,
            origin,
            closed,
            policy: &policy,
            journal: &mut journal,
            pins,
            kind: PartitionTerminalKind::Handoff,
            stage: if parts.data_profile == PartitionDataProfile::BasicReadonlyPhysicalV3 {
                PartitionTerminalStage::ProtectedPhysical
            } else {
                PartitionTerminalStage::Private
            },
            current_info,
            mounted_binding: parts.binding.storage,
            mounted: None,
        };
        guard.revalidate_metadata(events)?;
        guard.revalidate_closed(events)?;
        consume(guard, events)
    }
}
impl<'journal, 'pins> PartitionTerminalRestorationGuard<'journal, 'pins> {
    pub fn open_authenticated(
        mut owner: PartitionScopedOwner,
        policy: &'journal HeldPagedWritePolicy,
        journal: &'journal mut File,
        pins: super::paged_recovery::PagedRecoveryPins<'pins>,
        kind: PartitionTerminalKind,
        files: PartitionRestartFiles,
        published_sha256: [u8; 32],
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<Self> {
        let closed = authenticate_partition_closed_journal(
            &mut owner, policy, journal, &pins, kind, events,
        )?;
        let parts = owner.into_terminal_restoration_parts(&closed, events)?;
        let origin = Origin::authenticate(
            files,
            published_sha256,
            &parts.binding,
            parts.budget,
            &parts.state.partition.windows_volume,
            &pins,
        )?;
        need(
            origin.data_profile == parts.data_profile,
            "terminal scope and consumed owner profile differ",
        )?;
        let current_info = protected_info(&origin.original_info, parts.data_profile)?;
        let mut guard = Self {
            file: Some(parts.file),
            data_profile: parts.data_profile,
            physical_data: parts.physical_data,
            physical: parts.physical_readonly,
            binding: parts.binding.clone(),
            budget: parts.budget,
            baseline: parts.state.into(),
            token: parts.token,
            origin,
            closed,
            policy,
            journal,
            pins,
            kind,
            stage: if parts.data_profile == PartitionDataProfile::BasicReadonlyPhysicalV3 {
                PartitionTerminalStage::ProtectedPhysical
            } else {
                PartitionTerminalStage::Private
            },
            current_info,
            mounted_binding: parts.binding.storage,
            mounted: None,
        };
        guard.revalidate_metadata(events)?;
        guard.revalidate_closed(events)?;
        Ok(guard)
    }
    pub fn stage(&self) -> PartitionTerminalStage {
        self.stage
    }
    pub fn owner_token(&self) -> PartitionOwnerToken {
        self.token.clone()
    }
    pub fn closed_journal_observation(&self) -> &PartitionClosedJournalObservation {
        &self.closed
    }
    pub fn original_label(&self) -> &crate::volume_label::VolumeLabel {
        &self.origin.original_label
    }
    /// Consume actual readonly ReFS fidelity, then restore only this target's
    /// original attributes/label/mounts. Closed HND never becomes raw replay.
    pub fn finish(
        mut self,
        native: super::PartitionTerminalNativeObservation,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionRestorationReceipt> {
        need(
            self.kind == PartitionTerminalKind::Handoff
                && self.stage == PartitionTerminalStage::Readonly,
            "HND finish requires actual terminal readonly stage",
        )?;
        self.require_readonly(events)?;
        native.require_owner(&self.token, &self.mounted_binding)?;
        need(
            native.filesystem() == "ReFS",
            "HND native fidelity is not ReFS",
        )?;
        let current = terminal_volume_info(
            self.mounted
                .as_ref()
                .ok_or_else(|| bad("readonly target absent"))?,
        )?;
        need(
            current.filesystem == "ReFS"
                && current.label == *native.observed_label()
                && current.flags & 0x80000 != 0,
            "HND readonly filesystem/label changed after actual fidelity",
        )?;
        self.finish_checked("ReFS", observer, events)
    }
    /// ABT restores the previously admitted NTFS. Actual closed-J OLD/COPY/
    /// source-free authentication plus NTFS identity/label and protection are
    /// required; a deserialized aborted flag cannot call this constructor.
    pub fn finish_aborted(
        mut self,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionRestorationReceipt> {
        need(
            self.kind == PartitionTerminalKind::Aborted
                && self.stage == PartitionTerminalStage::Readonly,
            "ABT finish requires actual terminal readonly stage",
        )?;
        self.require_readonly(events)?;
        self.revalidate_closed_checkpoint(observer, "terminal-abt-closed-source", events)?;
        let volume = self
            .mounted
            .as_ref()
            .ok_or_else(|| bad("readonly rollback target absent"))?;
        let current = terminal_volume_info(volume)?;
        let ntfs = control(
            volume,
            "terminal-abort-NTFS-identity",
            0x0009_0064,
            &[],
            128,
            events,
        )?;
        need(
            current.filesystem == "NTFS"
                && current.label == self.origin.original_label
                && current.flags & 0x80000 != 0
                && ntfs.len() >= 96
                && crate::layout::u64_at(&ntfs, 0)?
                    == self.origin.native_pages.header().request.ntfs_serial
                && sha(&physical_read(
                    &self.binding,
                    self.binding.storage.identity.partition_offset,
                    512,
                )?) == self.origin.original_primary,
            "ABT readonly NTFS identity/label/primary differs from authenticated original",
        )?;
        self.finish_checked("NTFS", observer, events)
    }
    fn finish_checked(
        &mut self,
        filesystem: &'static str,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionRestorationReceipt> {
        self.revalidate_metadata_checkpoint(observer, "terminal-finish-metadata-1", events)?;
        self.require_readonly(events)?;
        self.revalidate_closed_checkpoint(observer, "terminal-finish-closed-source", events)?;
        // Check every path before enabling writes; never steal another volume's
        // letter or replace a nonempty/unrelated mounted folder.
        preflight_mounts(
            &self.origin.mount_paths,
            &self.mounted_binding,
            &self.current_info,
        )?;
        drop(self.mounted.take());
        self.change(
            crate::layout::u64_at(&self.origin.original_info, 64)?,
            observer,
            events,
        )?;
        let (binding, volume) = self.wait_for_terminal_volume(observer, events)?;
        self.mounted_binding = binding;
        self.mounted = Some(volume);
        let before = terminal_volume_info(self.mounted.as_ref().unwrap())?;
        need(
            before.filesystem == filesystem && before.flags & 0x80000 == 0,
            "terminal writable filesystem is not the verified target",
        )?;
        if before.label != self.origin.original_label {
            self.revalidate_metadata_checkpoint(observer, "terminal-finish-metadata-2", events)?;
            let root = wide_terminal(&format!("{}\\", self.mounted_binding.volume_path()?));
            let label = self.origin.original_label.terminated()?;
            // SAFETY: exact freshly revalidated target GUID, bounded original
            // label from authenticated publication. No physical payload write.
            if unsafe {
                windows_sys::Win32::Storage::FileSystem::SetVolumeLabelW(
                    root.as_ptr(),
                    label.as_ptr(),
                )
            } == 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        let after = terminal_volume_info(self.mounted.as_ref().unwrap())?;
        need(
            after.filesystem == filesystem
                && after.label == self.origin.original_label
                && after.flags & 0x80000 == 0,
            "terminal source label readback differs",
        )?;
        restore_terminal_mounts(
            &self.origin.mount_paths,
            &self.mounted_binding,
            &self.current_info,
        )?;
        self.revalidate_metadata_checkpoint(observer, "terminal-finish-metadata-3", events)?;
        need(
            self.current_info == self.origin.original_info,
            "terminal original native type/attrs/name not restored",
        )?;
        self.origin.revalidate()?;
        self.stage = PartitionTerminalStage::Restored;
        Ok(PartitionRestorationReceipt {
            kind: if self.kind == PartitionTerminalKind::Handoff {
                "Handoff"
            } else {
                "Aborted"
            },
            binding: PartitionSourceBinding {
                storage: self.mounted_binding.clone(),
            },
            source_type_restored: true,
            original_attributes_restored: true,
            label_restored: true,
            mount_paths_restored: true,
            journal_raw_replay_closed: true,
            source_payload_write_calls: 0,
        })
    }
    /// No saved no-AP flag or primary512 digest proves complete original NTFS
    /// after process death. This terminal guard never issues pre-AP cancel.
    pub fn cancel_pre_ap(&mut self) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "pre-AP restart cancellation requires a complete authenticated raw/native fingerprint; terminal guard cannot issue it",
        ))
    }
    fn expected_layout(
        &self,
        observed: &partition_isolation::PartitionIsolationObservation,
    ) -> io::Result<()> {
        validate_origin_layout(&self.origin, &self.binding, &self.current_info, observed)
    }
    fn observe(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<partition_isolation::PartitionIsolationObservation> {
        let mut physical = device_file(
            &format!("\\\\.\\PhysicalDrive{}", self.binding.storage.disk_number),
            false,
            false,
        )?;
        if self.data_profile == PartitionDataProfile::BasicReadonlyPhysicalV3 {
            partition_isolation::observe_physical_only(
                &mut physical,
                &PartitionSourceBinding {
                    storage: self.mounted_binding.clone(),
                },
                self.budget,
                events,
                crate::layout::guid_bytes(BASIC)?,
            )
        } else if self.current_info[32..48] == crate::layout::guid_bytes(PRIVATE)? {
            partition_isolation::observe_private(&mut physical, &self.binding, self.budget, events)
        } else {
            // Namespace absence/appearance is not an isolation witness. The
            // caller compares all complete GPT/C/critical fields separately.
            partition_isolation::observe_basic(
                &mut physical,
                &PartitionSourceBinding {
                    storage: self.mounted_binding.clone(),
                },
                self.budget,
                events,
            )
        }
    }
    // Stream the real native records between complete metadata bookends.
    // The observer must durably retain and drain them on both result paths.
    fn revalidate_metadata_checkpoint(
        &self,
        observer: &mut impl PartitionRestorationObserver,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<partition_isolation::PartitionIsolationObservation> {
        publication_checkpoint(Ok(()), observer, "terminal-metadata-before", events)?;
        let result = self.revalidate_metadata(events);
        publication_checkpoint(result, observer, phase, events)
    }
    fn revalidate_metadata(
        &self,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<partition_isolation::PartitionIsolationObservation> {
        let actual = self.observe(events)?;
        self.expected_layout(&actual)?;
        need(
            actual.disk_attributes == 0
                && actual.disk_device == self.baseline.partition.disk_device
                && actual.disk_length == self.baseline.partition.disk_length
                && actual.alignment == self.baseline.partition.alignment
                && actual.windows_volume == self.baseline.partition.windows_volume
                && actual.paging == self.baseline.partition.paging,
            "terminal physical/C/pagefile identity changed",
        )?;
        need(
            physical_read(&self.binding, 0, 512)? == self.origin.original_mbr,
            "terminal protective MBR changed",
        )?;
        let dumps = partition_dump_locations::observe_configured_dump_locations(
            &self.binding,
            self.budget,
            events,
        )?;
        let roles = super::partition_storage_roles::observe_partition_storage_roles(
            &self.binding,
            self.budget,
            events,
        )?;
        let critical_unchanged = roles.catalog_complete
            && roles.same_critical_roles(&self.baseline.storage_current_partition_roles);
        need(
            dumps == self.baseline.configured_dump_locations && critical_unchanged,
            "terminal critical-volume bindings changed",
        )?;
        if let Some(file) = &self.file {
            let info = control(
                file,
                "terminal-current-partition-info",
                0x0007_0048,
                &[],
                144,
                events,
            )?;
            need(
                info == self.current_info,
                "held terminal partition information changed",
            )?;
        }
        Ok(actual)
    }
    fn revalidate_closed_checkpoint(
        &mut self,
        observer: &mut impl PartitionRestorationObserver,
        phase: &'static str,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        publication_checkpoint(Ok(()), observer, "terminal-closed-source-opening", events)?;
        let result = self.revalidate_closed(events);
        publication_checkpoint(result, observer, phase, events)
    }
    fn revalidate_closed(&mut self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.origin.revalidate()?;
        let file = if let Some(data) = self.physical_data.as_ref() {
            data.revalidate_native(events)?;
            TerminalReadBacking::Held(data.duplicate_readonly(events)?)
        } else if let Some(original) = self.file.as_ref() {
            // The original FS lock admits access only through this SAME
            // FileObject. A reduced data duplicate shares its cursor mutex;
            // reopening the selected pathname can fail ERROR_NOT_READY21.
            need(
                events.len() <= 122,
                "terminal held source duplicate event budget exhausted",
            )?;
            TerminalReadBacking::Held(super::partition_lifecycle::held_read::duplicate_bound(
                original,
                &self.binding,
                &self.current_info,
                &self.token,
                events,
            )?)
        } else {
            // Original locking objects have closed before mounted BasicRO.
            // This independent readonly route keeps the existing unlocked lane.
            TerminalReadBacking::Independent(
                OpenOptions::new()
                    .read(true)
                    .share_mode(3)
                    .custom_flags(0xa000_0000)
                    .open(format!(
                        "\\\\?\\GLOBALROOT\\Device\\Harddisk{}\\Partition{}",
                        self.binding.storage.disk_number,
                        self.binding.storage.identity.partition_number
                    ))?,
            )
        };
        let mut reader = TerminalRawReader {
            file,
            buffer: AlignedBuffer::new()?,
            position: 0,
            length: self.binding.storage.identity.partition_bytes,
        };
        self.closed.revalidate_reader(
            &mut reader,
            self.binding.storage.identity.partition_bytes,
            &self.binding,
            &self.token,
            self.policy,
            self.journal,
            &self.pins,
        )
    }
    fn wait_for_terminal_volume(
        &mut self,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<(crate::general_layout::GeneralDiskBinding, File)> {
        let started = std::time::Instant::now();
        let bound = std::time::Duration::from_millis(60 * 250);
        for attempt in 0..60 {
            publication_checkpoint(
                Ok(()),
                observer,
                "terminal-volume-publication-before",
                events,
            )?;
            let before = self.revalidate_metadata(events).map(|_| ());
            publication_checkpoint(
                before,
                observer,
                "terminal-volume-publication-critical-before",
                events,
            )?;
            let found = find_terminal_volume(
                &self.binding,
                &self.current_info,
                self.budget,
                observer,
                events,
            );
            match found {
                Ok((binding, volume)) => {
                    self.mounted_binding = binding.clone();
                    let closing = (|| {
                        self.revalidate_metadata(events)?;
                        let info = control(
                            &volume,
                            "terminal-published-partition-closing",
                            0x0007_0048,
                            &[],
                            144,
                            events,
                        )?;
                        need(
                            info == self.current_info,
                            "published target native identity changed at closing bookend",
                        )
                    })();
                    publication_checkpoint(
                        closing,
                        observer,
                        "terminal-volume-publication-matched",
                        events,
                    )?;
                    return Ok((binding, volume));
                }
                Err(error)
                    if error.kind() == io::ErrorKind::NotFound
                        && error
                            .get_ref()
                            .is_some_and(|inner| inner.is::<NoTerminalTargetYet>()) =>
                {
                    let closing = self.revalidate_metadata(events).map(|_| ());
                    publication_checkpoint(
                        closing,
                        observer,
                        "terminal-volume-publication-not-yet",
                        events,
                    )?;
                    if attempt == 59 || started.elapsed() >= bound {
                        return Err(io::Error::new(
                            io::ErrorKind::NotFound,
                            "actual terminal volume was not published within bounded metadata wait",
                        ));
                    }
                    let remaining = bound.saturating_sub(started.elapsed());
                    std::thread::sleep(std::time::Duration::from_millis(250).min(remaining));
                }
                Err(error) => {
                    // Identity/malformed/unknown errors are not retried. Keep
                    // their actual native records before preserving the error.
                    return publication_checkpoint(
                        Err(error),
                        observer,
                        "terminal-volume-publication-hard-error",
                        events,
                    );
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "terminal publication metadata attempt bound exhausted",
        ))
    }
    fn change(
        &mut self,
        attrs: u64,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        publication_checkpoint(Ok(()), observer, "terminal-partition-change-before", events)?;
        let result = self.change_checked(attrs, observer, events);
        publication_checkpoint(
            result,
            observer,
            "terminal-partition-change-complete",
            events,
        )
    }
    fn change_checked(
        &mut self,
        attrs: u64,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        self.revalidate_metadata_checkpoint(observer, "terminal-change-metadata-1", events)?;
        self.origin.revalidate()?;
        let mut desired = self.origin.original_info.clone();
        desired[64..72].copy_from_slice(&attrs.to_le_bytes());
        observer.before_partition_change(self.kind, &self.current_info, &desired)?;
        self.revalidate_metadata_checkpoint(observer, "terminal-change-metadata-2", events)?;
        let route = format!(
            "\\\\?\\GLOBALROOT\\Device\\Harddisk{}\\Partition{}",
            self.binding.storage.disk_number, self.binding.storage.identity.partition_number
        );
        let management = if let Some(file) = self.file.take() {
            file
        } else {
            OpenOptions::new()
                .read(true)
                .write(true)
                .share_mode(3)
                .open(route)?
        };
        let actual = control(
            &management,
            "terminal-management-partition-info",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        need(
            actual == self.current_info,
            "terminal management file names another partition/state",
        )?;
        let mut input = [0u8; 120];
        input[..4].copy_from_slice(&1u32.to_le_bytes());
        input[8..120].copy_from_slice(&desired[32..144]);
        self.stage = PartitionTerminalStage::Poisoned;
        let reply = control_set_gpt_partition(
            &management,
            "terminal-SET_PARTITION_INFO_EX-once",
            &input,
            events,
        )?;
        need(reply.is_empty(), "terminal setter returned unexpected data")?;
        self.current_info = desired;
        self.file = Some(management);
        self.revalidate_metadata_checkpoint(observer, "terminal-change-metadata-3", events)?;
        Ok(())
    }
    pub fn enter_readonly(
        &mut self,
        observer: &mut impl PartitionRestorationObserver,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<()> {
        need(
            self.stage == PartitionTerminalStage::Private
                || self.stage == PartitionTerminalStage::ProtectedPhysical,
            "terminal readonly transition is one-shot",
        )?;
        self.revalidate_closed_checkpoint(
            observer,
            "terminal-before-readonly-closed-source",
            events,
        )?;
        if self.data_profile == PartitionDataProfile::BasicReadonlyPhysicalV3 {
            need(
                self.stage == PartitionTerminalStage::ProtectedPhysical
                    && self.current_info
                        == protected_info(&self.origin.original_info, self.data_profile)?,
                "physical terminal has not retained exact positive BasicRO",
            )?;
            self.revalidate_metadata_checkpoint(
                observer,
                "terminal-existing-physical-basic-ro",
                events,
            )?;
            // BASIC+RO already persists. No redundant type/attribute setter.
        } else {
            self.change(RO, observer, events)?;
        }
        // Persistent target-only RO precedes closing the old NTFS FileObject.
        // All root capture duplicates must also close before native publication.
        drop(self.file.take());
        let (binding, volume) = self.wait_for_terminal_volume(observer, events)?;
        self.mounted_binding = binding;
        self.mounted = Some(volume);
        self.stage = PartitionTerminalStage::Readonly;
        self.revalidate_metadata(events)?;
        self.require_readonly(events)?;
        self.revalidate_closed_checkpoint(
            observer,
            "terminal-after-readonly-closed-source",
            events,
        )?;
        Ok(())
    }
    pub fn readonly_volume(
        &self,
    ) -> io::Result<PartitionTerminalReadonlyVolume<'_, 'journal, 'pins>> {
        need(
            self.stage == PartitionTerminalStage::Readonly && self.mounted.is_some(),
            "actual terminal readonly volume unavailable",
        )?;
        Ok(PartitionTerminalReadonlyVolume { guard: self })
    }
    fn require_readonly(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        need(
            self.current_info[32..48] == crate::layout::guid_bytes(BASIC)?
                && crate::layout::u64_at(&self.current_info, 64)? == RO,
            "terminal target lost exact BasicRO",
        )?;
        let volume = self
            .mounted
            .as_ref()
            .ok_or_else(|| bad("actual mounted terminal volume absent"))?;
        let ext = control(
            volume,
            "terminal-readonly-volume-extents",
            VOLUME_EXTENTS,
            &[],
            32,
            events,
        )?;
        self.mounted_binding.validate_volume_extent(&ext)?;
        let info = control(
            volume,
            "terminal-readonly-partition-info",
            0x0007_0048,
            &[],
            144,
            events,
        )?;
        need(
            info == self.current_info,
            "terminal mounted partition information differs",
        )?;
        let at = events.len();
        let result = control(
            volume,
            "terminal-readonly-IS_WRITABLE",
            0x0007_0024,
            &[],
            0,
            events,
        );
        need(
            result.is_err()
                && events
                    .get(at)
                    .is_some_and(|event| !event.succeeded && event.native_error == Some(19)),
            "terminal volume must report actual WRITE_PROTECT19",
        )
    }
}

pub struct PartitionTerminalReadonlyVolume<'guard, 'journal, 'pins> {
    guard: &'guard PartitionTerminalRestorationGuard<'journal, 'pins>,
}
impl PartitionTerminalReadonlyVolume<'_, '_, '_> {
    pub fn binding(&self) -> &crate::general_layout::GeneralDiskBinding {
        &self.guard.mounted_binding
    }
    pub fn volume(&self) -> &File {
        self.guard
            .mounted
            .as_ref()
            .expect("capability requires actual mounted volume")
    }
    pub fn owner_token(&self) -> PartitionOwnerToken {
        self.guard.token.clone()
    }
    pub fn require_readonly(&self, events: &mut Vec<NativeEvent>) -> io::Result<()> {
        self.guard.revalidate_metadata(events)?;
        self.guard.require_readonly(events)
    }
    pub fn snapshot(
        &self,
        binding: &crate::layout::DiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionSnapshot> {
        need(
            binding.disk_number == self.binding().disk_number
                && binding.volume_guid == self.binding().volume_guid
                && binding.identity == self.binding().identity,
            "terminal native snapshot binding differs",
        )?;
        let observed = self.guard.revalidate_metadata(events)?;
        self.guard.require_readonly(events)?;
        Ok(PartitionSnapshot {
            binding: binding.clone(),
            disk_attributes: observed.disk_attributes,
            device: observed.disk_device,
            length: observed.disk_length,
            alignment: observed.alignment,
            layout: observed.gpt.native_layout,
        })
    }
}
impl super::ProtectedReadonlyRefsAccess for PartitionTerminalReadonlyVolume<'_, '_, '_> {
    fn binding(&self) -> &crate::general_layout::GeneralDiskBinding {
        self.binding()
    }
    fn volume(&self) -> &File {
        self.volume()
    }
    fn scope(&self) -> super::ReadonlyRefsScope {
        super::ReadonlyRefsScope::SelectedPartition
    }
    fn snapshot(
        &self,
        binding: &crate::layout::DiskBinding,
        events: &mut Vec<NativeEvent>,
    ) -> io::Result<PartitionSnapshot> {
        self.snapshot(binding, events)
    }
    fn partition_owner_token(&self) -> Option<&PartitionOwnerToken> {
        Some(&self.guard.token)
    }
}
pub(in crate::native) struct TerminalRawReader {
    file: TerminalReadBacking,
    buffer: AlignedBuffer,
    position: u64,
    length: u64,
}
enum TerminalReadBacking {
    Held(super::partition_lifecycle::held_read::HeldSourceRead),
    Independent(File),
}
impl Seek for TerminalRawReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let at = match from {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.position) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.length) + i128::from(n),
        };
        need(
            at >= 0 && at <= i128::from(self.length),
            "terminal raw seek leaves target",
        )?;
        self.position = at as u64;
        Ok(self.position)
    }
}
impl Read for TerminalRawReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() || self.position == self.length {
            return Ok(0);
        }
        let lead = (self.position % 4096) as usize;
        let count = (out.len().min(MAX_IO - lead) as u64).min(self.length - self.position) as usize;
        let n = (lead + count).div_ceil(4096) * 4096;
        let at = self.position - lead as u64;
        need(at + n as u64 <= self.length, "terminal read leaves target")?;
        let got = match &mut self.file {
            TerminalReadBacking::Held(source) => {
                source.read_at(at, &mut self.buffer.bytes_mut()[..n])?
            }
            TerminalReadBacking::Independent(file) => {
                file.seek(SeekFrom::Start(at))?;
                file.read(&mut self.buffer.bytes_mut()[..n])?
            }
        };
        need(got >= lead + count, "short terminal raw read")?;
        out[..count].copy_from_slice(&self.buffer.bytes_mut()[lead..lead + count]);
        self.position += count as u64;
        Ok(count)
    }
}

fn candidate_volume(
    name: &str,
    source: &PartitionSourceBinding,
    expected: &[u8],
    events: &mut Vec<NativeEvent>,
) -> io::Result<Option<(crate::general_layout::GeneralDiskBinding, File)>> {
    if !name.starts_with(r"\\?\Volume{") || !name.ends_with("}\\") {
        return Err(bad("volume enumeration returned malformed local GUID"));
    }
    crate::layout::guid_bytes(&name[11..name.len() - 2])?;
    let volume = match device_file(name.trim_end_matches('\\'), false, false) {
        Ok(file) => file,
        Err(error) if matches!(error.raw_os_error(), Some(2 | 3 | 21 | 1167)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let event_start = events.len();
    let ext = match control(
        &volume,
        "terminal-candidate-extents",
        VOLUME_EXTENTS,
        &[],
        32,
        events,
    ) {
        Ok(bytes) => bytes,
        Err(_)
            if events.get(event_start).is_some_and(|event| {
                !event.succeeded && matches!(event.native_error, Some(2 | 3 | 21 | 1167))
            }) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    };
    need(
        ext.len() == 32 && crate::layout::u32_at(&ext, 0)? == 1,
        "terminal candidate extent reply is malformed or not a complete single extent",
    )?;
    if crate::layout::u32_at(&ext, 8)? != source.storage.disk_number
        || crate::layout::u64_at(&ext, 16)? != source.storage.identity.partition_offset
        || crate::layout::u64_at(&ext, 24)? != source.storage.identity.partition_bytes
    {
        return Ok(None);
    }
    let info = control(
        &volume,
        "terminal-candidate-partition-info",
        0x0007_0048,
        &[],
        144,
        events,
    )?;
    need(
        info == expected,
        "matched terminal volume changed native target identity",
    )?;
    let mut binding = source.storage.clone();
    binding.volume_guid = name[11..name.len() - 2].to_owned();
    binding.validate()?;
    Ok(Some((binding, volume)))
}

fn wide_terminal(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(Some(0)).collect()
}
pub(in crate::native) struct TerminalVolumeInfo {
    pub(in crate::native) label: crate::volume_label::VolumeLabel,
    pub(in crate::native) filesystem: String,
    pub(in crate::native) flags: u32,
}
pub(in crate::native) fn terminal_volume_info(file: &File) -> io::Result<TerminalVolumeInfo> {
    use std::os::windows::io::AsRawHandle;
    let mut label = [0u16; 33];
    let mut filesystem = [0u16; 32];
    let (mut serial, mut component, mut flags) = (0, 0, 0);
    // SAFETY: actual held target volume and bounded initialized output arrays.
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            label.as_mut_ptr(),
            label.len() as u32,
            &mut serial,
            &mut component,
            &mut flags,
            filesystem.as_mut_ptr(),
            filesystem.len() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let n = label
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| bad("terminal label unterminated"))?;
    let label = crate::volume_label::VolumeLabel::from_utf16(label[..n].to_vec())?;
    let n = filesystem
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| bad("terminal filesystem name unterminated"))?;
    let filesystem = String::from_utf16(&filesystem[..n]).map_err(io::Error::other)?;
    Ok(TerminalVolumeInfo {
        label,
        filesystem,
        flags,
    })
}
fn validate_terminal_mount_path(path: &str) -> io::Result<()> {
    let b = path.as_bytes();
    need(
        b.len() >= 3
            && b[0].is_ascii_alphabetic()
            && b[1] == b':'
            && b[2] == b'\\'
            && path.ends_with('\\')
            && path.encode_utf16().count() < 32768
            && !path.contains('\0'),
        "unsupported original local mount path",
    )?;
    if path.len() == 3 {
        return Ok(());
    }
    for part in path[3..path.len() - 1]
        .split('\\')
        .filter(|p| !p.is_empty())
    {
        need(
            !matches!(part, "." | "..")
                && !part.ends_with([' ', '.'])
                && !part
                    .chars()
                    .any(|c| c.is_control() || "<>:\"/|?*".contains(c)),
            "ambiguous original mount component",
        )?;
    }
    Ok(())
}
fn mount_owner(path: &str) -> io::Result<Option<String>> {
    let input = wide_terminal(path);
    let mut name = [0u16; 64];
    // SAFETY: bounded validated mount path and fixed GUID output.
    if unsafe {
        windows_sys::Win32::Storage::FileSystem::GetVolumeNameForVolumeMountPointW(
            input.as_ptr(),
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        let error = io::Error::last_os_error();
        if matches!(error.raw_os_error(), Some(2 | 3 | 87)) {
            return Ok(None);
        }
        return Err(error);
    }
    let n = name
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| bad("mount-owner GUID unterminated"))?;
    Ok(Some(
        String::from_utf16(&name[..n]).map_err(io::Error::other)?,
    ))
}
fn is_target_mount(
    name: &str,
    binding: &crate::general_layout::GeneralDiskBinding,
    info: &[u8],
) -> io::Result<bool> {
    let volume = device_file(name.trim_end_matches('\\'), false, false)?;
    let ext = control(
        &volume,
        "terminal-existing-mount-extents",
        VOLUME_EXTENTS,
        &[],
        32,
        &mut Vec::new(),
    )?;
    if ext.len() != 32
        || crate::layout::u32_at(&ext, 0)? != 1
        || crate::layout::u32_at(&ext, 8)? != binding.disk_number
        || crate::layout::u64_at(&ext, 16)? != binding.identity.partition_offset
        || crate::layout::u64_at(&ext, 24)? != binding.identity.partition_bytes
    {
        return Ok(false);
    }
    Ok(control(
        &volume,
        "terminal-existing-mount-partition-info",
        0x0007_0048,
        &[],
        144,
        &mut Vec::new(),
    )? == info)
}
pub(in crate::native) fn preflight_mounts(
    paths: &[String],
    binding: &crate::general_layout::GeneralDiskBinding,
    info: &[u8],
) -> io::Result<()> {
    use std::os::windows::fs::MetadataExt;
    need(paths.len() <= 128, "terminal mount count exceeds bound")?;
    for (i, path) in paths.iter().enumerate() {
        validate_terminal_mount_path(path)?;
        need(
            !paths[..i].iter().any(|p| p.eq_ignore_ascii_case(path)),
            "duplicate terminal mount path",
        )?;
        if let Some(name) = mount_owner(path)? {
            need(
                is_target_mount(&name, binding, info)?,
                "original mount path is occupied by another volume",
            )?;
        } else if path.len() != 3 {
            let metadata = std::fs::symlink_metadata(path)?;
            need(
                metadata.is_dir()
                    && metadata.file_attributes() & 0x400 == 0
                    && std::fs::read_dir(path)?.next().is_none(),
                "original mounted folder is missing, redirected or nonempty",
            )?;
        }
    }
    Ok(())
}
pub(in crate::native) fn restore_terminal_mounts(
    paths: &[String],
    binding: &crate::general_layout::GeneralDiskBinding,
    info: &[u8],
) -> io::Result<()> {
    preflight_mounts(paths, binding, info)?;
    for path in paths {
        if let Some(name) = mount_owner(path)? {
            need(
                is_target_mount(&name, binding, info)?,
                "mount changed during terminal restoration",
            )?;
            continue;
        }
        let p = wide_terminal(path);
        let volume = wide_terminal(&format!("{}\\", binding.volume_path()?));
        // SAFETY: original validated unoccupied path and exact actual target.
        // No delete/steal/create-folder or unrelated mount change is attempted.
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::SetVolumeMountPointW(
                p.as_ptr(),
                volume.as_ptr(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        let name = mount_owner(path)?
            .ok_or_else(|| bad("terminal mount was not observed after assignment"))?;
        need(
            is_target_mount(&name, binding, info)?,
            "terminal mount readback points elsewhere",
        )?;
    }
    Ok(())
}
pub(in crate::native) fn find_terminal_volume(
    source: &PartitionSourceBinding,
    expected: &[u8],
    budget: PartitionObservationBudget,
    observer: &mut impl PartitionRestorationObserver,
    events: &mut Vec<NativeEvent>,
) -> io::Result<(crate::general_layout::GeneralDiskBinding, File)> {
    let known = format!("{}\\", source.storage.volume_path()?);
    let candidate = candidate_volume(&known, source, expected, events);
    if let Some(found) = publication_checkpoint(
        candidate,
        observer,
        "terminal-known-volume-metadata",
        events,
    )? {
        return Ok(found);
    }
    let mut name = [0u16; 1024];
    // SAFETY: bounded initialized volume-name output, local Mount Manager query.
    let handle = unsafe {
        windows_sys::Win32::Storage::FileSystem::FindFirstVolumeW(
            name.as_mut_ptr(),
            name.len() as u32,
        )
    };
    if handle == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
        let error = io::Error::last_os_error();
        return Err(
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES as i32)
            {
                no_terminal_target_yet()
            } else {
                error
            },
        );
    }
    struct Enumeration(windows_sys::Win32::Foundation::HANDLE);
    impl Drop for Enumeration {
        fn drop(&mut self) {
            unsafe {
                windows_sys::Win32::Storage::FileSystem::FindVolumeClose(self.0);
            }
        }
    }
    let enumeration = Enumeration(handle);
    let maximum = (budget.ram_bytes / 4096).min(4096) as usize;
    for _ in 0..maximum {
        let n = name
            .iter()
            .position(|unit| *unit == 0)
            .ok_or_else(|| bad("enumerated volume name unterminated"))?;
        let path = String::from_utf16(&name[..n]).map_err(io::Error::other)?;
        let candidate = candidate_volume(&path, source, expected, events);
        if let Some(found) = publication_checkpoint(
            candidate,
            observer,
            "terminal-enumerated-volume-metadata",
            events,
        )? {
            return Ok(found);
        }
        name.fill(0);
        if unsafe {
            windows_sys::Win32::Storage::FileSystem::FindNextVolumeW(
                enumeration.0,
                name.as_mut_ptr(),
                name.len() as u32,
            )
        } == 0
        {
            let error = io::Error::last_os_error();
            if error.raw_os_error()
                == Some(windows_sys::Win32::Foundation::ERROR_NO_MORE_FILES as i32)
            {
                return Err(no_terminal_target_yet());
            }
            return Err(error);
        }
    }
    Err(bad(
        "terminal volume enumeration exceeds admitted count budget",
    ))
}

// Only a completed metadata enumeration with no target, never an unrelated
// native/observer NotFound error, authorizes another publication attempt.
#[derive(Debug)]
struct NoTerminalTargetYet;
pub(in crate::native) fn terminal_publication_pending(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::NotFound
        && error
            .get_ref()
            .is_some_and(|inner| inner.is::<NoTerminalTargetYet>())
}
impl std::fmt::Display for NoTerminalTargetYet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("no actual terminal target volume is published yet")
    }
}
impl std::error::Error for NoTerminalTargetYet {}
fn no_terminal_target_yet() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, NoTerminalTargetYet)
}

// Checkpoint every attempted bounded metadata batch, including hard failures.
// The observer must retain the actual events before clearing this live budget.
fn publication_checkpoint<T>(
    result: io::Result<T>,
    observer: &mut impl PartitionRestorationObserver,
    phase: &'static str,
    events: &mut Vec<NativeEvent>,
) -> io::Result<T> {
    let checkpoint = observer
        .checkpoint_native_events(phase, events)
        .and_then(|()| {
            need(
                events.is_empty(),
                "terminal publication checkpoint did not drain actual metadata events",
            )
        });
    match (result, checkpoint) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(checkpoint)) => Err(io::Error::new(
            error.kind(),
            format!("{error}; native event checkpoint also failed: {checkpoint}"),
        )),
    }
}

/// Private transfer, not a pathname/serialized constructor. SDK owner validates
/// actual closed-J token and current private/C/critical state before moving it.
pub(super) struct PartitionTerminalTargetParts {
    pub(super) file: File,
    pub(super) physical_readonly: File,
    pub(super) data_profile: PartitionDataProfile,
    pub(super) physical_data: Option<PartitionPhysicalDataOwner>,
    pub(super) binding: PartitionSourceBinding,
    pub(super) budget: PartitionObservationBudget,
    pub(super) state: PartitionOwnerState,
    pub(super) token: PartitionOwnerToken,
}
/// SDK-internal consuming transfers only. Neither type has a public/path/DTO
/// constructor; fields come from the actual admission and spent HND witness.
pub(super) struct PartitionLivePreparationOwners {
    pub(super) intent: File,
    pub(super) native: crate::attestation_partition::PartitionPagedNtfsObservation,
    pub(super) pin: super::partition_lifecycle::PartitionPreparationPin,
    pub(super) label: crate::volume_label::VolumeLabel,
    pub(super) mount_paths: MountPathObservation,
}
pub(super) struct PartitionLiveJournalOwners {
    pub(super) closed: PartitionClosedJournalObservation,
    pub(super) journal: File,
    pub(super) policy: HeldPagedWritePolicy,
    pub(super) pins: super::paged_recovery::OwnedPartitionJournalPins,
}
pub struct PartitionLivePublicationFiles {
    pub publication: File,
    pub locator: File,
}
enum IntentInput {
    Reopened(File),
    Live {
        file: File,
        pin: super::partition_lifecycle::PartitionPreparationPin,
    },
}
enum NativeInput {
    Reopened(File),
    Live(crate::attestation_partition::PartitionPagedNtfsObservation),
}

fn validate_origin_layout(
    origin: &Origin,
    binding: &PartitionSourceBinding,
    current_info: &[u8],
    observed: &partition_isolation::PartitionIsolationObservation,
) -> io::Result<()> {
    let g = &origin.original_gpt;
    let mut entries = json_bytes(&g["entries"])?;
    let width = num_field(g, "entry_bytes")? as usize;
    let slot = num_field(g, "target_slot")? as usize;
    let at = slot
        .checked_sub(1)
        .and_then(|s| s.checked_mul(width))
        .ok_or_else(|| bad("original target slot overflow"))?;
    need(
        width >= 128 && at.checked_add(width).is_some_and(|e| e <= entries.len()),
        "original target slot out of bounds",
    )?;
    let original_entries = entries.clone();
    let primary = json_bytes(&g["primary_header"])?;
    let backup = json_bytes(&g["backup_header"])?;
    let original_native = json_bytes(&g["native_layout"])?;
    let mut full = Sha256::new();
    full.update(&primary);
    full.update(&original_entries);
    full.update(&backup);
    full.update(&original_native);
    need(
        <[u8; 32]>::from(full.finalize())
            == digest(
                &origin.scope["complete_preparation_guard"],
                "original_gpt_sha256",
            )?,
        "original complete GPT pin differs",
    )?;
    entries[at..at + 16].copy_from_slice(&current_info[32..48]);
    entries[at + 48..at + 56].copy_from_slice(&current_info[64..72]);
    let mut native = original_native;
    let guid = crate::layout::guid_bytes(&binding.storage.identity.partition_guid)?;
    let offsets: Vec<usize> = (48..native.len())
        .step_by(144)
        .filter(|a| *a + 144 <= native.len() && native[*a + 48..*a + 64] == guid)
        .collect();
    need(offsets.len() == 1, "original native target is not unique")?;
    native[offsets[0]..offsets[0] + 144].copy_from_slice(&current_info);
    let actual = &observed.gpt;
    need(
        actual.entries == entries
            && actual.primary_header == header(&primary, &entries)?
            && actual.backup_header == header(&backup, &entries)?
            && actual.native_layout == native
            && actual.primary_crc_valid
            && actual.backup_crc_valid
            && actual.entry_arrays_equal,
        "terminal GPT/siblings/unused entries changed beyond target type/attrs and required CRCs",
    )
}
