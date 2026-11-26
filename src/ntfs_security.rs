//! Raw NTFS security data, index and relative-descriptor reconciliation.
//! No access check, native security attestation or write authority is implied.
use crate::{
    ntfs_index::{self, Input, Profile},
    ntfs_inspect::FileInventory,
};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_METADATA_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DESCRIPTOR_BYTES: usize = 0x40000 - 20;
pub const MAX_TOTAL_DESCRIPTOR_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_DESCRIPTORS: usize = 16_384;
pub const MAX_TOTAL_ACES: usize = 65_536;
const HALF: usize = 0x40000;
const PAIR: usize = 0x80000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    ConsistentRawModel,
    Rejected,
    IncompleteAttributeInventory,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reconciliation {
    pub status: Status,
    pub metadata_bytes_read: usize,
    pub central_descriptors: usize,
    pub legacy_descriptors: usize,
    pub sii_entries: usize,
    pub sdh_entries: usize,
    pub index_blocks: usize,
    pub bound_files: usize,
    pub evidence_sha256: String,
    pub detail: String,
    pub descriptors: Vec<DescriptorRecord>,
    pub bindings: Vec<Binding>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Binding {
    pub record_number: u64,
    pub sequence_number: u16,
    pub security_id: Option<u32>,
    pub descriptor_sha256: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DescriptorRecord {
    pub security_id: Option<u32>,
    pub legacy_record: Option<u64>,
    pub sds_offset: Option<u64>,
    pub ntfs_hash: Option<u32>,
    pub descriptor: Descriptor,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Descriptor {
    pub sha256: String,
    pub relative_hex: String,
    pub control: u16,
    pub rm_control: u8,
    pub minimum_length: usize,
    pub owner_sid: Option<String>,
    pub group_sid: Option<String>,
    pub dacl: Acl,
    pub sacl: Acl,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AclState {
    Absent,
    Null,
    Present,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Acl {
    pub state: AclState,
    pub offset: usize,
    pub length: usize,
    pub revision: Option<u8>,
    pub aces: Vec<Ace>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Ace {
    pub ace_type: u8,
    pub flags: u8,
    pub offset: usize,
    pub length: usize,
    pub mask: u32,
    pub trustee_sid: String,
    pub object_flags: Option<u32>,
    pub object_type: Option<String>,
    pub inherited_object_type: Option<String>,
    pub application_data_offset: Option<usize>,
    pub application_data_length: usize,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Header {
    pub hash: u32,
    pub id: u32,
    pub offset: u64,
    pub length: u32,
}

#[cfg(windows)]
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PagedReconciliationPin {
    pub schema_version: u32,
    pub central: crate::ntfs_inspect::record_store::RecordStorePin,
    pub legacy: crate::ntfs_inspect::record_store::RecordStorePin,
    pub bindings: crate::ntfs_inspect::record_store::RecordStorePin,
    pub central_descriptors: u64,
    pub legacy_descriptors: u64,
    pub bound_files: u64,
    pub sii_entries: u64,
    pub sdh_entries: u64,
    pub index_blocks: u64,
    pub descriptor_bytes: u64,
    pub aces: u64,
    pub evidence_sha256: String,
}

/// Complete immutable raw-security facts, not source or native authority.
#[cfg(windows)]
pub struct PagedReconciliation {
    central: crate::ntfs_inspect::record_store::SortedRecordStore,
    legacy: crate::ntfs_inspect::record_store::SortedRecordStore,
    bindings: crate::ntfs_inspect::record_store::SortedRecordStore,
    pin: PagedReconciliationPin,
}

fn identity_key(number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}

#[cfg(windows)]
impl PagedReconciliation {
    /// Reopen immutable security metadata. This supplies no source provenance;
    /// the cold inspection issuer separately requires SDK byte continuity.
    pub(crate) fn open_cached(
        pin: &PagedReconciliationPin,
        scratch: &crate::ntfs_inspect::paged_storage::SourceScratch,
    ) -> Result<Self> {
        use crate::ntfs_inspect::record_store::SortedRecordStore;
        ensure!(pin.schema_version == 1, "unknown cached security schema");
        let value = Self {
            central: SortedRecordStore::open(&pin.central, scratch)?,
            legacy: SortedRecordStore::open(&pin.legacy, scratch)?,
            bindings: SortedRecordStore::open(&pin.bindings, scratch)?,
            pin: pin.clone(),
        };
        ensure!(
            value.central.len() == pin.central_descriptors
                && value.legacy.len() == pin.legacy_descriptors
                && value.bindings.len() == pin.bound_files
                && pin.sii_entries == pin.central_descriptors
                && pin.sdh_entries == pin.central_descriptors,
            "cached security count/index closure differs"
        );
        let mut bytes = 0u64;
        let mut aces = 0u64;
        for ordinal in 0..value.descriptor_count() {
            let record = value.descriptor(ordinal)?;
            let raw = hex::decode(&record.descriptor.relative_hex)?;
            let parsed = parse_descriptor_with_limit(&raw, scratch.budget().record_bytes)?;
            ensure!(
                serde_json::to_vec(&parsed)? == serde_json::to_vec(&record.descriptor)?,
                "cached security descriptor parsed facts differ"
            );
            if ordinal < value.central.len() {
                let header = descriptor_header(&record)?;
                ensure!(
                    record.legacy_record.is_none()
                        && value.central.key(ordinal)? == identity_key(u64::from(header.id))
                        && ntfs_hash(&raw)? == header.hash,
                    "cached central security identity/hash differs"
                );
            } else {
                let number = record
                    .legacy_record
                    .context("cached legacy identity absent")?;
                ensure!(
                    record.security_id.is_none()
                        && value.legacy.key(ordinal - value.central.len())? == identity_key(number),
                    "cached legacy security identity differs"
                );
            }
            bytes = bytes
                .checked_add(raw.len() as u64)
                .context("cached descriptor byte overflow")?;
            aces = aces
                .checked_add((parsed.dacl.aces.len() + parsed.sacl.aces.len()) as u64)
                .context("cached descriptor ACE overflow")?;
        }
        ensure!(
            bytes == pin.descriptor_bytes && aces == pin.aces,
            "cached security byte/ACE totals differ"
        );
        const MAX_SECURITY_CACHE: usize = 4096;
        let mut central_sha_cache: std::collections::HashMap<u32, String> =
            std::collections::HashMap::new();
        for ordinal in 0..value.bindings.len() {
            let binding = value.binding(ordinal)?;
            let descriptor_sha256 = if let Some(id) = binding.security_id {
                if let Some(cached) = central_sha_cache.get(&id) {
                    cached.as_str()
                } else {
                    let sha = value
                        .find_id(id)?
                        .context("cached security binding descriptor absent")?
                        .descriptor
                        .sha256;
                    if central_sha_cache.len() < MAX_SECURITY_CACHE {
                        central_sha_cache.insert(id, sha);
                        central_sha_cache.get(&id).unwrap().as_str()
                    } else {
                        ensure!(
                            binding.sequence_number != 0
                                && value.bindings.key(ordinal)?
                                    == identity_key(binding.record_number)
                                && sha == binding.descriptor_sha256,
                            "cached security binding identity/digest differs"
                        );
                        continue;
                    }
                }
            } else {
                let sha = value
                    .find_legacy(binding.record_number)?
                    .context("cached security binding descriptor absent")?
                    .descriptor
                    .sha256;
                ensure!(
                    binding.sequence_number != 0
                        && value.bindings.key(ordinal)? == identity_key(binding.record_number)
                        && sha == binding.descriptor_sha256,
                    "cached security binding identity/digest differs"
                );
                continue;
            };
            ensure!(
                binding.sequence_number != 0
                    && value.bindings.key(ordinal)? == identity_key(binding.record_number)
                    && descriptor_sha256 == binding.descriptor_sha256,
                "cached security binding identity/digest differs"
            );
        }
        value.revalidate()?;
        Ok(value)
    }
    pub fn pin(&self) -> &PagedReconciliationPin {
        &self.pin
    }
    pub fn descriptor_count(&self) -> u64 {
        self.pin.central_descriptors + self.pin.legacy_descriptors
    }
    pub fn descriptor(&self, ordinal: u64) -> Result<DescriptorRecord> {
        if ordinal < self.central.len() {
            self.central.get(ordinal)
        } else {
            self.legacy.get(
                ordinal
                    .checked_sub(self.central.len())
                    .context("security ordinal underflow")?,
            )
        }
    }
    pub fn find_id(&self, id: u32) -> Result<Option<DescriptorRecord>> {
        self.central.find(identity_key(u64::from(id)))
    }
    pub fn find_legacy(&self, number: u64) -> Result<Option<DescriptorRecord>> {
        self.legacy.find(identity_key(number))
    }
    pub fn binding(&self, ordinal: u64) -> Result<Binding> {
        self.bindings.get(ordinal)
    }
    pub fn find_binding(&self, number: u64) -> Result<Option<Binding>> {
        self.bindings.find(identity_key(number))
    }
    pub fn revalidate(&self) -> Result<()> {
        self.central.revalidate()?;
        self.legacy.revalidate()?;
        self.bindings.revalidate()?;
        Ok(())
    }
}

fn descriptor_header(record: &DescriptorRecord) -> Result<Header> {
    Ok(Header {
        hash: record.ntfs_hash.context("central descriptor hash absent")?,
        id: record.security_id.context("central descriptor ID absent")?,
        offset: record
            .sds_offset
            .context("central descriptor offset absent")?,
        length: u32::try_from(record.descriptor.relative_hex.len() / 2)?
            .checked_add(20)
            .context("descriptor header length overflow")?,
    })
}

fn descriptor_at(
    sds: &dyn crate::ntfs_inspect::source_domain::SourceMetadataRange,
    wanted: &Header,
    maximum_record_bytes: u64,
) -> Result<DescriptorRecord> {
    let length = u64::from(wanted.length);
    let within = wanted.offset % PAIR as u64;
    ensure!(
        within < HALF as u64
            && within.checked_add(length).is_some_and(|n| n <= HALF as u64)
            && length
                .checked_sub(20)
                .is_some_and(|n| n <= maximum_record_bytes),
        "indexed SDS descriptor escapes primary half or record budget"
    );
    let mirror_at = wanted
        .offset
        .checked_add(HALF as u64)
        .context("SDS mirror offset overflow")?;
    ensure!(
        mirror_at
            .checked_add(length)
            .is_some_and(|n| n <= sds.byte_len()),
        "indexed SDS mirror is absent"
    );
    let mut bytes = vec![0; usize::try_from(length)?];
    let mut mirror = vec![0; bytes.len()];
    sds.read_exact_at(wanted.offset, &mut bytes)?;
    sds.read_exact_at(mirror_at, &mut mirror)?;
    ensure!(
        header(&bytes[..20])? == *wanted && bytes == mirror,
        "indexed SDS header/mirror differs"
    );
    ensure!(
        ntfs_hash(&bytes[20..])? == wanted.hash,
        "indexed SDS content hash differs"
    );
    Ok(DescriptorRecord {
        security_id: Some(wanted.id),
        legacy_record: None,
        sds_offset: Some(wanted.offset),
        ntfs_hash: Some(wanted.hash),
        descriptor: parse_descriptor_with_limit(&bytes[20..], maximum_record_bytes)?,
    })
}

/// Reconcile the complete security graph through authenticated metadata ranges
/// and disk-resident record indexes. Nothing here opens a source device or
/// manufactures a live source/native admission capability.
#[cfg(windows)]
pub fn reconcile_paged(
    capture: &impl crate::ntfs_inspect::source_domain::RootSecurityCaptureDomain,
    files: &impl crate::ntfs_inspect::source_domain::RootFileDomain,
    base: &std::path::Path,
    scratch: &crate::ntfs_inspect::paged_storage::SourceScratch,
) -> Result<PagedReconciliation> {
    use crate::ntfs_inspect::{
        record_store::{SortedRecordStore, SortedRecordWriter},
        source_domain::SourceMetadataRange,
    };
    let budget = scratch.budget();
    budget.validate()?;
    // Account for a current source object and descriptor row together with
    // the intrinsic SDS mirror/descriptor parser windows. Page owners retain
    // their own separate leases in this same aggregate ledger.
    let transient = budget
        .record_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add((MAX_DESCRIPTOR_BYTES as u64) * 32))
        .and_then(|n| n.checked_add((2 * HALF + 65536) as u64))
        .context("security working-memory reservation overflow")?;
    let _working = scratch.lease_ram(transient)?;
    files.revalidate()?;
    capture.revalidate()?;
    ensure!(
        crate::ntfs_inspect::supports_record_geometry(&files.header().geometry)
            && ntfs_index::supports_cluster_size(files.header().geometry.cluster_size),
        "paged security indexes require supported NTFS index geometry"
    );
    let cluster = files.header().geometry.cluster_size;
    let index_record = files.header().geometry.index_record_size;
    let mut central_writer =
        SortedRecordWriter::new(&base.join("security-central"), *b"N2RSCEN1", scratch)?;
    let mut descriptor_bytes = 0u64;
    let mut aces = 0u64;
    // NTFS 1.2 has no $Secure: no central descriptors, and every file's
    // descriptor is its own, bound below like any legacy one.
    let central_present = capture.has_central();
    let (sii_entries, sdh_entries, index_blocks, sds_sha256, central_pin, central) =
        if !central_present {
            let central_pin = central_writer.finish()?;
            let central = SortedRecordStore::open(&central_pin, scratch)?;
            (
                0,
                0,
                0,
                String::from("no-central-security-table"),
                central_pin,
                central,
            )
        } else {
            let mut previous: Option<Header> = None;
            let sii = ntfs_index::paged::walk_ranges(
                capture.index(IndexKind::Id)?,
                Profile::SECURITY_ID,
                cluster,
                index_record,
                scratch,
                &base.join("security-sii.visited"),
                |_entry, key, value| {
                    let h = header(value).with_context(|| {
                        format!("$Secure:$SII entry with key {}", hex::encode(key))
                    })?;
                    ensure!(
                        key.len() == 4
                            && u32le(key, 0)? == h.id
                            && previous.as_ref().is_none_or(|prior| prior.id < h.id),
                        "SII keys duplicate, unordered or differ from their values"
                    );
                    let record = descriptor_at(capture.sds()?, &h, budget.record_bytes)?;
                    descriptor_bytes = descriptor_bytes
                        .checked_add((record.descriptor.relative_hex.len() / 2) as u64)
                        .context("security descriptor byte count overflow")?;
                    aces = aces
                        .checked_add(
                            (record.descriptor.dacl.aces.len() + record.descriptor.sacl.aces.len())
                                as u64,
                        )
                        .context("security ACE count overflow")?;
                    central_writer.push(identity_key(u64::from(h.id)), &record)?;
                    previous = Some(h);
                    Ok(())
                },
            )?;
            let central_pin = central_writer.finish()?;
            let central = SortedRecordStore::open(&central_pin, scratch)?;
            ensure!(
                sii.entries == central.len(),
                "complete SII descriptor domain differs"
            );
            let mut previous: Option<Header> = None;
            let sdh = ntfs_index::paged::walk_ranges(
                capture.index(IndexKind::Hash)?,
                Profile::SECURITY_HASH,
                cluster,
                index_record,
                scratch,
                &base.join("security-sdh.visited"),
                |_entry, key, value| {
                    let h = header(value).with_context(|| {
                        format!("$Secure:$SDH entry with key {}", hex::encode(key))
                    })?;
                    ensure!(
                        key.len() == 8
                            && u32le(key, 0)? == h.hash
                            && u32le(key, 4)? == h.id
                            && previous
                                .as_ref()
                                .is_none_or(|prior| (prior.hash, prior.id) < (h.hash, h.id)),
                        "SDH keys duplicate, unordered or differ from their values"
                    );
                    let record: DescriptorRecord = central
                        .find(identity_key(u64::from(h.id)))?
                        .context("SDH descriptor is absent from SII")?;
                    ensure!(
                        descriptor_header(&record)? == h,
                        "SDH/SII/SDS header differs"
                    );
                    previous = Some(h);
                    Ok(())
                },
            )?;
            ensure!(
                sdh.entries == central.len(),
                "complete SDH/SII descriptor sets differ"
            );
            let sds = scan_sds_range(capture.sds()?, budget, |h, _bytes| {
                let record: DescriptorRecord = central
                    .find(identity_key(u64::from(h.id)))?
                    .context("unindexed primary SDS descriptor")?;
                ensure!(
                    descriptor_header(&record)? == h,
                    "SDS primary ID/header is duplicated or differs from SII/SDH"
                );
                Ok(())
            })?;
            ensure!(
                sds.records == central.len() && sds.descriptor_bytes == descriptor_bytes,
                "complete SDS/SII/SDH record and byte domains differ"
            );
            let index_blocks = sii
                .index_blocks
                .checked_add(sdh.index_blocks)
                .context("security index block count overflow")?;
            (
                sii.entries,
                sdh.entries,
                index_blocks,
                sds.sha256,
                central_pin,
                central,
            )
        };
    let mut legacy_writer =
        SortedRecordWriter::new(&base.join("security-legacy"), *b"N2RSLEG1", scratch)?;
    for ordinal in 0..capture.legacy_count() {
        let item = capture.legacy(ordinal)?;
        ensure!(
            item.sequence_number != 0
                && item.bytes.len() as u64 <= budget.record_bytes
                && files
                    .find_record(item.record_number, Some(item.sequence_number))?
                    .is_some(),
            "legacy descriptor lacks its exact canonical MFT identity or exceeds record budget"
        );
        // Central SDS records are bounded by their on-disk half block. Legacy
        // descriptors instead belong to this admitted physical attribute row.
        // Charge any larger retained representation before decoding it.
        let _legacy_extra = scratch.lease_ram(
            (item.bytes.len() as u64)
                .saturating_sub(MAX_DESCRIPTOR_BYTES as u64)
                .checked_mul(4)
                .context("legacy security working RAM overflow")?,
        )?;
        let descriptor = parse_descriptor_with_limit(&item.bytes, budget.record_bytes)?;
        descriptor_bytes = descriptor_bytes
            .checked_add(item.bytes.len() as u64)
            .context("security descriptor byte count overflow")?;
        aces = aces
            .checked_add((descriptor.dacl.aces.len() + descriptor.sacl.aces.len()) as u64)
            .context("security ACE count overflow")?;
        let record = DescriptorRecord {
            security_id: None,
            legacy_record: Some(item.record_number),
            sds_offset: None,
            ntfs_hash: None,
            descriptor,
        };
        legacy_writer.push(identity_key(item.record_number), &record)?;
    }
    let legacy_pin = legacy_writer.finish()?;
    let legacy = SortedRecordStore::open(&legacy_pin, scratch)?;
    ensure!(
        legacy.len() == capture.legacy_count(),
        "complete legacy descriptor domain differs"
    );
    let mut binding_writer =
        SortedRecordWriter::new(&base.join("security-bindings"), *b"N2RSBND1", scratch)?;
    const MAX_SECURITY_CACHE: usize = 4096;
    let mut central_sha_cache: std::collections::HashMap<u32, String> =
        std::collections::HashMap::new();
    let has_legacy = legacy.len() > 0;
    let mut legacy_bound = 0u64;
    let mut previous = None;
    for ordinal in 0..files.file_count() {
        let file = files.file_shared(ordinal)?;
        ensure!(
            file.base_file_reference == 0
                && !file.attributes.iter().any(|a| a.type_code == 0x20)
                && file.sequence_number != 0
                && previous.is_none_or(|number| number < file.record_number),
            "unassembled, duplicate or unordered security binding identity"
        );
        previous = Some(file.record_number);
        if (12..16).contains(&file.record_number)
            && file.names.is_empty()
            && file.attributes.is_empty()
            && !file.is_directory
            && file.hard_link_count == 0
        {
            continue;
        }
        let id = file
            .standard_information
            .as_ref()
            .and_then(|si| si.security_id)
            .filter(|id| *id != 0);
        let descriptor_sha256: String = if let Some(id) = id {
            ensure!(
                !file.attributes.iter().any(|a| a.type_code == 0x50)
                    && (!has_legacy
                        || legacy
                            .find::<DescriptorRecord>(identity_key(file.record_number))?
                            .is_none()),
                "file has both central and legacy security"
            );
            if let Some(cached) = central_sha_cache.get(&id) {
                cached.clone()
            } else {
                let record: DescriptorRecord = central
                    .find(identity_key(u64::from(id)))?
                    .context("MFT security ID absent from complete SDS/index domain")?;
                if central_sha_cache.len() < MAX_SECURITY_CACHE {
                    central_sha_cache.insert(id, record.descriptor.sha256.clone());
                }
                record.descriptor.sha256
            }
        } else {
            let record: DescriptorRecord = legacy
                .find(identity_key(file.record_number))?
                .context("allocated MFT file lacks resolvable security")?;
            let mut attributes = file.attributes.iter().filter(|a| a.type_code == 0x50);
            let attribute = attributes
                .next()
                .context("legacy descriptor lacks its source attribute")?;
            ensure!(
                attributes.next().is_none()
                    && attribute.name_utf16.is_empty()
                    && attribute.flags == 0
                    && attribute.lowest_vcn == 0
                    && attribute.initialized_size == attribute.logical_size
                    && attribute.logical_size == (record.descriptor.relative_hex.len() / 2) as u64,
                "legacy descriptor/source attribute differs"
            );
            if attribute.resident {
                let bytes = hex::decode(&record.descriptor.relative_hex)?;
                ensure!(
                    attribute.resident_sha256.as_deref()
                        == Some(n2r_win32::content_digest::of(&bytes).as_str()),
                    "legacy resident descriptor hash differs"
                );
            }
            legacy_bound = legacy_bound
                .checked_add(1)
                .context("legacy binding count overflow")?;
            record.descriptor.sha256
        };
        binding_writer.push(
            identity_key(file.record_number),
            &Binding {
                record_number: file.record_number,
                sequence_number: file.sequence_number,
                security_id: id,
                descriptor_sha256,
            },
        )?;
    }
    ensure!(
        legacy_bound == legacy.len(),
        "legacy descriptor has no exact MFT binding"
    );
    let bindings_pin = binding_writer.finish()?;
    let bindings = SortedRecordStore::open(&bindings_pin, scratch)?;
    capture.revalidate()?;
    files.revalidate()?;
    let mut evidence = Sha256::new();
    evidence.update(b"ntfs2refs-paged-security-v1\0");
    evidence.update(sds_sha256.as_bytes());
    // Commit every captured index byte as well as the independently walked
    // reachable rows. Working memory stays one small fixed read window.
    let mut buffer = [0u8; 65536];
    let kinds: &[IndexKind] = if central_present {
        &[IndexKind::Id, IndexKind::Hash]
    } else {
        &[]
    };
    for &kind in kinds {
        let index = capture.index(kind)?;
        for range in [Some(index.root), index.allocation, index.bitmap]
            .into_iter()
            .flatten()
        {
            evidence.update(range.byte_len().to_le_bytes());
            let mut at = 0u64;
            while at < range.byte_len() {
                let n = (range.byte_len() - at).min(buffer.len() as u64) as usize;
                range.read_exact_at(at, &mut buffer[..n])?;
                evidence.update(&buffer[..n]);
                at += n as u64;
            }
            range.revalidate()?;
        }
    }
    for pin in [&central_pin, &legacy_pin, &bindings_pin] {
        evidence.update(pin.data.logical_sha256.as_bytes());
        evidence.update(pin.directory.logical_sha256.as_bytes());
    }
    let pin = PagedReconciliationPin {
        schema_version: 1,
        central_descriptors: central.len(),
        legacy_descriptors: legacy.len(),
        bound_files: bindings.len(),
        sii_entries,
        sdh_entries,
        index_blocks,
        descriptor_bytes,
        aces,
        evidence_sha256: hex::encode(evidence.finalize()),
        central: central_pin,
        legacy: legacy_pin,
        bindings: bindings_pin,
    };
    let result = PagedReconciliation {
        central,
        legacy,
        bindings,
        pin,
    };
    result.revalidate()?;
    Ok(result)
}
#[derive(Clone, Copy)]
pub enum IndexKind {
    Id,
    Hash,
}
pub struct SecurityIndex {
    pub entries: Vec<Header>,
    pub index_blocks: usize,
}
/// The central table ($Secure). Empty on NTFS 1.2, which has none.
#[derive(Default)]
pub struct Table {
    pub records: Vec<DescriptorRecord>,
    pub index_blocks: usize,
}

/// Complete streamed SDS facts. Counts do not constitute file/native admission.
#[derive(Clone, Debug, Serialize)]
pub struct SdsRangeSummary {
    pub records: u64,
    /// Freed slots chkdsk left (see `freed_slot`), passed over.
    pub freed_slots: u64,
    pub descriptor_bytes: u64,
    pub logical_bytes: u64,
    pub sha256: String,
}

/// Visit every primary descriptor and verify its exact mirror with two fixed
/// 256-KiB windows. Unlike the legacy slice reader, no SDS-sized allocation or
/// aggregate descriptor collection is needed. ID/index closure is caller-owned.
pub fn scan_sds_range(
    source: &dyn crate::ntfs_inspect::source_domain::SourceMetadataRange,
    budget: crate::ntfs_inspect::source_domain::SourceMetadataBudget,
    mut emit: impl FnMut(Header, &[u8]) -> Result<()>,
) -> Result<SdsRangeSummary> {
    budget.validate()?;
    ensure!(
        (2 * HALF) as u64 <= budget.ram_bytes / 4,
        "security mirror windows exceed source working-memory budget"
    );
    source.revalidate()?;
    let mut primary = vec![0u8; HALF];
    let mut mirror = vec![0u8; HALF];
    let length = source.byte_len();
    let mut base = 0u64;
    let mut records = 0u64;
    let mut freed = 0u64;
    let mut descriptor_bytes = 0u64;
    let mut digest = Sha256::new();
    while base < length {
        let first = usize::try_from((length - base).min(HALF as u64))?;
        source.read_exact_at(base, &mut primary[..first])?;
        digest.update(&primary[..first]);
        let mirror_base = base
            .checked_add(HALF as u64)
            .context("SDS mirror offset overflow")?;
        let second = usize::try_from(length.saturating_sub(mirror_base).min(HALF as u64))?;
        if second != 0 {
            source.read_exact_at(mirror_base, &mut mirror[..second])?;
            digest.update(&mirror[..second]);
        }
        let mut at = 0usize;
        while at.checked_add(20).is_some_and(|end| end <= first) {
            if primary[at..at + 20].iter().all(|byte| *byte == 0) {
                break;
            }
            if let Some(n) = freed_slot(&primary[at..first]) {
                ensure!(
                    at.checked_add(n).is_some_and(|end| end <= second)
                        && primary[at..at + n] == mirror[at..at + n],
                    "$Secure:$SDS freed slot at byte {} differs from its mirror",
                    base + at as u64
                );
                freed = freed
                    .checked_add(1)
                    .context("SDS freed slot count overflow")?;
                at = at
                    .checked_add(n)
                    .and_then(|n| n.checked_add(15))
                    .context("SDS record alignment overflow")?
                    & !15;
                continue;
            }
            let h = header(&primary[at..at + 20])
                .with_context(|| format!("$Secure:$SDS record at byte {}", base + at as u64))?;
            let n = usize::try_from(h.length)?;
            ensure!(
                h.offset == base + at as u64 && n <= first - at,
                "SDS header position/record boundary differs"
            );
            ensure!(
                at.checked_add(n).is_some_and(|end| end <= second),
                "missing SDS mirror record"
            );
            ensure!(
                primary[at..at + n] == mirror[at..at + n],
                "SDS primary/mirror mismatch"
            );
            let bytes = &primary[at + 20..at + n];
            ensure!(
                bytes.len() as u64 <= budget.record_bytes,
                "security descriptor exceeds pinned record budget"
            );
            ensure!(ntfs_hash(bytes)? == h.hash, "SDS descriptor hash mismatch");
            records = records
                .checked_add(1)
                .context("SDS descriptor count overflow")?;
            descriptor_bytes = descriptor_bytes
                .checked_add(bytes.len() as u64)
                .context("SDS descriptor byte count overflow")?;
            emit(h, bytes)?;
            at = at
                .checked_add(n)
                .and_then(|n| n.checked_add(15))
                .context("SDS record alignment overflow")?
                & !15;
        }
        ensure!(
            primary[at.min(first)..first].iter().all(|byte| *byte == 0),
            "unparsed nonzero SDS primary tail"
        );
        ensure!(
            mirror[at.min(second)..second].iter().all(|byte| *byte == 0),
            "unparsed nonzero SDS mirror tail"
        );
        base = base
            .checked_add(PAIR as u64)
            .context("SDS pair offset overflow")?;
    }
    source.revalidate()?;
    Ok(SdsRangeSummary {
        records,
        freed_slots: freed,
        descriptor_bytes,
        logical_bytes: length,
        sha256: hex::encode(digest.finalize()),
    })
}

fn u16le(b: &[u8], at: usize) -> Result<u16> {
    Ok(u16::from_le_bytes(
        b.get(at..at + 2)
            .context("truncated security u16")?
            .try_into()?,
    ))
}
fn u32le(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .context("truncated security u32")?
            .try_into()?,
    ))
}
fn u64le(b: &[u8], at: usize) -> Result<u64> {
    Ok(u64::from_le_bytes(
        b.get(at..at + 8)
            .context("truncated security u64")?
            .try_into()?,
    ))
}
pub fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub fn ntfs_hash(bytes: &[u8]) -> Result<u32> {
    ensure!(
        bytes.len().is_multiple_of(4),
        "unaligned NTFS security hash input"
    );
    Ok(bytes.as_chunks::<4>().0.iter().fold(0u32, |h, w| {
        h.rotate_left(3).wrapping_add(u32::from_le_bytes(*w))
    }))
}
/// The length of a freed `$SDS` slot at the start of `bytes`, or `None`
/// where there is none. chkdsk leaves one where it dropped a descriptor
/// (lab n12-chkdsk-6, at byte 496 between IDs 259 and 261): a header of
/// hash 0, security ID 0 and offset 0 that keeps only its length, and
/// zeros where the descriptor was. No $SII or $SDH entry can name it (their
/// IDs are 256 and up), so NTFS never reads it; it is passed over, its
/// length kept so the records after it stay where they are. Anything else
/// with ID 0, or a nonzero byte in it, is not one.
fn freed_slot(bytes: &[u8]) -> Option<usize> {
    let header = bytes.get(..20)?;
    if header[..16].iter().any(|byte| *byte != 0) {
        return None;
    }
    let length = usize::try_from(u32::from_le_bytes(header[16..20].try_into().ok()?)).ok()?;
    ((40..=HALF).contains(&length)
        && bytes
            .get(20..length)
            .is_some_and(|rest| rest.iter().all(|byte| *byte == 0)))
    .then_some(length)
}

fn header(bytes: &[u8]) -> Result<Header> {
    ensure!(bytes.len() == 20, "exact 20-byte security header required");
    let h = Header {
        hash: u32le(bytes, 0)?,
        id: u32le(bytes, 4)?,
        offset: u64le(bytes, 8)?,
        length: u32le(bytes, 16)?,
    };
    ensure!(
        h.id >= 256 && h.offset.is_multiple_of(16) && h.length >= 40 && h.length <= HALF as u32,
        "invalid security header identity/offset/length: security ID {} (at least 256), offset {} (a multiple of 16), length {} (40 to {HALF}); header bytes {}",
        h.id,
        h.offset,
        h.length,
        hex::encode(bytes)
    );
    Ok(h)
}
pub fn parse_index(input: Input<'_>, kind: IndexKind) -> Result<SecurityIndex> {
    parse_index_with_cluster_size(input, kind, 4096)
}

/// As [`parse_index_with_geometry`], with the 4 KiB index records Windows
/// formats.
pub fn parse_index_with_cluster_size(
    input: Input<'_>,
    kind: IndexKind,
    cluster_bytes: u32,
) -> Result<SecurityIndex> {
    parse_index_with_geometry(
        input,
        kind,
        cluster_bytes,
        ntfs_index::DEFAULT_INDEX_RECORD_BYTES,
    )
}

/// Security indexes for the volume's cluster and index record sizes.
pub fn parse_index_with_geometry(
    input: Input<'_>,
    kind: IndexKind,
    cluster_bytes: u32,
    index_record_bytes: u32,
) -> Result<SecurityIndex> {
    let profile = match kind {
        IndexKind::Id => Profile::SECURITY_ID,
        IndexKind::Hash => Profile::SECURITY_HASH,
    };
    let index = ntfs_index::parse_with_geometry(
        input,
        profile,
        cluster_bytes,
        index_record_bytes,
        |_entry, key, value| {
            let h = header(value)
                .with_context(|| format!("$Secure index entry with key {}", hex::encode(key)))?;
            match kind {
                IndexKind::Id => ensure!(
                    key.len() == 4 && u32le(key, 0)? == h.id,
                    "SII key/value identity mismatch"
                ),
                IndexKind::Hash => ensure!(
                    key.len() == 8 && u32le(key, 0)? == h.hash && u32le(key, 4)? == h.id,
                    "SDH key/value mismatch"
                ),
            }
            Ok(h)
        },
    )?;
    for pair in index.entries.windows(2) {
        let ordered = match kind {
            IndexKind::Id => pair[0].id < pair[1].id,
            IndexKind::Hash => (pair[0].hash, pair[0].id) < (pair[1].hash, pair[1].id),
        };
        ensure!(ordered, "security index keys unordered or duplicated");
    }
    Ok(SecurityIndex {
        entries: index.entries,
        index_blocks: index.index_blocks,
    })
}

fn sid(bytes: &[u8], offset: usize) -> Result<(String, usize)> {
    let prefix = bytes
        .get(offset..offset + 8)
        .context("truncated SID header")?;
    ensure!(
        prefix[0] == 1 && prefix[1] <= 15,
        "unsupported SID revision/subauthority count"
    );
    let length = 8 + 4 * usize::from(prefix[1]);
    let data = bytes
        .get(offset..offset + length)
        .context("SID exceeds descriptor/ACE")?;
    let authority = prefix[2..8]
        .iter()
        .fold(0u64, |a, v| (a << 8) | u64::from(*v));
    let mut text = if authority <= u64::from(u32::MAX) {
        format!("S-1-{authority}")
    } else {
        format!("S-1-0x{authority:012x}")
    };
    for w in data[8..].as_chunks::<4>().0 {
        text.push_str(&format!("-{}", u32::from_le_bytes(*w)));
    }
    Ok((text, length))
}
fn guid(bytes: &[u8]) -> Result<String> {
    ensure!(bytes.len() == 16, "GUID length differs");
    Ok(format!(
        "{:08x}-{:04x}-{:04x}-{:02x}{:02x}-{}",
        u32le(bytes, 0)?,
        u16le(bytes, 4)?,
        u16le(bytes, 6)?,
        bytes[8],
        bytes[9],
        hex::encode(&bytes[10..])
    ))
}
fn acl(bytes: &[u8], offset: usize, present: bool) -> Result<Acl> {
    if !present {
        ensure!(offset == 0, "absent ACL has a nonzero offset");
        return Ok(Acl {
            state: AclState::Absent,
            offset: 0,
            length: 0,
            revision: None,
            aces: Vec::new(),
        });
    }
    if offset == 0 {
        return Ok(Acl {
            state: AclState::Null,
            offset: 0,
            length: 0,
            revision: None,
            aces: Vec::new(),
        });
    }
    ensure!(
        offset >= 20 && offset.is_multiple_of(4),
        "invalid ACL relative offset"
    );
    let revision = *bytes.get(offset).context("ACL header outside descriptor")?;
    ensure!(
        [2, 4].contains(&revision)
            && bytes.get(offset + 1) == Some(&0)
            && u16le(bytes, offset + 6)? == 0,
        "invalid ACL revision/reserved fields"
    );
    let length = usize::from(u16le(bytes, offset + 2)?);
    let count = usize::from(u16le(bytes, offset + 4)?);
    ensure!(
        length >= 8 && length.is_multiple_of(4) && count <= (length - 8) / 16,
        "invalid ACL size/ACE count"
    );
    let data = bytes
        .get(offset..offset + length)
        .context("ACL exceeds descriptor")?;
    let mut at = 8;
    let mut aces = Vec::new();
    for _ in 0..count {
        let prefix = data.get(at..at + 8).context("short ACE header/mask")?;
        let n = usize::from(u16le(prefix, 2)?);
        ensure!(n >= 16 && n.is_multiple_of(4), "invalid ACE length");
        let entry = data.get(at..at + n).context("ACE exceeds ACL")?;
        let ty = entry[0];
        let object = matches!(ty, 5..=8 | 11 | 12 | 15 | 16);
        let application = matches!(ty, 9..=16 | 18 | 21);
        ensure!(matches!(ty,0..=3|5..=21), "unsupported ACE type {ty}");
        let mut sid_at = 8;
        let mut object_flags = None;
        let mut object_type = None;
        let mut inherited_object_type = None;
        if object {
            ensure!(revision == 4, "object ACE requires ACL revision 4");
            let flags = u32le(entry, 8)?;
            ensure!(flags & !3 == 0, "unknown object ACE flags");
            object_flags = Some(flags);
            sid_at = 12;
            if flags & 1 != 0 {
                object_type = Some(guid(
                    entry
                        .get(sid_at..sid_at + 16)
                        .context("truncated object GUID")?,
                )?);
                sid_at += 16;
            }
            if flags & 2 != 0 {
                inherited_object_type = Some(guid(
                    entry
                        .get(sid_at..sid_at + 16)
                        .context("truncated inherited GUID")?,
                )?);
                sid_at += 16;
            }
        }
        let (trustee_sid, sid_length) = sid(entry, sid_at)?;
        let end = sid_at + sid_length;
        ensure!(
            application || end == entry.len(),
            "ordinary ACE has trailing data"
        );
        let application_data_length = entry.len() - end;
        aces.push(Ace {
            ace_type: ty,
            flags: entry[1],
            offset: offset + at,
            length: n,
            mask: u32le(entry, 4)?,
            trustee_sid,
            object_flags,
            object_type,
            inherited_object_type,
            application_data_offset: if application_data_length > 0 {
                Some(offset + at + end)
            } else {
                None
            },
            application_data_length,
        });
        at += n;
    }
    // `at` may stop short of `length`. That is not a malformed ACL: Windows
    // defines AclSize as covering "the ACL structure, all the ACEs, and the
    // potential unused memory" and reports the remainder as AclBytesFree
    // (ACL_SIZE_INFORMATION). The whole declared length is kept and hashed
    // with the descriptor, so no byte of it is hidden from any comparison.
    Ok(Acl {
        state: AclState::Present,
        offset,
        length,
        revision: Some(revision),
        aces,
    })
}

/// Preserves all relative bytes and ordered ACEs. Conditional/resource ACE
/// application data is retained by offset, not evaluated or normalized.
pub fn parse_descriptor(bytes: &[u8]) -> Result<Descriptor> {
    parse_descriptor_with_limit(bytes, MAX_DESCRIPTOR_BYTES as u64)
}

/// Parse one complete relative descriptor under the owning metadata row's
/// admitted byte window. SDS callers separately enforce primary/mirror framing;
/// ACL/ACE/SID offsets, lengths, order and exact relative bytes remain unchanged.
pub fn parse_descriptor_with_limit(bytes: &[u8], maximum_bytes: u64) -> Result<Descriptor> {
    ensure!(
        bytes.len() >= 20 && bytes.len() as u64 <= maximum_bytes && bytes.len().is_multiple_of(4),
        "security descriptor size bound differs"
    );
    ensure!(bytes[0] == 1, "unsupported security descriptor revision");
    let control = u16le(bytes, 2)?;
    ensure!(
        control & 0x8000 != 0 && (control & 0x4000 != 0 || bytes[1] == 0),
        "descriptor is not valid relative form/RM control"
    );
    let mut minimum_length = 20;
    let mut read_sid = |at: usize| -> Result<Option<String>> {
        let offset = u32le(bytes, at)? as usize;
        if offset == 0 {
            return Ok(None);
        }
        ensure!(
            offset >= 20 && offset.is_multiple_of(4),
            "invalid SID relative offset"
        );
        let (text, n) = sid(bytes, offset)?;
        minimum_length = minimum_length.max(offset + n);
        Ok(Some(text))
    };
    let owner_sid = read_sid(4)?;
    let group_sid = read_sid(8)?;
    let sacl = acl(bytes, u32le(bytes, 12)? as usize, control & 0x10 != 0)?;
    let dacl = acl(bytes, u32le(bytes, 16)? as usize, control & 4 != 0)?;
    minimum_length = minimum_length
        .max(sacl.offset + sacl.length)
        .max(dacl.offset + dacl.length);
    Ok(Descriptor {
        sha256: hash(bytes),
        relative_hex: hex::encode(bytes),
        control,
        rm_control: bytes[1],
        minimum_length,
        owner_sid,
        group_sid,
        dacl,
        sacl,
    })
}

fn sds_records(bytes: &[u8]) -> Result<BTreeMap<u32, (Header, &[u8])>> {
    ensure!(bytes.len() <= MAX_METADATA_BYTES, "SDS read limit exceeded");
    let mut records = BTreeMap::new();
    let mut descriptor_bytes = 0usize;
    for base in (0..bytes.len()).step_by(PAIR) {
        let end = (base + HALF).min(bytes.len());
        let mut at = base;
        while at + 20 <= end {
            if bytes[at..at + 20].iter().all(|v| *v == 0) {
                break;
            }
            if let Some(n) = freed_slot(&bytes[at..end]) {
                let duplicate = at + HALF;
                ensure!(
                    duplicate + n <= bytes.len()
                        && bytes[at..at + n] == bytes[duplicate..duplicate + n],
                    "$Secure:$SDS freed slot at byte {at} differs from its mirror"
                );
                at = (at + n + 15) & !15;
                continue;
            }
            let h = header(&bytes[at..at + 20])
                .with_context(|| format!("$Secure:$SDS record at byte {at}"))?;
            let n = h.length as usize;
            ensure!(
                h.offset == at as u64 && n <= end - at,
                "SDS header position/record boundary differs"
            );
            let duplicate = at + HALF;
            ensure!(duplicate + n <= bytes.len(), "missing SDS mirror record");
            ensure!(
                bytes[at..at + n] == bytes[duplicate..duplicate + n],
                "SDS primary/mirror mismatch"
            );
            let data = &bytes[at + 20..at + n];
            ensure!(ntfs_hash(data)? == h.hash, "SDS descriptor hash mismatch");
            descriptor_bytes += data.len();
            ensure!(
                descriptor_bytes <= MAX_TOTAL_DESCRIPTOR_BYTES && records.len() < MAX_DESCRIPTORS,
                "security descriptor count/byte budget exceeded"
            );
            ensure!(
                records.insert(h.id, (h, data)).is_none(),
                "duplicate primary SDS security ID"
            );
            at = (at + n + 15) & !15;
        }
        ensure!(
            bytes[at.min(end)..end].iter().all(|v| *v == 0),
            "unparsed nonzero SDS primary tail"
        );
        let backup_tail = (at + HALF).min(bytes.len());
        let backup_end = (base + PAIR).min(bytes.len());
        ensure!(
            bytes[backup_tail.min(backup_end)..backup_end]
                .iter()
                .all(|v| *v == 0),
            "unparsed nonzero SDS mirror tail"
        );
    }
    Ok(records)
}

pub fn reconcile_table(sds: &[u8], sii: &SecurityIndex, sdh: &SecurityIndex) -> Result<Table> {
    let records = sds_records(sds)?;
    ensure!(
        sii.entries.len() == records.len() && sdh.entries.len() == records.len(),
        "SDS/SII/SDH descriptor counts differ"
    );
    for index in [sii, sdh] {
        let mut ids = BTreeSet::new();
        for h in &index.entries {
            ensure!(ids.insert(h.id), "security index repeats a descriptor ID");
            ensure!(
                records.get(&h.id).is_some_and(|r| r.0 == *h),
                "SDS/index security header mismatch"
            );
        }
    }
    let mut result = Vec::new();
    let mut aces = 0usize;
    for (id, (h, data)) in records {
        let descriptor = parse_descriptor(data)?;
        aces += descriptor.dacl.aces.len() + descriptor.sacl.aces.len();
        ensure!(aces <= MAX_TOTAL_ACES, "aggregate ACE limit exceeded");
        result.push(DescriptorRecord {
            security_id: Some(id),
            legacy_record: None,
            sds_offset: Some(h.offset),
            ntfs_hash: Some(h.hash),
            descriptor,
        });
    }
    Ok(Table {
        records: result,
        index_blocks: sii.index_blocks + sdh.index_blocks,
    })
}

pub fn bind_files(files: &[FileInventory], records: &[DescriptorRecord]) -> Result<Vec<Binding>> {
    ensure!(
        files.len() <= MAX_DESCRIPTORS && records.len() <= MAX_DESCRIPTORS,
        "security binding count limit exceeded"
    );
    let mut central = BTreeMap::new();
    let mut legacy = BTreeMap::new();
    for r in records {
        match (r.security_id, r.legacy_record) {
            (Some(id), None) => ensure!(
                central.insert(id, r).is_none(),
                "duplicate central descriptor identity"
            ),
            (None, Some(record)) => ensure!(
                legacy.insert(record, r).is_none(),
                "duplicate legacy descriptor identity"
            ),
            _ => bail!("ambiguous descriptor source identity"),
        }
    }
    let mut bindings = Vec::new();
    let mut used_legacy = BTreeSet::new();
    let mut seen = BTreeSet::new();
    for f in files {
        ensure!(
            f.base_file_reference == 0 && !f.attributes.iter().any(|a| a.type_code == 0x20),
            "unassembled security attributes"
        );
        ensure!(
            seen.insert(f.record_number) && f.sequence_number != 0,
            "invalid security binding file identity"
        );
        if (12..16).contains(&f.record_number)
            && f.names.is_empty()
            && f.attributes.is_empty()
            && !f.is_directory
            && f.hard_link_count == 0
        {
            continue;
        }
        let id = f
            .standard_information
            .as_ref()
            .and_then(|s| s.security_id)
            .filter(|id| *id != 0);
        let record = if let Some(id) = id {
            ensure!(
                !legacy.contains_key(&f.record_number)
                    && !f.attributes.iter().any(|a| a.type_code == 0x50),
                "file has both legacy and central security"
            );
            central
                .get(&id)
                .context("MFT security ID is absent from validated SDS/index table")?
        } else {
            used_legacy.insert(f.record_number);
            let source = legacy
                .get(&f.record_number)
                .context("allocated file lacks a resolvable security descriptor")?;
            let mut attributes = f.attributes.iter().filter(|a| a.type_code == 0x50);
            let a = attributes
                .next()
                .context("legacy descriptor lacks its source attribute")?;
            ensure!(
                attributes.next().is_none()
                    && a.name_utf16.is_empty()
                    && a.flags == 0
                    && a.lowest_vcn == 0
                    && a.initialized_size == a.logical_size
                    && a.logical_size as usize == source.descriptor.relative_hex.len() / 2,
                "legacy descriptor/source attribute mismatch"
            );
            if a.resident {
                // The resident attribute carries a content digest; the
                // descriptor's own evidence hash stays SHA-256.
                let bytes = hex::decode(&source.descriptor.relative_hex)?;
                ensure!(
                    a.resident_sha256.as_deref()
                        == Some(n2r_win32::content_digest::of(&bytes).as_str()),
                    "legacy resident descriptor hash mismatch"
                );
            }
            source
        };
        bindings.push(Binding {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            security_id: id,
            descriptor_sha256: record.descriptor.sha256.clone(),
        });
    }
    ensure!(
        used_legacy.len() == legacy.len(),
        "legacy descriptor has no binding"
    );
    Ok(bindings)
}

/// Actual retained heap capacities for the inspector's shared report budget.
pub fn heap_bytes(report: &Reconciliation) -> usize {
    let mut n = report.evidence_sha256.capacity()
        + report.detail.capacity()
        + report.descriptors.capacity() * std::mem::size_of::<DescriptorRecord>()
        + report.bindings.capacity() * std::mem::size_of::<Binding>();
    for b in &report.bindings {
        n += b.descriptor_sha256.capacity();
    }
    for r in &report.descriptors {
        let d = &r.descriptor;
        n += d.sha256.capacity()
            + d.relative_hex.capacity()
            + d.owner_sid.as_ref().map_or(0, String::capacity)
            + d.group_sid.as_ref().map_or(0, String::capacity);
        for acl in [&d.dacl, &d.sacl] {
            n += acl.aces.capacity() * std::mem::size_of::<Ace>();
            for ace in &acl.aces {
                n += ace.trustee_sid.capacity()
                    + ace.object_type.as_ref().map_or(0, String::capacity)
                    + ace
                        .inherited_object_type
                        .as_ref()
                        .map_or(0, String::capacity);
            }
        }
    }
    n
}

#[cfg(test)]
mod freed_slot_tests {
    use super::*;
    use crate::ntfs_inspect::source_domain::{SourceMetadataBudget, SourceMetadataRange};

    struct Bytes(Vec<u8>);
    impl SourceMetadataRange for Bytes {
        fn byte_len(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_exact_at(&self, offset: u64, output: &mut [u8]) -> Result<()> {
            let at = offset as usize;
            output.copy_from_slice(&self.0[at..at + output.len()]);
            Ok(())
        }
        fn revalidate(&self) -> Result<()> {
            Ok(())
        }
    }
    fn budget() -> SourceMetadataBudget {
        SourceMetadataBudget {
            ram_bytes: 64 << 20,
            scratch_bytes: 64 << 20,
            page_bytes: 65536,
            record_bytes: 65536,
            merge_fan_in: 8,
        }
    }
    /// A descriptor of `length` bytes: a 20-byte header and no ACLs.
    fn descriptor(length: usize) -> Vec<u8> {
        let mut d = vec![0u8; length];
        d[0] = 1;
        d[2..4].copy_from_slice(&0x8000u16.to_le_bytes());
        d
    }
    fn put(sds: &mut [u8], at: usize, bytes: &[u8]) {
        for base in [at, at + HALF] {
            sds[base..base + bytes.len()].copy_from_slice(bytes);
        }
    }
    fn record(at: usize, id: u32, d: &[u8]) -> Vec<u8> {
        let mut r = vec![0u8; 20];
        r[..4].copy_from_slice(&ntfs_hash(d).unwrap().to_le_bytes());
        r[4..8].copy_from_slice(&id.to_le_bytes());
        r[8..16].copy_from_slice(&(at as u64).to_le_bytes());
        r[16..20].copy_from_slice(&((20 + d.len()) as u32).to_le_bytes());
        r.extend_from_slice(d);
        r
    }
    /// The $SDS chkdsk wrote on n12-chkdsk-6, around byte 496: a record of
    /// 100 bytes, the freed slot exactly as it was 112 bytes in (header
    /// 000000000000000000000000000000005c000000 and 72 zero bytes), and the
    /// record after it, 96 bytes long, at the next 16-byte boundary.
    fn sds() -> Vec<u8> {
        let mut sds = vec![0u8; HALF + 4096];
        put(&mut sds, 0, &record(0, 256, &descriptor(80)));
        let mut freed = hex::decode("000000000000000000000000000000005c000000").unwrap();
        freed.resize(92, 0);
        put(&mut sds, 112, &freed);
        put(&mut sds, 208, &record(208, 261, &descriptor(76)));
        sds
    }

    #[test]
    fn a_freed_slot_chkdsk_left_is_passed_over() {
        let summary = scan_sds_range(&Bytes(sds()), budget(), |_, _| Ok(())).unwrap();
        assert_eq!((summary.records, summary.freed_slots), (2, 1));
        let bytes = sds();
        let records = sds_records(&bytes).unwrap();
        assert_eq!(records.keys().copied().collect::<Vec<_>>(), [256, 261]);
    }

    #[test]
    fn only_an_all_zero_slot_with_its_mirror_is_freed() {
        // A byte where the descriptor was.
        let mut sds = sds();
        for base in [112 + 40, HALF + 112 + 40] {
            sds[base] = 1;
        }
        assert!(scan_sds_range(&Bytes(sds.clone()), budget(), |_, _| Ok(())).is_err());
        assert!(sds_records(&sds).is_err());
        // A hash, with ID 0 still.
        let mut sds = self::sds();
        for base in [112, HALF + 112] {
            sds[base] = 1;
        }
        let error = scan_sds_range(&Bytes(sds), budget(), |_, _| Ok(())).unwrap_err();
        assert!(format!("{error:#}").contains("security ID 0"), "{error:#}");
        // Its mirror not freed.
        let mut sds = self::sds();
        sds[HALF + 112 + 30] = 9;
        let error = scan_sds_range(&Bytes(sds), budget(), |_, _| Ok(())).unwrap_err();
        assert!(
            format!("{error:#}").contains("freed slot at byte 112"),
            "{error:#}"
        );
    }
}
