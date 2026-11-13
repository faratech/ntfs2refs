//! Resource-backed verification of the same supported NTFS internal states.
use super::*;
use crate::ntfs_inspect::{
    CheckedMftDomain, PagedInspection, RootFileDomain, SourceIndexRanges, SourceMetadataRange,
    external_sort::ExternalSort,
    paged_storage::{PagedMetadataRange, SourcePagePin, SourceScratch},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use n2r_win32::attestation::NativeObservationDomain;
use std::{
    fs,
    io::{self, Write},
    path::Path,
};

#[derive(Debug, Serialize)]
pub struct PagedIndexState {
    pub role: String,
    pub name: String,
    pub record_number: u64,
    pub root_sha256: String,
    pub initialized_allocation_sha256: Option<String>,
    pub bitmap_sha256: Option<String>,
    pub index_blocks: u64,
    pub entries: u64,
    pub entry_evidence: RecordStorePin,
    pub replacement_supported: bool,
    pub detail: String,
    pub root_pages: SourcePagePin,
    pub allocation_pages: Option<SourcePagePin>,
    pub bitmap_pages: Option<SourcePagePin>,
}
struct HeldIndexStorage {
    root: PagedMetadataRange,
    allocation: Option<PagedMetadataRange>,
    bitmap: Option<PagedMetadataRange>,
}
/// Created only after actual source/index reads and complete joins. JSON pins
/// are diagnostics; no deserializer can reconstruct this held proof owner.
#[derive(Serialize)]
pub struct PagedVerifiedIndexes {
    inspection_sha256: String,
    internal_volume_object_id: Option<InternalVolumeObjectId>,
    pub indexes: Vec<PagedIndexState>,
    pub default_quotas_only: bool,
    pub native_quota_policy_bound: bool,
    pub replacement_supported: bool,
    #[serde(skip)]
    stores: Vec<SortedRecordStore>,
    #[serde(skip)]
    ranges: Vec<HeldIndexStorage>,
    #[serde(skip)]
    windows_object_ids: Option<std::sync::Arc<crate::boot_alias::WindowsObjectIdDomain>>,
    /// A data volume's object IDs, matched against the index and archived.
    #[serde(skip)]
    data_object_ids: Option<std::sync::Arc<crate::object_id_disposition::DataObjectIds>>,
}
impl PagedVerifiedIndexes {
    pub fn binds_domain(&self, source: &PagedInspection) -> bool {
        source
            .canonical_sha256()
            .is_ok_and(|hash| hash == self.inspection_sha256)
    }
    pub fn internal_volume_object_id(&self) -> Option<&InternalVolumeObjectId> {
        self.internal_volume_object_id.as_ref()
    }
    pub(crate) fn windows_object_ids_owned(
        &self,
    ) -> Option<std::sync::Arc<crate::boot_alias::WindowsObjectIdDomain>> {
        self.windows_object_ids.clone()
    }
    /// The object IDs of a data volume's files and directories that this
    /// verification matched and archived, and that are not carried over.
    pub(crate) fn data_object_ids_owned(
        &self,
    ) -> Option<std::sync::Arc<crate::object_id_disposition::DataObjectIds>> {
        self.data_object_ids.clone()
    }
    pub fn covers_volume_object_id_domain(&self, source: &PagedInspection, record: u64) -> bool {
        record == 3
            && self.binds_domain(source)
            && self.internal_volume_object_id.as_ref().is_some_and(|id| {
                id.record_number == record && id.inspection_sha256 == self.inspection_sha256
            })
    }
    pub fn bind_native_quota(
        &mut self,
        observed: &n2r_win32::GeneralLivePagedNtfsObservation,
    ) -> bool {
        let Some(native) = observed.txf() else {
            return false;
        };
        let native = &native.observation;
        if observed.domain().header().request.source_inspection_sha256 != self.inspection_sha256
            || !self.default_quotas_only
            || !n2r_win32::windows_build::supported(native.windows_version)
            || native.rm_handle_profile != "volume-root-directory-physical-disk-read-only"
            || !native
                .quota_before
                .as_ref()
                .zip(native.quota_after.as_ref())
                .is_some_and(|(a, b)| {
                    a == b
                        && a.control_flags == 0
                        && a.default_threshold == -1
                        && a.default_limit == -1
                        && a.free_space_start_filtering == 0
                        && a.free_space_threshold == 0
                        && a.free_space_stop_filtering == 0
                })
        {
            return false;
        }
        self.native_quota_policy_bound = true;
        for index in &mut self.indexes {
            if index.role == "$Extend\\$Quota" {
                index.replacement_supported = true;
                index.detail =
                    "cross-matched unlimited defaults; native quotas disabled with zero accounting"
                        .into();
            }
        }
        self.replacement_supported = self.indexes.iter().all(|i| i.replacement_supported);
        true
    }
    pub(crate) fn bind_partition_native_quota(
        &mut self,
        observed: &n2r_win32::attestation_partition::PartitionPagedNtfsObservation,
    ) -> bool {
        let native = observed.txf().observation();
        if observed.domain().header().request.source_inspection_sha256 != self.inspection_sha256
            || !self.default_quotas_only
            || !n2r_win32::windows_build::supported(native.windows_version)
            || native.rm_handle_profile != "volume-root-directory-selected-partition-read-only"
            || !native
                .quota_before
                .as_ref()
                .zip(native.quota_after.as_ref())
                .is_some_and(|(a, b)| {
                    a == b
                        && a.control_flags == 0
                        && a.default_threshold == -1
                        && a.default_limit == -1
                        && a.free_space_start_filtering == 0
                        && a.free_space_threshold == 0
                        && a.free_space_stop_filtering == 0
                })
        {
            return false;
        }
        self.native_quota_policy_bound = true;
        for index in &mut self.indexes {
            if index.role == "$Extend\\$Quota" {
                index.replacement_supported = true;
                index.detail =
                    "cross-matched unlimited defaults; native quotas disabled with zero accounting"
                        .into();
            }
        }
        self.replacement_supported = self.indexes.iter().all(|i| i.replacement_supported);
        true
    }
    pub(crate) fn bind_offline_native_quota(
        &mut self,
        observed: &n2r_win32::offline_environment::OfflinePagedNtfsObservation,
        owner: &n2r_win32::offline_environment::OfflineSourceOwnerToken,
    ) -> Result<bool> {
        observed.require_owner(owner)?;
        observed.require_admission_evidence()?;
        let native = observed
            .txf()
            .context("actual offline quota observation absent")?;
        if observed.domain().header().request.source_inspection_sha256 != self.inspection_sha256
            || !self.default_quotas_only
            || native.windows_version != [10, 0, 26100]
            || native.rm_handle_profile != "volume-root-directory-physical-disk-read-only"
            || !native
                .quota_before
                .as_ref()
                .zip(native.quota_after.as_ref())
                .is_some_and(|(a, b)| {
                    a == b
                        && a.control_flags == 0
                        && a.default_threshold == -1
                        && a.default_limit == -1
                        && a.free_space_start_filtering == 0
                        && a.free_space_threshold == 0
                        && a.free_space_stop_filtering == 0
                })
        {
            return Ok(false);
        }
        self.native_quota_policy_bound = true;
        for index in &mut self.indexes {
            if index.role == "$Extend\\$Quota" {
                index.replacement_supported = true;
                index.detail = "cross-matched unlimited defaults and disabled native quotas on the actual offline owner".into();
            }
        }
        self.replacement_supported = self.indexes.iter().all(|index| index.replacement_supported);
        observed.revalidate()?;
        Ok(true)
    }
    pub fn revalidate(&self) -> Result<()> {
        if let Some(domain) = &self.windows_object_ids {
            domain.revalidate()?;
        }
        if let Some(domain) = &self.data_object_ids {
            domain.revalidate()?;
        }
        for store in &self.stores {
            store.revalidate()?;
        }
        for ranges in &self.ranges {
            ranges.root.revalidate()?;
            if let Some(a) = &ranges.allocation {
                a.revalidate()?;
            }
            if let Some(b) = &ranges.bitmap {
                b.revalidate()?;
            }
        }
        Ok(())
    }
}
struct IndexStorage {
    root: ntfs_inspect::LeasedResidentBytes,
    root_pin: SourcePagePin,
    allocation: Option<SourcePagePin>,
    bitmap: Option<SourcePagePin>,
    initialized: u64,
}
fn record_key(number: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&number.to_be_bytes());
    key
}
fn capture_attribute<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    mapping: &CheckedMftDomain,
    file: &ntfs_inspect::FileInventory,
    attribute: &ntfs_inspect::AttributeInventory,
    path: &Path,
    tag: [u8; 8],
    scratch: &SourceScratch,
) -> Result<SourcePagePin> {
    ensure!(
        attribute.flags == 0 && attribute.compression_unit == 0 && attribute.lowest_vcn == 0,
        "internal index requires plain assembled metadata"
    );
    let mut writer = scratch.writer(path, tag)?;
    if attribute.resident {
        let value = mapping.resident_attribute(reader, source, file, attribute)?;
        writer.write_all(&value)?;
    } else {
        ntfs_inspect::validate_stream_mapping(attribute, &source.header().geometry)?;
        ensure!(
            attribute
                .extents
                .iter()
                .all(|e| e.physical_offset.is_some()),
            "sparse internal index metadata"
        );
        let window = (u64::from(scratch.budget().page_bytes) / 4).max(1);
        let _ram = scratch.lease_ram(window)?;
        let mut bytes = vec![0; window as usize];
        let mut at = 0;
        while at < attribute.logical_size {
            let count = (attribute.logical_size - at).min(window) as usize;
            bytes[..count].fill(0);
            let initialized = attribute
                .initialized_size
                .saturating_sub(at)
                .min(count as u64) as usize;
            if initialized > 0 {
                ntfs_inspect::read_nonresident_inventory_range(
                    reader,
                    attribute,
                    at,
                    &mut bytes[..initialized],
                    &source.header().geometry,
                )?;
            }
            writer.write_all(&bytes[..count])?;
            at += count as u64;
        }
    }
    writer.finish()
}
fn storage<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    mapping: &CheckedMftDomain,
    file: &ntfs_inspect::FileInventory,
    name: &str,
    role: &str,
    ordinal: usize,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<IndexStorage> {
    mapping.verify_record(reader, source, file.record_number)?;
    let units: Vec<_> = name.encode_utf16().collect();
    let mut attrs = file.attributes.iter().filter(|a| a.name_utf16 == units);
    let named: Vec<_> = attrs.by_ref().collect();
    // The reparse index holds an entry per reparse point, and the object-ID
    // index one per file that a shortcut was ever made to: both may have
    // outgrown their root. The quota indexes are their root.
    let may_have_grown = role == "$Extend\\$Reparse" || role == "$Extend\\$ObjId";
    let (index_root, allocation, bitmap) = if may_have_grown {
        let mut index_root = None;
        let mut allocation = None;
        let mut bitmap = None;
        for a in &file.attributes {
            if matches!(a.type_code, 0x90 | 0xa0 | 0xb0) {
                ensure!(
                    a.name_utf16 == units
                        && a.flags == 0
                        && a.lowest_vcn == 0
                        && a.compression_unit == 0,
                    "{role} contains an unknown, encoded or continued index"
                );
                let slot = match a.type_code {
                    0x90 => &mut index_root,
                    0xa0 => &mut allocation,
                    _ => &mut bitmap,
                };
                ensure!(
                    slot.replace(a).is_none(),
                    "{role} has a duplicate index stream"
                );
            } else {
                let metadata = matches!(a.type_code, 0x10 | 0x30 | 0x50)
                    && a.resident
                    && a.name_utf16.is_empty()
                    && a.flags == 0;
                let empty = a.type_code == 0x80
                    && a.name_utf16.is_empty()
                    && a.flags == 0
                    && a.logical_size == 0
                    && a.initialized_size == 0
                    && a.allocated_size == 0
                    && a.extents.is_empty();
                ensure!(
                    metadata || empty,
                    "{role} has an attribute of type {:#x} that an index file does not have",
                    a.type_code
                );
            }
        }
        (
            index_root.with_context(|| format!("{role} has no index root"))?,
            allocation,
            bitmap,
        )
    } else {
        ensure!(
            named.len() == 1
                && named[0].type_code == 0x90
                && named[0].flags == 0
                && named[0].lowest_vcn == 0
                && named[0].compression_unit == 0,
            "internal index exceeds resident-only replacement profile"
        );
        (named[0], None, None)
    };
    ensure!(index_root.resident, "internal index root must be resident");
    let bytes = mapping.resident_attribute(reader, source, file, index_root)?;
    let root_pin = PagedMetadataRange::capture(
        &root.join(format!("index-{ordinal}-root.pages")),
        *b"N2RIROOT",
        &mut io::Cursor::new(&bytes),
        bytes.len() as u64,
        scratch,
    )?;
    ensure!(
        allocation.is_some() == bitmap.is_some(),
        "internal index allocation/bitmap pair incomplete"
    );
    if let Some(a) = allocation {
        ensure!(
            !a.resident
                && a.logical_size > 0
                && a.logical_size
                    .is_multiple_of(u64::from(source.header().geometry.index_record_size))
                && a.initialized_size <= a.logical_size,
            "internal index allocation form differs"
        );
    }
    if let Some(a) = bitmap {
        ensure!(
            a.initialized_size == a.logical_size,
            "internal bitmap is uninitialized"
        );
    }
    Ok(IndexStorage {
        root: bytes,
        root_pin,
        allocation: allocation
            .map(|a| {
                capture_attribute(
                    reader,
                    source,
                    mapping,
                    file,
                    a,
                    &root.join(format!("index-{ordinal}-allocation.pages")),
                    *b"N2RIALLO",
                    scratch,
                )
            })
            .transpose()?,
        bitmap: bitmap
            .map(|a| {
                capture_attribute(
                    reader,
                    source,
                    mapping,
                    file,
                    a,
                    &root.join(format!("index-{ordinal}-bitmap.pages")),
                    *b"N2RIBMAP",
                    scratch,
                )
            })
            .transpose()?,
        initialized: allocation.map_or(0, |a| a.initialized_size),
    })
}
/// An index entry as the walk stored it, read back.
#[derive(serde::Deserialize)]
struct StoredIndexEntry {
    key_hex: String,
    value_hex: String,
}
#[derive(Serialize, serde::Deserialize, PartialEq, Eq)]
struct ReparseBinding {
    reference: u64,
    tag: u32,
}
fn prefix_hash(range: &dyn SourceMetadataRange, length: u64) -> Result<String> {
    ensure!(
        length <= range.byte_len(),
        "initialized internal index prefix escapes range"
    );
    let mut digest = Sha256::new();
    let mut bytes = [0u8; 4096];
    let mut at = 0;
    while at < length {
        let count = (length - at).min(bytes.len() as u64) as usize;
        range.read_exact_at(at, &mut bytes[..count])?;
        digest.update(&bytes[..count]);
        at += count as u64;
    }
    Ok(hex::encode(digest.finalize()))
}

pub fn verify_domain<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    root: &Path,
) -> Result<PagedVerifiedIndexes> {
    verify_domain_with_windows(reader, source, root, None)
}
pub fn verify_domain_windows<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    root: &Path,
    binding: &n2r_win32::general_layout::GeneralDiskBinding,
    proof: std::sync::Arc<n2r_win32::windows_object_ids::VerifiedWindowsObjectIds>,
) -> Result<PagedVerifiedIndexes> {
    ensure!(
        source.is_windows_conversion()
            && proof.binding() == binding
            && binding.layout_profile
                == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows,
        "Windows object-ID reconciliation requires actual Windows/native source scope"
    );
    verify_domain_with_windows(reader, source, root, Some((binding, proof)))
}
fn verify_domain_with_windows<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    root: &Path,
    windows: Option<(
        &n2r_win32::general_layout::GeneralDiskBinding,
        std::sync::Arc<n2r_win32::windows_object_ids::VerifiedWindowsObjectIds>,
    )>,
) -> Result<PagedVerifiedIndexes> {
    source.revalidate()?;
    let geometry = &source.header().geometry;
    ensure!(
        ntfs_index::supports_cluster_size(geometry.cluster_size)
            && matches!(geometry.bytes_per_sector, 512 | 4096)
            && matches!(geometry.file_record_size, 1024 | 4096)
            && ntfs_index::supports_index_record_size(geometry.index_record_size),
        "the internal index scan requires 512- or 4096-byte sectors, 1 or 4 KiB file records and 4 KiB index records"
    );
    ensure!(
        !root.exists(),
        "fresh internal-index evidence directory required"
    );
    fs::create_dir(root)?;
    let scratch = source.metadata_scratch();
    let _rows = scratch.lease_ram(
        scratch
            .budget()
            .record_bytes
            .checked_mul(8)
            .context("index working RAM overflow")?,
    )?;
    let mapping = CheckedMftDomain::open(reader, source)?;
    let mut selected: [Option<ntfs_inspect::FileInventory>; 3] = [None, None, None];
    let mut object_id_count = 0u64;
    let mut volume_id = None;
    let mut expected_reparse =
        SortedRecordWriter::new(&root.join("expected-reparse"), *b"N2RRPEXP", &scratch)?;
    for ordinal in 0..source.file_count() {
        let file = source.file(ordinal)?;
        for attribute in file.attributes.iter().filter(|a| a.type_code == 0x40) {
            object_id_count = object_id_count
                .checked_add(1)
                .context("object ID count overflow")?;
            if object_id_count == 1 {
                volume_id = Some((file.clone(), attribute.clone()));
            }
        }
        if let Some(point) = crate::ntfs_reparse::file_point(&file)? {
            ensure!(
                file.sequence_number != 0 && file.record_number <= 0x0000_ffff_ffff_ffff,
                "invalid reparse reference"
            );
            expected_reparse.push(
                record_key(file.record_number),
                &ReparseBinding {
                    reference: file.record_number | (u64::from(file.sequence_number) << 48),
                    tag: point.tag(),
                },
            )?;
        }
        if file.record_number >= 16
            && file.metadata_role != ntfs_inspect::MetadataRole::ExtendDescendantCandidate
        {
            continue;
        }
        let role = ntfs_admission::paged::internal_role(source, &file)?;
        let slot = match role.as_deref() {
            Some("$Extend\\$ObjId") => 0,
            Some("$Extend\\$Reparse") => 1,
            Some("$Extend\\$Quota") => 2,
            _ => continue,
        };
        ensure!(
            selected[slot].replace(file).is_none(),
            "duplicate internal index file role"
        );
    }
    let expected_pin = expected_reparse.finish()?;
    let expected = SortedRecordStore::open(&expected_pin, &scratch)?;
    let mut indexes = Vec::new();
    let mut stores = Vec::new();
    let mut ranges = Vec::new();
    let mut quota_owners = Vec::new();
    let mut quota_ids = Vec::new();
    let mut internal_volume_object_id = None;
    let mut windows_object_ids = None;
    let mut data_object_ids = None;
    for (ordinal, (role, name, profile, slot)) in [
        ("$Extend\\$ObjId", "$O", Profile::OBJECT_ID, 0),
        ("$Extend\\$Reparse", "$R", Profile::REPARSE, 1),
        ("$Extend\\$Quota", "$O", Profile::QUOTA_OWNER, 2),
        ("$Extend\\$Quota", "$Q", Profile::QUOTA_ID, 2),
    ]
    .into_iter()
    .enumerate()
    {
        let file = selected[slot]
            .as_ref()
            .context("missing internal index object")?;
        let storage = storage(
            reader, source, &mapping, file, name, role, ordinal, root, &scratch,
        )?;
        let root_range = PagedMetadataRange::open(&storage.root_pin, &scratch)?;
        let allocation = storage
            .allocation
            .as_ref()
            .map(|p| PagedMetadataRange::open(p, &scratch))
            .transpose()?;
        let bitmap = storage
            .bitmap
            .as_ref()
            .map(|p| PagedMetadataRange::open(p, &scratch))
            .transpose()?;
        let mut writer = SortedRecordWriter::new(
            &root.join(format!("index-{ordinal}-entries")),
            *b"N2RINDEX",
            &scratch,
        )?;
        let mut entry_count = 0u64;
        let mut entries = Vec::new();
        let mut actual_reparse = if slot == 1 {
            Some(ExternalSort::new(
                &root.join("actual-reparse"),
                *b"N2RRPACT",
                &scratch,
            )?)
        } else {
            None
        };
        let mut previous = None;
        let walked = ntfs_index::paged::walk_ranges(
            SourceIndexRanges {
                root: &root_range,
                allocation: allocation.as_ref().map(|r| r as &dyn SourceMetadataRange),
                bitmap: bitmap.as_ref().map(|r| r as &dyn SourceMetadataRange),
                initialized_allocation_bytes: storage.initialized,
            },
            profile,
            geometry.cluster_size,
            geometry.index_record_size,
            &scratch,
            &root.join(format!("index-{ordinal}.visited")),
            |_, key, value| {
                writer.push(
                    record_key(entry_count),
                    &IndexEntry {
                        key_hex: hex::encode(key),
                        value_hex: hex::encode(value),
                    },
                )?;
                entry_count = entry_count
                    .checked_add(1)
                    .context("internal index count overflow")?;
                if let Some(sort) = &mut actual_reparse {
                    ensure!(
                        key.len() == 12 && value.is_empty(),
                        "invalid reparse index key/value shape"
                    );
                    let tag = u32::from_le_bytes(key[..4].try_into()?);
                    let low = u32::from_le_bytes(key[4..8].try_into()?);
                    let high = u32::from_le_bytes(key[8..12].try_into()?);
                    let order = (tag, low, high);
                    ensure!(
                        previous.is_none_or(|p| p < order),
                        "reparse index ordering differs"
                    );
                    previous = Some(order);
                    let reference = u64::from(low) | (u64::from(high) << 32);
                    ensure!(reference >> 48 != 0, "zero reparse sequence");
                    sort.push(
                        record_key(reference & 0x0000_ffff_ffff_ffff),
                        &ReparseBinding { reference, tag },
                    )?;
                } else if slot != 0 || entries.len() < 2 {
                    // The quota profiles are resident-root-only, so this is
                    // one <=4KiB node, not an N table. The object-ID index
                    // can be of any size: its entries are read back from
                    // the entry store, and only enough are kept here to
                    // tell one entry from several.
                    entries.push((key.to_vec(), value.to_vec()));
                }
                Ok(())
            },
        )?;
        let entry_pin = writer.finish()?;
        let entry_store = SortedRecordStore::open(&entry_pin, &scratch)?;
        let supported = if slot == 0 {
            if let Some((binding, proof)) = windows.as_ref() {
                let object_index_name: Vec<_> = "$O".encode_utf16().collect();
                // (The index was once required to be its root alone: a
                // Windows on which shortcuts had been made to more than a
                // few dozen files was refused.)
                ensure!(
                    file.base_file_reference == 0
                        && file.sequence_number != 0
                        && file.metadata_role_issue.is_none()
                        && !file.attributes.iter().any(|a| a.type_code == 0x20
                            || (matches!(a.type_code, 0x90 | 0xa0 | 0xb0)
                                && a.name_utf16 != object_index_name)),
                    "Windows object-ID index file is not in the form the converter reads"
                );
                ensure!(
                    object_id_count == entry_store.len(),
                    "Windows has {object_id_count} object-ID attributes and its $Extend\\$ObjId index has {} entries",
                    entry_store.len()
                );
                let inspection: [u8; 32] = hex::decode(source.canonical_sha256()?)?
                    .try_into()
                    .map_err(|_| {
                        anyhow::anyhow!("Windows object-ID inspection digest width differs")
                    })?;
                let mut archive = ExternalSort::new(
                    &root.join("windows-object-ID-dispositions"),
                    *b"WINOID01",
                    &scratch,
                )?;
                let mut ordinary = 0u64;
                let mut volume_entries = 0u64;
                for ordinal in 0..entry_store.len() {
                    let stored: StoredIndexEntry = entry_store.get(ordinal)?;
                    let (key, indexed) = (
                        &hex::decode(&stored.key_hex)?,
                        &hex::decode(&stored.value_hex)?,
                    );
                    ensure!(
                        key.len() == 16 && key.iter().any(|b| *b != 0) && indexed.len() == 56,
                        "Windows object-ID index entry shape differs"
                    );
                    let reference = u64::from_le_bytes(indexed[..8].try_into()?);
                    let number = reference & 0x0000_ffff_ffff_ffff;
                    let sequence = (reference >> 48) as u16;
                    ensure!(sequence != 0, "Windows object-ID index sequence is zero");
                    let owner = source
                        .find_record(number, Some(sequence))?
                        .context("Windows object-ID index source identity absent")?;
                    let mut attributes = owner.attributes.iter().filter(|a| a.type_code == 0x40);
                    let attribute = attributes
                        .next()
                        .context("Windows object-ID index lacks its raw attribute")?;
                    ensure!(
                        attributes.next().is_none(),
                        "Windows object-ID raw attribute is duplicated"
                    );
                    let raw = crate::boot_alias::windows_object_id_bytes(attribute)?;
                    let actual = mapping.resident_attribute(reader, source, &owner, attribute)?;
                    ensure!(
                        raw.as_slice() == key.as_slice() && actual.as_ref() == raw,
                        "Windows object-ID fresh raw/index bytes differ"
                    );
                    if number == 3 {
                        volume_entries = volume_entries
                            .checked_add(1)
                            .context("volume object-ID count overflow")?;
                        ensure!(
                            volume_entries == 1,
                            "duplicate Windows filesystem volume identity"
                        );
                        internal_volume_object_id = volume_identity(
                            reader,
                            source,
                            &mapping,
                            &owner,
                            attribute,
                            file,
                            &storage.root,
                            &(key.clone(), indexed.clone()),
                            false,
                        )?;
                        ensure!(
                            internal_volume_object_id.is_some(),
                            "Windows filesystem volume identity exceeds strict profile"
                        );
                    } else {
                        ensure!(
                            number >= 16
                                && owner.base_file_reference == 0
                                && !owner.is_metadata
                                && owner.metadata_role
                                    == ntfs_inspect::MetadataRole::OutsideExtendCandidate
                                && owner.metadata_role_issue.is_none(),
                            "unknown Windows object-ID source role"
                        );
                        let identity = n2r_win32::attestation::FileIdentity {
                            record_number: number,
                            sequence_number: sequence,
                        };
                        let extended: [u8; 48] = indexed[8..].try_into()?;
                        proof.require_raw_object_id_scope(
                            binding, inspection, &identity, &raw, &extended,
                        )?;
                        let mut native = [0u8; 64];
                        native[..16].copy_from_slice(&raw);
                        native[16..].copy_from_slice(&extended);
                        archive.push(
                            record_key(number),
                            &crate::boot_alias::WindowsObjectIdDisposition {
                                identity,
                                source_inspection_sha256: hex::encode(inspection),
                                source_attribute: attribute.clone(),
                                index_key_hex: hex::encode(key),
                                index_value_hex: hex::encode(indexed),
                                native_object_id_hex: hex::encode(native),
                            },
                        )?;
                        ordinary = ordinary
                            .checked_add(1)
                            .context("Windows ordinary object-ID count overflow")?;
                    }
                }
                ensure!(
                    ordinary == u64::try_from(proof.len())?
                        && ordinary.checked_add(volume_entries) == Some(object_id_count),
                    "Windows object-ID complete native/raw/index membership differs"
                );
                windows_object_ids = Some(std::sync::Arc::new(
                    crate::boot_alias::WindowsObjectIdDomain::from_verified_archive(
                        source,
                        binding,
                        std::sync::Arc::clone(proof),
                        &archive.finish()?,
                        &scratch,
                    )?,
                ));
                internal_volume_object_id.is_some()
                    || (object_id_count == 0 && entries.is_empty())
                    || (volume_entries == 0 && ordinary == object_id_count)
            } else {
                if object_id_count == 1 && entries.len() == 1 {
                    if let Some((volume, attribute)) = &volume_id {
                        internal_volume_object_id = volume_identity(
                            reader,
                            source,
                            &mapping,
                            volume,
                            attribute,
                            file,
                            &storage.root,
                            &entries[0],
                            true,
                        )?;
                    }
                }
                if internal_volume_object_id.is_some()
                    || (object_id_count == 0 && entries.is_empty())
                {
                    true
                } else if source.is_windows_conversion() {
                    false
                } else {
                    // A data volume that has been used: files and directories
                    // with object IDs of their own.
                    let (domain, volume) = data_object_ids_of(
                        reader,
                        source,
                        &mapping,
                        file,
                        &storage.root,
                        &entry_store,
                        object_id_count,
                        root,
                        &scratch,
                    )?;
                    internal_volume_object_id = volume;
                    data_object_ids = Some(std::sync::Arc::new(domain));
                    true
                }
            }
        } else if slot == 1 {
            let pin = actual_reparse
                .take()
                .context("reparse collector absent")?
                .finish()?;
            let actual = SortedRecordStore::open(&pin, &scratch)?;
            let mut same = actual.len() == expected.len();
            if same {
                for i in 0..actual.len() {
                    same &= actual.key(i)? == expected.key(i)?
                        && actual.get::<ReparseBinding>(i)? == expected.get::<ReparseBinding>(i)?;
                }
            }
            drop(actual);
            scratch.retire_created(&pin.data)?;
            scratch.retire_created(&pin.directory)?;
            same
        } else {
            if name == "$Q" {
                quota_ids = entries;
            } else {
                quota_owners = entries;
            }
            false
        };
        indexes.push(PagedIndexState {
            role: role.into(),
            name: name.into(),
            record_number: file.record_number,
            root_sha256: storage.root_pin.logical_sha256.clone(),
            initialized_allocation_sha256: allocation
                .as_ref()
                .map(|a| prefix_hash(a, storage.initialized))
                .transpose()?,
            bitmap_sha256: storage.bitmap.as_ref().map(|p| p.logical_sha256.clone()),
            index_blocks: walked.index_blocks,
            entries: entry_count,
            entry_evidence: entry_pin,
            replacement_supported: supported,
            detail: if slot == 0 && data_object_ids.is_some() {
                "every object ID matched with its attribute and archived; not carried over"
            } else if supported {
                "complete supported index state cross-matched"
            } else {
                "nondefault or unexplained internal state requires preservation/native policy"
            }
            .into(),
            root_pages: storage.root_pin,
            allocation_pages: storage.allocation,
            bitmap_pages: storage.bitmap,
        });
        stores.push(entry_store);
        ranges.push(HeldIndexStorage {
            root: root_range,
            allocation,
            bitmap,
        });
    }
    drop(expected);
    scratch.retire_created(&expected_pin.data)?;
    scratch.retire_created(&expected_pin.directory)?;
    source.revalidate()?;
    Ok(PagedVerifiedIndexes {
        inspection_sha256: source.canonical_sha256()?,
        internal_volume_object_id,
        replacement_supported: indexes.iter().all(|i| i.replacement_supported),
        default_quotas_only: quota_indexes_match(&quota_owners, &quota_ids),
        native_quota_policy_bound: false,
        indexes,
        stores,
        ranges,
        windows_object_ids,
        data_object_ids,
    })
}

/// Matches every entry of a data volume's `$Extend\$ObjId` index with the
/// `$OBJECT_ID` attribute of the file it names, and the other way round by
/// count, and archives them. The volume's own entry, if it has one, is the
/// internal identity it always was.
fn data_object_ids_of<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    mapping: &CheckedMftDomain,
    index_file: &ntfs_inspect::FileInventory,
    index_root: &[u8],
    entry_store: &SortedRecordStore,
    object_id_count: u64,
    root: &Path,
    scratch: &SourceScratch,
) -> Result<(
    crate::object_id_disposition::DataObjectIds,
    Option<InternalVolumeObjectId>,
)> {
    ensure!(
        object_id_count == entry_store.len(),
        "the volume has {object_id_count} object-ID attributes and its $Extend\\$ObjId index has {} entries",
        entry_store.len()
    );
    let mut archive = ExternalSort::new(
        &root.join("object-ids-not-carried-over"),
        crate::object_id_disposition::PURPOSE,
        scratch,
    )?;
    let mut volume = None;
    let mut ordinary = 0u64;
    for ordinal in 0..entry_store.len() {
        let stored: StoredIndexEntry = entry_store.get(ordinal)?;
        let key = hex::decode(&stored.key_hex)?;
        let indexed = hex::decode(&stored.value_hex)?;
        ensure!(
            key.len() == 16 && key.iter().any(|b| *b != 0) && indexed.len() == 56,
            "object-ID index entry {ordinal} is not a 16-byte ID with a 56-byte value"
        );
        let reference = u64::from_le_bytes(indexed[..8].try_into()?);
        let number = reference & 0x0000_ffff_ffff_ffff;
        let sequence = (reference >> 48) as u16;
        ensure!(
            sequence != 0,
            "object-ID index entry {ordinal} names MFT record {number} with sequence zero"
        );
        let owner = source
            .find_record(number, Some(sequence))?
            .with_context(|| {
                format!(
                    "object-ID index entry {ordinal} names MFT record {number}, which is not in use"
                )
            })?;
        let mut attributes = owner.attributes.iter().filter(|a| a.type_code == 0x40);
        let attribute = attributes.next().with_context(|| {
            format!("MFT record {number} is in the object-ID index and has no object-ID attribute")
        })?;
        ensure!(
            attributes.next().is_none(),
            "MFT record {number} has more than one object-ID attribute"
        );
        let raw = crate::boot_alias::windows_object_id_bytes(attribute)
            .with_context(|| format!("object ID of MFT record {number}"))?;
        let actual = mapping.resident_attribute(reader, source, &owner, attribute)?;
        ensure!(
            raw.as_slice() == key.as_slice() && actual.as_ref() == raw,
            "the object ID of MFT record {number} differs between its attribute and the index"
        );
        if number == 3 {
            ensure!(volume.is_none(), "the volume has two object IDs of its own");
            volume = volume_identity(
                reader,
                source,
                mapping,
                &owner,
                attribute,
                index_file,
                index_root,
                &(key.clone(), indexed.clone()),
                false,
            )?;
            ensure!(
                volume.is_some(),
                "the volume's own object ID is not in the form the converter replaces"
            );
        } else {
            ensure!(
                crate::object_id_disposition::ordinary(&owner),
                "MFT record {number} has an object ID and is not an ordinary file or directory"
            );
            archive.push(
                crate::object_id_disposition::key(number),
                &crate::object_id_disposition::ObjectIdNotCarried {
                    record_number: number,
                    sequence_number: sequence,
                    source_attribute: attribute.clone(),
                    index_key_hex: stored.key_hex,
                    index_value_hex: stored.value_hex,
                },
            )?;
            ordinary = ordinary
                .checked_add(1)
                .context("object-ID count overflow")?;
        }
    }
    ensure!(
        ordinary.checked_add(u64::from(volume.is_some())) == Some(object_id_count),
        "object-ID attributes and index entries do not pair up"
    );
    let domain = crate::object_id_disposition::DataObjectIds::from_verified_archive(
        source,
        &archive.finish()?,
        scratch,
    )?;
    ensure!(domain.len() == ordinary, "object-ID archive is incomplete");
    Ok((domain, volume))
}

fn volume_identity<R: Read + Seek>(
    reader: &mut R,
    source: &PagedInspection,
    mapping: &CheckedMftDomain,
    volume: &ntfs_inspect::FileInventory,
    attribute: &ntfs_inspect::AttributeInventory,
    index_file: &ntfs_inspect::FileInventory,
    index_root: &[u8],
    entry: &(Vec<u8>, Vec<u8>),
    // Whether the index has to be its root alone. It is where the volume's
    // is the only object ID; a data volume's index may have grown.
    root_only: bool,
) -> Result<Option<InternalVolumeObjectId>> {
    let name: Vec<_> = "$O".encode_utf16().collect();
    if volume.record_number != 3
        || volume.sequence_number == 0
        || volume.base_file_reference != 0
        || volume.is_directory
        || volume.hard_link_count != 1
        || volume.metadata_role != ntfs_inspect::MetadataRole::ReservedSystemRecord
        || volume.metadata_role_issue.is_some()
        || ntfs_admission::paged::internal_role(source, volume)?.as_deref() != Some("$Volume")
        || !attribute.resident
        || !attribute.name_utf16.is_empty()
        || attribute.flags != 0
        || attribute.compression_unit != 0
        || attribute.lowest_vcn != 0
        || attribute.logical_size != 16
        || attribute.initialized_size != 16
        || attribute.allocated_size != 16
        || !attribute.extents.is_empty()
        || index_file.base_file_reference != 0
        || index_file.sequence_number == 0
        || index_file.metadata_role_issue.is_some()
        || index_file.attributes.iter().any(|a| {
            a.type_code == 0x20
                || (root_only && matches!(a.type_code, 0xa0 | 0xb0))
                || (matches!(a.type_code, 0x90 | 0xa0 | 0xb0) && a.name_utf16 != name)
        })
    {
        return Ok(None);
    }
    let value = mapping.resident_attribute(reader, source, volume, attribute)?;
    let reference = volume.record_number | (u64::from(volume.sequence_number) << 48);
    let (key, indexed) = entry;
    if value.len() != 16
        || value.iter().all(|b| *b == 0)
        || key.as_slice() != value.as_ref()
        || indexed.len() != 56
        || indexed[..8] != reference.to_le_bytes()
        || indexed[8..] != [0; 48]
    {
        return Ok(None);
    }
    Ok(Some(InternalVolumeObjectId {
        inspection_sha256: source.canonical_sha256()?,
        record_number: volume.record_number,
        sequence_number: volume.sequence_number,
        attribute_instance: attribute.instance,
        object_id_hex: hex::encode(&value),
        object_id_sha256: hex::encode(Sha256::digest(&value)),
        object_index_record_number: index_file.record_number,
        object_index_sequence_number: index_file.sequence_number,
        object_index_name: "$O",
        object_index_root_sha256: hex::encode(Sha256::digest(index_root)),
        object_index_value_sha256: hex::encode(Sha256::digest(indexed)),
        file_reference: reference,
        disposition: "replace-filesystem-internal-volume-identity",
        same_refs_object_id_preserved: false,
    }))
}
