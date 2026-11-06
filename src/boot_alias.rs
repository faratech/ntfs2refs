//! Derived Windows short-path entries for a native ReFS shadow. These entries
//! are separate from source identities: an alias never fabricates an MFT ID,
//! adds a source hard link, or grants source-admission/write authority.
use crate::ntfs_inspect::{
    FileInventory, PagedInspection, RootFileDomain,
    paged_storage::{SourceScratch, SourceRamLease},
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::reparse_layout::Point;
use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc, io};
use sha2::{Digest, Sha256};

const PURPOSE: [u8; 8] = *b"WINALIS1";

/// The parent identity and canonical target are proven by the complete raw
/// namespace. The derived entry is a relative symlink, not a ReFS short name.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WindowsPathAlias {
    pub source_record: u64,
    pub source_sequence: u16,
    pub parent_record: u64,
    pub parent_sequence: u16,
    pub directory: bool,
    pub path: Vec<String>,
    pub canonical_path: Vec<String>,
    pub reparse: Point,
}

pub(crate) fn aliases_for(source: &PagedInspection, file: &FileInventory) -> Result<Vec<WindowsPathAlias>> {
    let canonical = crate::ntfs_admission::paged::canonical_paths_for_alias_preparation(source, file)?;
    let names: Vec<_> = file.names.iter().filter(|name| name.namespace != 2).collect();
    ensure!(names.len() == canonical.len(), "Windows canonical path/name coverage differs");
    let mut rows = Vec::new();
    for alias in file.names.iter().filter(|name| name.namespace == 2) {
        let mut targets = names.iter().zip(&canonical).filter(|(name, _)| {
            name.parent_record_number == alias.parent_record_number
                && name.parent_sequence_number == alias.parent_sequence_number
        });
        let (target, target_path) = targets.next().context("Windows alias has no canonical sibling")?;
        ensure!(targets.next().is_none(),
            "Windows alias has ambiguous canonical siblings at FILE {}", file.record_number);
        let target_name = String::from_utf16(&target.name_utf16)?;
        let alias_name = String::from_utf16(&alias.name_utf16)?;
        ensure!(alias_name != target_name
            && n2r_win32::shadow_names::valid_unicode_component(&alias_name)
            && target_path.last() == Some(&target_name), "Windows alias component differs");
        let mut path = target_path.clone();
        *path.last_mut().context("Windows alias cannot replace the volume root")? = alias_name;
        ensure!(crate::shadow_tree::expected_path_fits(&path, !file.is_directory),
            "Windows alias path exceeds native representation");
        rows.push(WindowsPathAlias {
            source_record: file.record_number, source_sequence: file.sequence_number,
            parent_record: alias.parent_record_number, parent_sequence: alias.parent_sequence_number,
            directory: file.is_directory, path, canonical_path: target_path.clone(),
            reparse: Point::relative_component_alias(&target.name_utf16)?,
        });
    }
    Ok(rows)
}

/// An owning, paged alias plan bound to the actual held source inventory.
/// Ordinary source admission still refuses DOS aliases until its boot-specific
/// preservation path consumes and verifies this domain.
pub struct WindowsAliasDomain {
    entries: SortedRecordStore,
    source_inspection_sha256: String,
    storage_hint_normalization: Option<Arc<n2r_win32::BootStorageHintNormalization>>,
    _storage_hint_ram: Option<SourceRamLease>,
    _scratch: SourceScratch,
    _owner_ram: SourceRamLease,
}
impl WindowsAliasDomain {
    pub fn derive(source: &PagedInspection, base: &Path, scratch: &SourceScratch) -> Result<Self> {
        source.revalidate()?;
        let source_inspection_sha256 = source.canonical_sha256()?;
        let _row_ram = scratch.lease_ram(source.budget().record_bytes.checked_mul(8)
            .and_then(|bytes| bytes.checked_add(4 << 20)).context("Windows alias row RAM overflow")?)?;
        let mut writer = SortedRecordWriter::new(base, PURPOSE, scratch)?;
        for ordinal in 0..source.file_count() {
            let file = source.file(ordinal)?;
            if !file.names.iter().any(|name| name.namespace == 2) { continue; }
            for (index, alias) in aliases_for(source, &file)?.iter().enumerate() {
                let mut key = [0; 16];
                key[..8].copy_from_slice(&file.record_number.to_be_bytes());
                key[8..].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
                writer.push(key, alias)?;
            }
        }
        let pin = writer.finish()?;
        let entries = SortedRecordStore::open(&pin, scratch)?;
        source.revalidate()?;
        ensure!(source.canonical_sha256()? == source_inspection_sha256,
            "Windows source changed across alias derivation");
        let owner_ram = scratch.lease_ram(std::mem::size_of::<Self>() as u64 + 128)?;
        Ok(Self { entries, source_inspection_sha256, storage_hint_normalization: None, _storage_hint_ram: None,
            _scratch: scratch.clone(), _owner_ram: owner_ram })
    }
    pub fn len(&self) -> u64 { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn pin(&self) -> &RecordStorePin { self.entries.pin() }
    pub fn source_inspection_sha256(&self) -> &str { &self.source_inspection_sha256 }
    pub fn alias(&self, ordinal: u64) -> Result<WindowsPathAlias> { self.entries.get(ordinal) }
    pub(crate) fn bind_storage_hint_normalization(
        &mut self, source: &PagedInspection, proof: Arc<n2r_win32::BootStorageHintNormalization>,
    ) -> Result<()> {
        ensure!(self.storage_hint_normalization.is_none()
            && source.canonical_sha256()? == self.source_inspection_sha256
            && proof.binding().layout_profile == n2r_win32::general_layout::GeneralDiskLayoutProfile::OfflineWindows
            && (source.header().geometry.volume_size == proof.binding().identity.partition_bytes
                || source.header().geometry.volume_size.checked_add(u64::from(source.header().geometry.bytes_per_sector))
                    == Some(proof.binding().identity.partition_bytes)),
            "default storage-hint normalization differs from the held Windows source");
        // Each Arc owner retains credit for the shared proof even if the
        // surrounding source context is consumed before this alias domain.
        self._storage_hint_ram = Some(self._scratch.lease_ram(16384)?);
        self.storage_hint_normalization = Some(proof); Ok(())
    }
    pub(crate) fn storage_hint_normalization(&self) -> Option<&n2r_win32::BootStorageHintNormalization> {
        self.storage_hint_normalization.as_deref()
    }
    pub(crate) fn has_storage_hint_owner(&self, proof: &Arc<n2r_win32::BootStorageHintNormalization>) -> bool {
        self.storage_hint_normalization.as_ref().is_some_and(|held| Arc::ptr_eq(held, proof))
    }
    /// Canonical paths only after conserving every alias of this exact source
    /// record in the independently owned derived-entry domain. The enclosing
    /// source owner must call require_source at its phase boundaries.
    pub(crate) fn user_paths(&self, source: &PagedInspection, file: &FileInventory) -> Result<Vec<Vec<String>>> {
        ensure!(source.canonical_sha256()? == self.source_inspection_sha256,
            "Windows alias paths belong to another source inventory");
        let mut key = [0u8; 16];
        key[..8].copy_from_slice(&file.record_number.to_be_bytes());
        let first = self.entries.find_ordinal(key)?;
        let expected = aliases_for(source, file)?;
        ensure!(first.is_some() == !expected.is_empty(), "Windows source alias coverage differs");
        if let Some(first) = first {
            for (index, wanted) in expected.iter().enumerate() {
                let ordinal = first.checked_add(u64::try_from(index)?).context("Windows alias ordinal overflow")?;
                key[8..].copy_from_slice(&u64::try_from(index)?.to_be_bytes());
                ensure!(ordinal < self.entries.len() && self.entries.key(ordinal)? == key
                    && self.alias(ordinal)? == *wanted, "Windows alias row differs from the complete source namespace");
            }
            let end = first.checked_add(u64::try_from(expected.len())?).context("Windows alias range overflow")?;
            ensure!(end == self.entries.len() || self.entries.key(end)?[..8] != key[..8],
                "Windows alias domain has extra entries for this source record");
        }
        let mut paths = crate::ntfs_admission::paged::canonical_paths_for_alias_preparation(source, file)?;
        paths.sort_by(|left, right| (left.len(), left).cmp(&(right.len(), right)));
        ensure!(!paths.windows(2).any(|pair| pair[0] == pair[1]), "duplicate canonical Windows paths");
        Ok(paths)
    }
    pub fn require_source(&self, source: &PagedInspection) -> Result<()> {
        source.revalidate()?;
        self.entries.revalidate()?;
        ensure!(source.canonical_sha256()? == self.source_inspection_sha256,
            "Windows alias plan belongs to a different source inventory");
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct ObjectIndexRow { ordinal: u64, sequence: u16, directory: bool }
fn object_key(record: u64) -> [u8; 16] {
    let mut key = [0; 16]; key[..8].copy_from_slice(&record.to_be_bytes()); key
}

/// SDK adapter over a separate derived namespace. The original source/target
/// object domain and its source file IDs are neither extended nor rewritten.
pub struct WindowsAliasNativeDomain<'a> {
    aliases: Arc<WindowsAliasDomain>,
    expected: &'a crate::shadow_tree::PagedExpectedTree,
    admission: n2r_win32::tree_resources::SourceResourceAdmission,
    indices: SortedRecordStore,
    scratch: SourceScratch,
    semantic_sha256: [u8; 32],
    length: usize,
    _owner_ram: SourceRamLease,
}
pub struct WindowsAliasNativeRow {
    alias: WindowsPathAlias,
    canonical_object_index: usize,
    parent_object_index: usize,
    _ram: SourceRamLease,
}
impl<'a> WindowsAliasNativeDomain<'a> {
    pub fn new(
        aliases: Arc<WindowsAliasDomain>,
        expected: &'a crate::shadow_tree::PagedExpectedTree,
        admission: n2r_win32::tree_resources::SourceResourceAdmission,
        output: &Path, scratch: &SourceScratch,
    ) -> Result<Self> {
        use crate::ntfs_inspect::external_sort::ExternalSort;
        expected.require_resource_owner(admission)?;
        let length = usize::try_from(aliases.len()).context("Windows alias count exceeds the native address domain")?;
        ensure!(aliases.source_inspection_sha256() == hex::encode(admission.source_inspection_sha256),
            "Windows aliases and canonical expected tree have different sources");
        aliases.entries.revalidate()?;
        let owner_ram = scratch.lease_ram(std::mem::size_of::<Self>() as u64 + 4096)?;
        let mut writer = ExternalSort::with_record_hint(output, *b"WINAIDX1", scratch, u64::try_from(expected.len())?)?;
        for ordinal in 0..expected.len() {
            let object = expected.object_leased(ordinal)?;
            writer.push(object_key(object.record_number), &ObjectIndexRow {
                ordinal: u64::try_from(ordinal)?, sequence: object.sequence_number, directory: object.directory,
            })?;
        }
        let indices = SortedRecordStore::open(&writer.finish()?, scratch)?;
        ensure!(indices.len() == u64::try_from(expected.len())?, "Windows canonical object index coverage differs");
        let mut hash = Sha256::new();
        hash.update(b"ntfs2refs-Windows-native-alias-domain-v1\0");
        hash.update(admission.source_inspection_sha256);
        for value in [expected.semantic_sha256(), aliases.pin().data.logical_sha256.as_str(),
            aliases.pin().directory.logical_sha256.as_str(), indices.pin().data.logical_sha256.as_str(),
            indices.pin().directory.logical_sha256.as_str()] {
            let bytes = hex::decode(value)?;
            ensure!(bytes.len() == 32, "Windows alias semantic digest width differs"); hash.update(bytes);
        }
        hash.update(aliases.len().to_le_bytes());
        let value = Self { aliases, expected, admission, indices, scratch: scratch.clone(),
            semantic_sha256: hash.finalize().into(), length, _owner_ram: owner_ram };
        // The SDK preflights every mapped row before making any target entry.
        value.revalidate_owner()?;
        Ok(value)
    }
    fn index(&self, record: u64, sequence: u16) -> Result<(usize, bool)> {
        let value: ObjectIndexRow = self.indices.find(object_key(record))?
            .context("Windows alias canonical source object is absent from the expected tree")?;
        ensure!(value.sequence == sequence && value.ordinal < u64::try_from(self.expected.len())?,
            "Windows alias canonical source sequence or ordinal differs");
        Ok((usize::try_from(value.ordinal)?, value.directory))
    }
    fn row(&self, ordinal: usize) -> Result<WindowsAliasNativeRow> {
        ensure!(u64::try_from(ordinal)? < self.aliases.len(), "Windows alias ordinal is outside the complete plan");
        let ram = self.scratch.lease_ram(self.admission.budget.max_row_bytes.checked_mul(4)
            .context("Windows alias native row memory overflow")?)?;
        let alias = self.aliases.alias(u64::try_from(ordinal)?)?;
        let (canonical_object_index, directory) = self.index(alias.source_record, alias.source_sequence)?;
        let (parent_object_index, parent_directory) = self.index(alias.parent_record, alias.parent_sequence)?;
        ensure!(directory == alias.directory && parent_directory && canonical_object_index != parent_object_index,
            "Windows alias source or parent type/identity differs");
        Ok(WindowsAliasNativeRow { alias, canonical_object_index, parent_object_index, _ram: ram })
    }
    fn revalidate_owner(&self) -> Result<()> {
        self.aliases.entries.revalidate()?; self.indices.revalidate()?;
        self.expected.require_resource_owner(self.admission)?;
        ensure!(self.aliases.source_inspection_sha256() == hex::encode(self.admission.source_inspection_sha256),
            "Windows alias source ownership changed"); Ok(())
    }
    pub fn semantic_digest(&self) -> [u8; 32] { self.semantic_sha256 }
    pub fn uses_alias_owner(&self, owner: &Arc<WindowsAliasDomain>) -> bool { Arc::ptr_eq(&self.aliases, owner) }
}
impl n2r_win32::shadow_native::windows_aliases::WindowsAliasInput for WindowsAliasNativeRow {
    fn input(&self) -> n2r_win32::shadow_native::windows_aliases::WindowsAliasInputRef<'_> {
        n2r_win32::shadow_native::windows_aliases::WindowsAliasInputRef {
            canonical_object_index: self.canonical_object_index, parent_object_index: self.parent_object_index,
            components: &self.alias.path, canonical_components: &self.alias.canonical_path,
        }
    }
}
impl n2r_win32::shadow_native::windows_aliases::WindowsAliasInputDomain for WindowsAliasNativeDomain<'_> {
    type Alias = WindowsAliasNativeRow;
    fn len(&self) -> usize { self.length }
    fn alias(&self, index: usize) -> io::Result<Self::Alias> { self.row(index).map_err(io::Error::other) }
    fn source_inspection_sha256(&self) -> [u8; 32] { self.admission.source_inspection_sha256 }
    fn semantic_sha256(&self) -> io::Result<[u8; 32]> { Ok(self.semantic_sha256) }
    fn require_resource_metadata(&self, admission: n2r_win32::tree_resources::SourceResourceAdmission) -> io::Result<()> {
        if admission != self.admission { return Err(io::Error::other("Windows alias resource admission differs")); }
        self.revalidate_owner().map_err(io::Error::other)
    }
    fn revalidate(&self) -> io::Result<()> { self.revalidate_owner().map_err(io::Error::other) }
}
