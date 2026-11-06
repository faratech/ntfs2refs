//! Derived Windows short-path entries for a native ReFS shadow. These entries
//! are separate from source identities: an alias never fabricates an MFT ID,
//! adds a source hard link, or grants source-admission/write authority.
use crate::ntfs_inspect::{
    FileInventory, PagedInspection, RootFileDomain,
    paged_storage::SourceScratch,
    record_store::{RecordStorePin, SortedRecordStore, SortedRecordWriter},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::reparse_layout::Point;
use serde::{Deserialize, Serialize};
use std::path::Path;

const PURPOSE: [u8; 8] = *b"WINALIS1";

/// The parent identity and canonical target are proven by the complete raw
/// namespace. The derived entry is a relative symlink, not a ReFS short name.
#[derive(Debug, Serialize, Deserialize)]
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
    _scratch: SourceScratch,
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
        Ok(Self { entries, source_inspection_sha256, _scratch: scratch.clone() })
    }
    pub fn len(&self) -> u64 { self.entries.len() }
    pub fn is_empty(&self) -> bool { self.entries.is_empty() }
    pub fn pin(&self) -> &RecordStorePin { self.entries.pin() }
    pub fn source_inspection_sha256(&self) -> &str { &self.source_inspection_sha256 }
    pub fn alias(&self, ordinal: u64) -> Result<WindowsPathAlias> { self.entries.get(ordinal) }
    pub fn require_source(&self, source: &PagedInspection) -> Result<()> {
        source.revalidate()?;
        self.entries.revalidate()?;
        ensure!(source.canonical_sha256()? == self.source_inspection_sha256,
            "Windows alias plan belongs to a different source inventory");
        Ok(())
    }
}
