//! Authenticated alias expectations only; fresh native observation issues proof.
use super::*;
use crate::{
    artifact_arena::ArtifactGroup,
    ntfs_inspect::{external_sort::ExternalSort, paged_storage::SourcePagePin},
    shadow_tree::PagedExpectedTree,
};
use n2r_win32::tree_resources::SourceResourceAdmission;
use std::{
    fs::{File, OpenOptions},
    os::windows::fs::{MetadataExt, OpenOptionsExt},
};

pub(crate) struct PublishedWindowsAliasExpectations {
    pin: RecordStorePin,
    _store: SortedRecordStore,
}
impl PublishedWindowsAliasExpectations {
    pub(crate) fn pin(&self) -> &RecordStorePin {
        &self.pin
    }
}

fn canonical_pin(pin: &SourcePagePin, volume: &str) -> Result<SourcePagePin> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&pin.path)?;
    let metadata = file.metadata()?;
    let route = n2r_win32::file_storage::final_path_guid(&file)?;
    let prefix = format!("{}\\", volume.trim_end_matches('\\'));
    ensure!(
        metadata.is_file()
            && metadata.file_attributes() & 0x400 == 0
            && metadata.len() == pin.wire_bytes
            && n2r_win32::file_storage::number_of_links(&file)? == 1
            && route
                .get(..prefix.len())
                .is_some_and(|r| r.eq_ignore_ascii_case(&prefix)),
        "Windows alias publication file is not the actual ordinary journal artifact"
    );
    let mut result = pin.clone();
    result.path = route.into();
    Ok(result)
}

/// Copy complete actual source-derived rows before the preparation arena closes.
/// Wire files may differ; exact logical rows/keys and their hashes must not.
pub(crate) fn publish(
    source: &WindowsAliasDomain,
    scratch: &SourceScratch,
    base: &Path,
) -> Result<PublishedWindowsAliasExpectations> {
    let group = scratch
        .artifact_group()
        .context("alias publication requires its actual arena")?;
    ensure!(
        group.group() == ArtifactGroup::RecoveryCopy,
        "alias publication needs recovery-copy quota"
    );
    source.entries.revalidate()?;
    let _working = scratch.lease_ram(
        scratch
            .budget()
            .record_bytes
            .checked_mul(4)
            .context("alias publication row RAM overflow")?,
    )?;
    let mut writer = SortedRecordWriter::new(base, PURPOSE, scratch)?;
    for ordinal in 0..source.len() {
        let row = source.alias(ordinal)?;
        writer.push(source.entries.key(ordinal)?, &row)?;
    }
    let original = source.pin();
    let pin = writer.finish()?;
    ensure!(
        pin.records == original.records
            && pin.purpose == original.purpose
            && pin.data.logical_sha256 == original.data.logical_sha256
            && pin.data.logical_bytes == original.data.logical_bytes
            && pin.directory.logical_sha256 == original.directory.logical_sha256
            && pin.directory.logical_bytes == original.directory.logical_bytes,
        "published Windows alias rows or ordinal coverage differ from the actual source plan"
    );
    let store = SortedRecordStore::open(&pin, scratch)?;
    source.entries.revalidate()?;
    let volume = group.arena().volume_guid_path()?;
    let mut canonical = pin.clone();
    canonical.data = canonical_pin(&pin.data, volume)?;
    canonical.directory = canonical_pin(&pin.directory, volume)?;
    Ok(PublishedWindowsAliasExpectations {
        pin: canonical,
        _store: store,
    })
}

pub(crate) struct ReopenedWindowsAliasNativeDomain<'expected> {
    entries: SortedRecordStore,
    expected: &'expected PagedExpectedTree,
    admission: SourceResourceAdmission,
    indices: SortedRecordStore,
    namespace: SortedRecordStore,
    scratch: SourceScratch,
    semantic_sha256: [u8; 32],
    length: usize,
    _held_files: [File; 2],
    _owner_ram: SourceRamLease,
}

fn path_key(path: &[String]) -> [u8; 16] {
    let mut hash = Sha256::new();
    hash.update(b"n2r-reopened-Windows-alias-path-v1");
    hash.update((path.len() as u64).to_le_bytes());
    for component in path {
        hash.update((component.len() as u64).to_le_bytes());
        hash.update(component.as_bytes());
    }
    hash.finalize()[..16]
        .try_into()
        .expect("fixed digest prefix")
}

impl<'expected> ReopenedWindowsAliasNativeDomain<'expected> {
    /// Called only with actual held files authenticated by the recovery envelope.
    /// The expectation owner borrows only the canonical expected pages, never the
    /// recovery target, and cannot mint a constructor/native/write capability.
    pub(crate) fn open(
        pin: &RecordStorePin,
        expected_plan_sha256: [u8; 32],
        held_files: [File; 2],
        expected: &'expected PagedExpectedTree,
        admission: SourceResourceAdmission,
        scratch: &SourceScratch,
        output: &Path,
    ) -> Result<Self> {
        expected.require_resource_owner(admission)?;
        ensure!(
            pin.schema_version == 1
                && pin.purpose == PURPOSE
                && pin.records <= admission.maximum_namespace_names()? as u64,
            "reopened alias record store exceeds the original resource/source profile"
        );
        let group = scratch
            .artifact_group()
            .context("reopened aliases need actual recovery arena")?;
        ensure!(
            group.group() == ArtifactGroup::RecoveryCopy,
            "reopened aliases require recovery-copy quota"
        );
        // The expected pages are owned either by the run that built them or,
        // after a restart, by the file reopened from the published recovery
        // records. Both are accounted in this arena.
        expected
            .require_shared_memory(group.arena())
            .or_else(|_| expected.require_recovery_memory(group.arena()))
            .context("reopened aliases need the expected pages accounted in the recovery arena")?;
        let owner_ram = scratch.lease_ram(std::mem::size_of::<Self>() as u64 + 16384)?;
        for (pin, file) in [
            (&pin.data, &held_files[0]),
            (&pin.directory, &held_files[1]),
        ] {
            ensure!(
                file.metadata()?.len() == pin.wire_bytes
                    && n2r_win32::file_storage::final_path_guid(file)?.eq_ignore_ascii_case(
                        pin.path.to_str().context("alias GUID path UTF16 differs")?
                    ),
                "reopened alias reader is not the authenticated held artifact"
            );
        }
        let entries = SortedRecordStore::open(pin, scratch)?;
        let mut index_writer =
            ExternalSort::with_record_hint(output, *b"WINAIDX1", scratch, expected.len() as u64)?;
        let mut namespace_writer = ExternalSort::with_record_hint(
            &output.with_extension("namespace"),
            *b"WIALPTH1",
            scratch,
            (expected.len() as u64)
                .checked_add(pin.records)
                .context("alias namespace hint overflow")?,
        )?;
        let mut names = 0u64;
        for ordinal in 0..expected.len() {
            let object = expected.object_leased(ordinal)?;
            index_writer.push(
                object_key(object.record_number),
                &ObjectIndexRow {
                    ordinal: ordinal as u64,
                    sequence: object.sequence_number,
                    directory: object.directory,
                },
            )?;
            for path in std::iter::once(&object.path).chain(&object.additional_names) {
                namespace_writer.push(path_key(path), path)?;
                names = names
                    .checked_add(1)
                    .context("canonical namespace count overflow")?;
            }
        }
        let indices = SortedRecordStore::open(&index_writer.finish()?, scratch)?;
        ensure!(
            indices.len() == expected.len() as u64,
            "reopened alias canonical index is incomplete"
        );
        let length = usize::try_from(entries.len())?;
        let _working = scratch.lease_ram(
            admission
                .budget
                .max_row_bytes
                .checked_mul(8)
                .context("reopened alias row RAM overflow")?,
        )?;
        let mut previous_record = None;
        let mut next_alias = 0u64;
        for ordinal in 0..entries.len() {
            let row: WindowsPathAlias = entries.get(ordinal)?;
            if previous_record != Some(row.source_record) {
                next_alias = 0;
            }
            let mut key = object_key(row.source_record);
            key[8..].copy_from_slice(&next_alias.to_be_bytes());
            ensure!(
                entries.key(ordinal)? == key,
                "reopened alias source-record ordinal coverage differs"
            );
            next_alias = next_alias
                .checked_add(1)
                .context("alias ordinal overflow")?;
            previous_record = Some(row.source_record);
            Self::validate_row(expected, &indices, &row)?;
            namespace_writer.push(path_key(&row.path), &row.path)?;
            names = names
                .checked_add(1)
                .context("reopened alias namespace overflow")?;
            ensure!(
                names <= admission.maximum_namespace_names()? as u64,
                "reopened complete Windows namespace exceeds original bound"
            );
        }
        // Duplicate aliases, aliases colliding with canonical names, and any
        // hash-key collision are hard refusals in the existing exact-key sort.
        let namespace = SortedRecordStore::open(&namespace_writer.finish()?, scratch)?;
        ensure!(
            namespace.len() == names,
            "reopened alias namespace coverage differs"
        );
        let mut hash = Sha256::new();
        hash.update(b"ntfs2refs-Windows-native-alias-domain-v1\0");
        hash.update(admission.source_inspection_sha256);
        for value in [
            expected.semantic_sha256(),
            pin.data.logical_sha256.as_str(),
            pin.directory.logical_sha256.as_str(),
            indices.pin().data.logical_sha256.as_str(),
            indices.pin().directory.logical_sha256.as_str(),
        ] {
            let bytes = hex::decode(value)?;
            ensure!(
                bytes.len() == 32,
                "reopened alias semantic pin width differs"
            );
            hash.update(bytes);
        }
        hash.update(pin.records.to_le_bytes());
        let semantic_sha256: [u8; 32] = hash.finalize().into();
        ensure!(
            semantic_sha256 == expected_plan_sha256,
            "reopened alias source/expected/index plan differs from the published constructor plan"
        );
        let value = Self {
            entries,
            expected,
            admission,
            indices,
            namespace,
            scratch: scratch.clone(),
            semantic_sha256,
            length,
            _held_files: held_files,
            _owner_ram: owner_ram,
        };
        value.revalidate_owner()?;
        Ok(value)
    }
    fn index(
        indices: &SortedRecordStore,
        expected: &PagedExpectedTree,
        record: u64,
        sequence: u16,
    ) -> Result<(usize, bool)> {
        let row: ObjectIndexRow = indices
            .find(object_key(record))?
            .context("reopened alias source/parent object absent")?;
        ensure!(
            sequence != 0 && row.sequence == sequence && row.ordinal < expected.len() as u64,
            "reopened alias source/parent sequence or ordinal differs"
        );
        Ok((usize::try_from(row.ordinal)?, row.directory))
    }
    fn validate_row(
        expected: &PagedExpectedTree,
        indices: &SortedRecordStore,
        row: &WindowsPathAlias,
    ) -> Result<(usize, usize)> {
        let (canonical, directory) =
            Self::index(indices, expected, row.source_record, row.source_sequence)?;
        let (parent, parent_directory) =
            Self::index(indices, expected, row.parent_record, row.parent_sequence)?;
        let object = expected.object_leased(canonical)?;
        let parent_object = expected.object_leased(parent)?;
        ensure!(
            canonical != parent
                && directory == row.directory
                && parent_directory
                && parent_object.reparse.is_none()
                && !row.path.is_empty()
                && !row.canonical_path.is_empty()
                && row.path != row.canonical_path
                && row.path[..row.path.len() - 1] == parent_object.path
                && row.canonical_path[..row.canonical_path.len() - 1] == parent_object.path
                && std::iter::once(&object.path)
                    .chain(&object.additional_names)
                    .any(|path| path == &row.canonical_path)
                && crate::shadow_tree::expected_path_fits(&row.path, !directory)
                && row
                    .path
                    .iter()
                    .all(|part| n2r_win32::shadow_names::valid_unicode_component(part)),
            "reopened alias is not an exact admitted same-parent canonical sibling"
        );
        ensure!(
            row.reparse
                == Point::relative_component_alias(
                    &row.canonical_path
                        .last()
                        .unwrap()
                        .encode_utf16()
                        .collect::<Vec<_>>()
                )?,
            "reopened alias relative reparse point differs"
        );
        Ok((canonical, parent))
    }
    fn row(&self, ordinal: usize) -> Result<WindowsAliasNativeRow> {
        ensure!(
            ordinal < self.length,
            "reopened alias ordinal exceeds complete plan"
        );
        let ram = self.scratch.lease_ram(
            self.admission
                .budget
                .max_row_bytes
                .checked_mul(4)
                .context("alias row RAM overflow")?,
        )?;
        let alias: WindowsPathAlias = self.entries.get(ordinal as u64)?;
        let (canonical_object_index, parent_object_index) =
            Self::validate_row(self.expected, &self.indices, &alias)?;
        Ok(WindowsAliasNativeRow {
            alias,
            canonical_object_index,
            parent_object_index,
            _ram: ram,
        })
    }
    fn revalidate_owner(&self) -> Result<()> {
        self.entries.revalidate()?;
        self.indices.revalidate()?;
        self.namespace.revalidate()?;
        self.expected.require_resource_owner(self.admission)?;
        Ok(())
    }
    pub(crate) fn semantic_digest(&self) -> [u8; 32] {
        self.semantic_sha256
    }
    pub(crate) fn len(&self) -> usize {
        self.length
    }
}
impl n2r_win32::shadow_native::windows_aliases::WindowsAliasInputDomain
    for ReopenedWindowsAliasNativeDomain<'_>
{
    type Alias = WindowsAliasNativeRow;
    fn len(&self) -> usize {
        self.length
    }
    fn alias(&self, index: usize) -> io::Result<Self::Alias> {
        self.row(index).map_err(io::Error::other)
    }
    fn source_inspection_sha256(&self) -> [u8; 32] {
        self.admission.source_inspection_sha256
    }
    fn semantic_sha256(&self) -> io::Result<[u8; 32]> {
        Ok(self.semantic_sha256)
    }
    fn require_resource_metadata(&self, admission: SourceResourceAdmission) -> io::Result<()> {
        if admission != self.admission {
            return Err(io::Error::other(
                "reopened alias resource admission differs",
            ));
        }
        self.revalidate_owner().map_err(io::Error::other)
    }
    fn revalidate(&self) -> io::Result<()> {
        self.revalidate_owner().map_err(io::Error::other)
    }
}
