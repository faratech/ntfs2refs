//! Preparation eligibility mirrors the existing ordinary NTFS move policy.
//! It is stricter than conversion support and never grants native authority.
use crate::ntfs_inspect::{FileInventory, MetadataRole, StreamInventory};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Eligibility {
    PlainInitializedUnnamedUserData,
    SystemMetadata,
    UnclassifiedMetadataRole,
    Directory,
    ExtensionRecord,
    UnresolvedFileIdentity,
    NamedStream,
    ResidentStream,
    SparseStream,
    CompressedStream,
    EncryptedStream,
    OtherStreamFlags,
    MissingStandardInformation,
    UnsupportedFileAttributes,
    UninitializedData,
    AttributeMismatch,
    InvalidPlainLayout,
    NoInitializedWholeClusters,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Outcome {
    NoObservedCollision,
    SkippedUnsupported,
    CollisionOutsideInitializedWholeClusters,
    AllEligibleCollisionsHaveSuggestions,
    SomeEligibleCollisionsLackOutsideHeadroom,
}
pub(super) fn classify(
    file: &FileInventory,
    stream: &StreamInventory,
    cluster: u64,
) -> Eligibility {
    use Eligibility::*;
    if file.is_directory {
        return Directory;
    }
    if file.record_number < 16
        || file.is_metadata
        || matches!(
            file.metadata_role,
            MetadataRole::ReservedSystemRecord | MetadataRole::ExtendDescendantCandidate
        )
    {
        return SystemMetadata;
    }
    if file.base_file_reference != 0 {
        return ExtensionRecord;
    }
    if file.metadata_role != MetadataRole::OutsideExtendCandidate
        || file.metadata_role_issue.is_some()
    {
        return UnclassifiedMetadataRole;
    }
    if file.sequence_number == 0 || file.names.is_empty() {
        return UnresolvedFileIdentity;
    }
    if !stream.name_utf16.is_empty() || !stream.name.is_empty() {
        return NamedStream;
    }
    if stream.resident {
        return ResidentStream;
    }
    if stream.flags & 0x8000 != 0 {
        return SparseStream;
    }
    if stream.flags & 1 != 0 {
        return CompressedStream;
    }
    if stream.flags & 0x4000 != 0 {
        return EncryptedStream;
    }
    if stream.flags != 0 {
        return OtherStreamFlags;
    }
    let Some(standard) = &file.standard_information else {
        return MissingStandardInformation;
    };
    if standard.file_attributes & 0x5e15 != 0 {
        return UnsupportedFileAttributes;
    }
    if stream.initialized_size != stream.logical_size {
        return UninitializedData;
    }
    let mut matching = file
        .attributes
        .iter()
        .filter(|a| a.type_code == 0x80 && a.name_utf16.is_empty());
    let Some(a) = matching.next() else {
        return AttributeMismatch;
    };
    if matching.next().is_some()
        || file
            .streams
            .iter()
            .filter(|s| s.name_utf16.is_empty())
            .count()
            != 1
        || a.resident
        || a.flags != 0
        || a.lowest_vcn != 0
        || a.compression_unit != 0
        || a.total_allocated_size.is_some()
        || a.extents != stream.extents
        || a.logical_size != stream.logical_size
        || a.initialized_size != stream.initialized_size
        || a.allocated_size != stream.allocated_size
    {
        return AttributeMismatch;
    }
    let Some(eof) = stream.logical_size.checked_next_multiple_of(cluster) else {
        return InvalidPlainLayout;
    };
    if stream.allocated_size < eof || !stream.allocated_size.is_multiple_of(cluster) {
        return InvalidPlainLayout;
    }
    let mut end = 0u64;
    for extent in &stream.extents {
        if extent.logical_offset != end
            || extent.length == 0
            || !extent.length.is_multiple_of(cluster)
            || !extent
                .physical_offset
                .is_some_and(|p| p.is_multiple_of(cluster))
        {
            return InvalidPlainLayout;
        }
        let Some(next) = end.checked_add(extent.length) else {
            return InvalidPlainLayout;
        };
        end = next;
    }
    if end != stream.allocated_size {
        return InvalidPlainLayout;
    }
    if stream.initialized_size < cluster {
        return NoInitializedWholeClusters;
    }
    PlainInitializedUnnamedUserData
}
