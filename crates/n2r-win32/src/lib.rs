//! Native I/O boundary. The main converter crate continues to forbid unsafe Rust.
//! No formatter is exposed. An offline partition remains offline when dropped;
//! making it mountable requires a separate explicit handoff operation.
/// Most native control events one batch may hold before it must be drained
/// into the event log. It bounds an in-memory diagnostic list, nothing on disk.
/// It was 128, which the Windows-volume target capture exceeds: observing the
/// shadow with its short-name aliases issues more controls between drains than
/// any data-volume path did.
pub const MAX_BATCH_EVENTS: usize = 1024;
pub mod attestation;
#[cfg(windows)]
mod attestation_native;
#[cfg(windows)]
pub mod attestation_partition;
pub mod bitmap_layout;
#[cfg(windows)]
mod bitmap_observation;
pub mod bitmap_paging;
pub mod bitmap_streaming;
pub mod bitmap_window;
#[cfg(windows)]
pub mod bitmap_window_native;
pub mod bitmap_window_transport;
pub mod content_digest;
#[cfg(windows)]
pub mod directory_case;
pub mod discovery;
pub mod drive_inventory;
pub mod extended_attributes;
#[cfg(windows)]
pub mod extended_attributes_native;
#[cfg(windows)]
pub mod extent_observation;
#[cfg(windows)]
pub mod file_storage;
pub mod general_layout;
#[cfg(windows)]
pub mod io_profile;
#[cfg(windows)]
pub mod journal_file;
#[cfg(windows)]
pub mod lab_compression_fixture;
pub mod lab_hold;
#[cfg(windows)]
pub mod lab_job;
#[cfg(windows)]
pub mod lab_ntfs_fragmentation;
#[cfg(windows)]
pub mod lab_reparse_fixture;
#[cfg(windows)]
pub mod lab_security_fixture;
pub mod layout;
#[cfg(windows)]
pub mod layout_residual_pages;
pub mod logical_hash;
#[cfg(windows)]
pub mod managed_shadow;
#[cfg(windows)]
pub mod metadata_pages;
pub mod namespace_layout;
#[cfg(windows)]
mod namespace_native;
#[cfg(windows)]
pub mod ntfs_preparation;
#[cfg(windows)]
pub mod observation_pages;
pub mod perf;
#[cfg(windows)]
pub mod preparation_shadow;
#[cfg(windows)]
pub mod process_io;
pub mod progress;
#[cfg(windows)]
pub(crate) mod query_scratch;
pub mod stack_sampler;
#[cfg(windows)]
pub use native::recovery_boot;
#[cfg(windows)]
pub use native::recovery_image;
pub mod reference_file;
#[cfg(windows)]
pub mod reference_import;
pub mod refs_security_descriptor;
pub mod region_layout;
pub mod reparse_layout;
#[cfg(windows)]
pub mod reparse_native;
#[cfg(windows)]
pub mod resource_native;
pub mod retention_layout;
pub mod retrieval_paging;
#[cfg(windows)]
pub mod run_environment;
pub mod security_descriptor;
#[cfg(windows)]
pub mod sha256_native;
#[cfg(windows)]
pub(crate) mod shadow_evacuation;
pub mod shadow_names;
#[cfg(windows)]
pub mod shadow_native;
#[cfg(windows)]
pub mod source_cancel;
pub mod sparse_layout;
pub mod stream_layout;
#[cfg(windows)]
mod stream_native;
pub mod target_cluster;
pub mod target_refs_version;
pub mod tree_resources;
#[cfg(windows)]
pub mod txf_native;
#[cfg(windows)]
pub mod windows_alias_native;
#[cfg(windows)]
pub mod windows_txf;
#[cfg(windows)]
pub use windows_txf::VerifiedWindowsTxfMarkers;
#[cfg(windows)]
pub mod windows_object_ids;
#[cfg(windows)]
pub use windows_object_ids::VerifiedWindowsObjectIds;
pub mod verify_policy;
pub mod volume_label;
pub mod volume_manifest;
#[cfg(windows)]
pub mod volume_policy;
#[cfg(windows)]
pub mod vss_observation;
pub mod windows_build;
#[cfg(windows)]
pub use attestation_native::collect_file_metadata;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::BootStorageHintNormalization;
#[cfg(windows)]
pub use native::PartitionMixedReplayGate;
#[cfg(windows)]
pub use native::PartitionTerminalNativeObservation;
#[cfg(windows)]
pub use native::forbid_disk_state_changes;
pub use native::forbid_raw_write_activation;
#[cfg(windows)]
pub use native::offline_environment;
#[cfg(windows)]
pub use native::partition_isolation;
#[cfg(windows)]
pub use native::partition_lifecycle;
#[cfg(windows)]
pub use native::partition_restoration;
#[cfg(windows)]
pub use native::{
    BorrowedPagedWriter, DriveLetterRestore, GeneralAllocationFreezeWitness,
    GeneralAllocationPhase, GeneralAllocationSnapshot, GeneralDiskState,
    GeneralExclusiveRecoveryTarget, GeneralFreezeObservation, GeneralFrozenLane,
    GeneralFrozenPartition, GeneralFrozenSourceReadScope, GeneralJournalReadView,
    GeneralJournaledPartition, GeneralLiveConvertedObservation, GeneralLiveNtfsObservation,
    GeneralLivePagedNtfsObservation, GeneralLiveRefsLayoutObservation, GeneralLiveRefsObservation,
    GeneralLockedPartition, GeneralPartitionReader, GeneralProbe, GeneralReadonlyAllocationWitness,
    HeldPagedWritePolicy, LiveNtfsObservation, MountPathObservation, NativeEvent,
    NativeSourceObservationOrigin, OfflinePartition, PagedPolicyIndexBuilder,
    PagedPolicyIndexFacts, PagedPolicyIndexRow, PagedRecoveryDirection, PagedRecoveryPins,
    PartitionSnapshot, SourceCacheContinuity, SourceCacheFingerprintDomain,
    SourceCacheFingerprintMismatch, SourceCacheRefreshDomain, SourceCacheRefreshRow, WritePolicy,
    capture_mount_paths_for_journal, capture_mount_paths_general, current_windows_directory,
    mounted_filesystem_general, note_selected_new_bytes_verified,
    observe_general_disk_state_readonly, probe_general, rediscover_general_volume,
    rediscover_general_volume_wait, restore_drive_letter_general, selected_new_bytes_verified,
};
#[cfg(windows)]
pub use native::{
    PartitionClosedJournalObservation, PartitionHandoffWitness, PartitionJournalReadView,
    PartitionPagedWriter, PartitionSourceAdmissionGate, PartitionTerminalKind,
    authenticate_partition_closed_journal,
};
#[cfg(windows)]
pub use native::{PartitionOwnerState, PartitionOwnerToken, PartitionScopedOwner};

#[cfg(windows)]
pub mod windows_boot_geometry;
