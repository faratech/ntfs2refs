//! Native I/O boundary. The main converter crate continues to forbid unsafe Rust.
//! No formatter is exposed. An offline partition remains offline when dropped;
//! making it mountable requires a separate explicit handoff operation.
pub mod attestation;
#[cfg(windows)]
pub mod attestation_partition;
#[cfg(windows)]
mod attestation_native;
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
#[cfg(windows)]
pub mod preparation_shadow;
#[cfg(windows)]
pub mod process_io;
#[cfg(windows)]
pub use native::recovery_image;
#[cfg(windows)]
pub use native::recovery_boot;
pub mod reference_file;
#[cfg(windows)]
pub mod reference_import;
pub mod region_layout;
pub mod reparse_layout;
#[cfg(windows)]
pub mod reparse_native;
#[cfg(windows)]
pub mod resource_native;
pub mod retention_layout;
pub mod retrieval_paging;
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
pub mod tree_resources;
#[cfg(windows)]
pub mod txf_native;
pub mod volume_label;
#[cfg(windows)]
pub mod volume_policy;
#[cfg(windows)]
pub mod vss_observation;
#[cfg(windows)]
pub use attestation_native::collect_file_metadata;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::partition_isolation;
#[cfg(windows)]
pub use native::offline_environment;
#[cfg(windows)]
pub use native::partition_lifecycle;
#[cfg(windows)]
pub use native::partition_restoration;
#[cfg(windows)]
pub use native::PartitionTerminalNativeObservation;
#[cfg(windows)]
pub use native::{PartitionOwnerState, PartitionOwnerToken, PartitionScopedOwner};
#[cfg(windows)]
pub use native::PartitionMixedReplayGate;
#[cfg(windows)]
pub use native::{PartitionClosedJournalObservation, PartitionHandoffWitness,
    PartitionJournalReadView, PartitionPagedWriter, PartitionSourceAdmissionGate,
    PartitionTerminalKind, authenticate_partition_closed_journal};
#[cfg(windows)]
pub use native::{
    BorrowedPagedWriter, DriveLetterRestore, GeneralAllocationFreezeWitness, GeneralAllocationPhase,
    GeneralAllocationSnapshot, GeneralDiskState, GeneralExclusiveRecoveryTarget,
    GeneralFreezeObservation, GeneralFrozenLane, GeneralFrozenPartition, GeneralJournalReadView,
    GeneralJournaledPartition, GeneralLiveConvertedObservation, GeneralLiveNtfsObservation, GeneralLivePagedNtfsObservation,
    GeneralLiveRefsLayoutObservation, GeneralLiveRefsObservation, GeneralLockedPartition,
    GeneralPartitionReader, GeneralProbe, GeneralReadonlyAllocationWitness, HeldPagedWritePolicy,
    LiveNtfsObservation, MountPathObservation, NativeEvent, OfflinePartition,
    PagedPolicyIndexBuilder, PagedPolicyIndexFacts, PagedPolicyIndexRow, PagedRecoveryDirection,
    PagedRecoveryPins, PartitionSnapshot,
    WritePolicy, capture_mount_paths_for_journal, capture_mount_paths_general, mounted_filesystem_general,
    observe_general_disk_state_readonly, probe_general, current_windows_directory, rediscover_general_volume,
    rediscover_general_volume_wait, restore_drive_letter_general,
};
