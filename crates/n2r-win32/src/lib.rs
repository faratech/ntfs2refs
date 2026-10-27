//! Native I/O boundary. The main converter crate continues to forbid unsafe Rust.
//! No formatter is exposed. An offline partition remains offline when dropped;
//! making it mountable requires a separate explicit handoff operation.
pub mod attestation;
#[cfg(windows)]
mod attestation_native;
pub mod bitmap_layout;
pub mod bitmap_paging;
pub mod bitmap_streaming;
pub mod discovery;
pub mod general_layout;
#[cfg(windows)]
pub mod journal_file;
pub mod layout;
pub mod logical_hash;
pub mod namespace_layout;
#[cfg(windows)]
mod namespace_native;
pub mod reference_file;
#[cfg(windows)]
pub mod reference_import;
pub mod region_layout;
pub mod retention_layout;
pub mod retrieval_paging;
#[cfg(windows)]
pub mod shadow_native;
#[cfg(windows)]
pub mod source_cancel;
pub mod stream_layout;
#[cfg(windows)]
mod stream_native;
#[cfg(windows)]
pub mod txf_native;
pub mod volume_label;
#[cfg(windows)]
pub use attestation_native::collect_file_metadata;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{
    DriveLetterRestore, GeneralAllocationFreezeWitness, GeneralAllocationPhase,
    GeneralAllocationSnapshot, GeneralDiskState, GeneralFreezeObservation, GeneralFrozenPartition,
    GeneralJournaledPartition, GeneralLiveNtfsObservation, GeneralLiveRefsObservation,
    GeneralLockedPartition, GeneralPartitionReader, GeneralProbe, LiveNtfsObservation,
    MountPathObservation, NativeEvent, OfflinePartition, PartitionSnapshot, WritePolicy,
    capture_mount_paths_general, mounted_filesystem_general, observe_general_disk_state_readonly,
    probe_general, rediscover_general_volume, rediscover_general_volume_wait,
    restore_drive_letter_general,
};
