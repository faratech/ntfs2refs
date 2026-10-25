//! Native I/O boundary. The main converter crate continues to forbid unsafe Rust.
//! No formatter is exposed. An offline partition remains offline when dropped;
//! making it mountable requires a separate explicit handoff operation.
pub mod attestation;
#[cfg(windows)]
mod attestation_native;
pub mod bitmap_layout;
pub mod general_layout;
#[cfg(windows)]
pub mod journal_file;
pub mod layout;
pub mod logical_hash;
pub mod namespace_layout;
#[cfg(windows)]
mod namespace_native;
pub mod region_layout;
#[cfg(windows)]
pub mod shadow_native;
pub mod stream_layout;
#[cfg(windows)]
mod stream_native;
#[cfg(windows)]
pub mod txf_native;
#[cfg(windows)]
pub use attestation_native::collect_file_metadata;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{
    GeneralDiskState, GeneralFrozenPartition, GeneralJournaledPartition, GeneralPartitionReader,
    GeneralProbe, LiveNtfsObservation, NativeEvent, OfflinePartition, PartitionSnapshot,
    WritePolicy, probe_general,
};
