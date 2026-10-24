//! Native I/O boundary. The main converter crate continues to forbid unsafe Rust.
//! No formatter is exposed. An offline partition remains offline when dropped;
//! making it mountable requires a separate explicit handoff operation.
#[cfg(windows)]
pub mod journal_file;
pub mod layout;
#[cfg(windows)]
mod native;
#[cfg(windows)]
pub use native::{NativeEvent, OfflinePartition, PartitionSnapshot, WritePolicy};
