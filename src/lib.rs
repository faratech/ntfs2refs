//! Offline filesystem inspection and feasibility-gated conversion planning.
//!
//! The experimental ReFS writer is deliberately unavailable until native-driver
//! validation establishes a complete format profile and commit protocol.
pub mod block_io;
pub mod corpus;
pub mod extent_adoption;
pub mod fixed_vhd;
#[cfg(windows)]
pub mod general_lab;
#[cfg(windows)]
pub mod general_reconstruct;
#[cfg(windows)]
pub mod general_shadow;
#[cfg(windows)]
pub mod general_source_admission;
#[cfg(windows)]
pub mod general_target_preservation;
#[cfg(windows)]
pub mod lab_native;
#[cfg(windows)]
pub mod lab_native_reconstruct;
pub mod lab_reconstruct;
#[cfg(windows)]
pub mod lab_tree_expectation;
#[cfg(windows)]
pub mod lab_tree_reconstruct;
pub mod ntfs_admission;
pub mod ntfs_allocation;
pub mod ntfs_attestation;
pub mod ntfs_backup;
pub mod ntfs_data_attestation;
#[cfg(windows)]
pub mod ntfs_freeze;
pub mod ntfs_index;
pub mod ntfs_inspect;
pub mod ntfs_internal;
pub mod ntfs_log;
pub mod ntfs_namespace;
pub mod ntfs_namespace_attestation;
pub mod ntfs_security;
pub mod ntfs_source_view;
pub mod ntfs_stream_attestation;
pub mod ntfs_stream_plan;
pub mod ntfs_transactions;
pub mod planner;
pub mod refs_allocator;
pub mod refs_bootstrap;
pub mod refs_containers;
pub mod refs_cow_overlay;
pub mod refs_inspect;
pub mod refs_node;
pub mod refs_retained_allocation;
pub mod refs_virtual_roots;
pub mod refs_write_set;
pub mod retained_compare;
#[cfg(windows)]
pub mod shadow_freeze;
pub mod shadow_tree;
pub mod tree_placement;
