//! Offline filesystem inspection and feasibility-gated conversion planning.
//!
//! The experimental ReFS writer is deliberately unavailable until native-driver
//! validation establishes a complete format profile and commit protocol.
#[cfg(windows)]
pub(crate) mod artifact_arena;
pub mod block_io;
#[cfg(windows)]
pub(crate) mod boot_alias;
pub mod boot_profile;
pub mod capability_evidence;
#[cfg(windows)]
pub(crate) mod compact_recovery_bundle;
pub(crate) mod confirmation;
pub mod disclaimer;
pub mod drive_cli;
pub(crate) mod drive_recovery;
pub(crate) mod execution_mode;
#[cfg(windows)]
pub(crate) mod general_composite_target;
#[cfg(windows)]
pub(crate) mod general_conversion;
#[cfg(windows)]
pub(crate) mod general_qualification;
#[cfg(windows)]
pub(crate) mod general_reconstruct;
#[cfg(windows)]
pub(crate) mod general_recovery;
#[cfg(windows)]
pub(crate) mod general_shadow;
#[cfg(windows)]
pub(crate) mod general_source_admission;
#[cfg(windows)]
pub(crate) mod general_target_preservation;
pub(crate) mod interrupted_marker;
#[cfg(windows)]
pub mod lab_native;
#[cfg(windows)]
pub(crate) mod lab_native_reconstruct;
pub mod lab_reconstruct;
pub mod ntfs_admission;
pub mod ntfs_allocation;
pub mod ntfs_attestation;
pub mod ntfs_attribute_list;
pub mod ntfs_backup;
pub mod ntfs_compression;
pub mod ntfs_data_attestation;
pub(crate) mod ntfs_extended_attributes;
pub(crate) mod ntfs_file_attributes;
pub mod ntfs_index;
pub mod ntfs_inspect;
pub mod ntfs_internal;
pub mod ntfs_log;
pub mod ntfs_namespace;
pub mod ntfs_namespace_attestation;
#[cfg(windows)]
pub(crate) mod ntfs_preparation;
pub(crate) mod ntfs_reparse;
pub mod ntfs_security;
pub mod ntfs_source_view;
#[cfg(windows)]
mod ntfs_storage_class;
pub mod ntfs_stream_attestation;
pub mod ntfs_stream_plan;
pub mod ntfs_transactions;
#[cfg(windows)]
pub(crate) mod object_id_disposition;
pub(crate) mod panic_report;
#[cfg(windows)]
pub(crate) mod parallel_digest;
pub(crate) mod payload_copy_plan;
pub mod planner;
pub(crate) mod preparation_progress;
#[cfg(windows)]
pub(crate) mod preparation_resume;
pub(crate) mod refs_allocator;
pub mod refs_bootstrap;
pub mod refs_containers;
pub(crate) mod refs_extent_refs;
pub(crate) mod refs_hybrid;
pub mod refs_inspect;
pub(crate) mod refs_mlog_refs;
pub mod refs_node;
pub(crate) mod refs_object_refs;
pub(crate) mod refs_record_refs;
pub(crate) mod refs_required_ranges;
pub(crate) mod refs_retained_allocation;
pub(crate) mod refs_security_descriptor;
#[cfg(windows)]
pub(crate) mod refs_security_integration;
pub(crate) mod refs_security_patch;
#[cfg(windows)]
pub(crate) mod refs_security_repair;
pub(crate) mod refs_split_refs;
pub mod refs_virtual_roots;
pub mod refs_write_set;
#[cfg(windows)]
pub(crate) mod resource_finalize;
#[cfg(windows)]
#[doc(hidden)]
pub mod resource_partition_alpha;
#[cfg(windows)]
pub(crate) mod resource_preparation;
#[cfg(windows)]
pub(crate) mod resource_prepared_bundle;
#[cfg(windows)]
pub(crate) mod resource_prepared_offline_apply;
#[cfg(windows)]
pub(crate) mod resource_recovery;
#[cfg(windows)]
pub(crate) mod resource_review;
pub mod retained_compare;
#[cfg(windows)]
pub(crate) mod review;
pub(crate) mod run_memory;
pub mod running_windows;
pub(crate) mod selected_capacity;
pub(crate) mod selected_journal;
pub(crate) mod selected_ownership;
pub mod shadow_tree;
pub(crate) mod short_name_disposition;
#[cfg(windows)]
pub(crate) mod source_fingerprint;
pub mod source_volume_label;
pub(crate) mod verification_policy;
#[cfg(windows)]
pub(crate) mod verify_first;

#[cfg(windows)]
pub(crate) mod resource_prepared_terminal;
