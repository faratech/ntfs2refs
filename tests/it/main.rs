//! Every integration test of the converter, as one executable.
//!
//! Each file here was a test executable of its own: forty-two of them, every
//! one linked against the whole library, which was most of what a test run
//! spent before it ran a test. As modules of one executable they are linked
//! once. `cargo test --test it <module>::` runs one file's tests.

// Shared by the modules below, and by unit tests of the library, which
// include files of it by path.
#[allow(dead_code)]
#[path = "../support/mod.rs"]
mod support;

mod after_marker_durability;
mod cli;
mod current_documents;
mod feature_matrix;
mod lab_native;
mod lab_reconstruct;
mod lab_retired_scripts;
mod ntfs_admission;
mod ntfs_allocation;
mod ntfs_allocation_integration;
mod ntfs_attestation;
mod ntfs_attribute_list;
mod ntfs_backup;
mod ntfs_compression;
mod ntfs_data_attestation;
mod ntfs_inspection;
mod ntfs_internal;
mod ntfs_log;
mod ntfs_metadata_roles;
mod ntfs_namespace;
mod ntfs_namespace_attestation;
mod ntfs_namespace_integration;
mod ntfs_plain_stream;
mod ntfs_security;
mod ntfs_security_integration;
mod ntfs_source_view;
mod ntfs_stream_attestation;
mod ntfs_streaming_budget;
mod ntfs_transactions;
mod ntfs_volume_object_id;
mod recovery_model;
mod refs_bootstrap;
mod refs_containers;
mod refs_inspection;
mod refs_node;
mod refs_virtual_roots;
mod refs_write_set;
mod retained_compare;
mod rollback_completion_faults;
mod shadow_tree;
mod source_volume_label;
mod volume_manifest_cli;
