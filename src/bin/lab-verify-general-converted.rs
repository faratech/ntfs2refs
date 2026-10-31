//! Repeatable native ReFS verification after the original data disk has
//! crossed journal handoff. No journal replay or raw partition write exists.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        capture_mount_paths_general, mounted_filesystem_general, rediscover_general_volume_wait,
        shadow_native,
    };
    use ntfs2refs::{general_conversion, general_reconstruct, ntfs_attestation, shadow_tree};
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        collections::BTreeSet,
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        /// Read-only locator for an actual public allocation-bounded conversion.
        /// This does not open its journal/ticket or grant recovery authority.
        #[arg(long, requires = "allocation_bundle_sha256")]
        allocation_bundle: Option<PathBuf>,
        #[arg(long, requires = "allocation_bundle")]
        allocation_bundle_sha256: Option<String>,
        #[arg(long)]
        output: PathBuf,
        /// Save bounded native observations without treating them as a passed
        /// semantic verification. This never authorizes conversion writes.
        #[arg(long)]
        diagnose_only: bool,
        /// Require admitted retained bytes to keep their original physical
        /// addresses in fresh native same-file retrieval mappings.
        #[arg(long, conflicts_with = "diagnose_only")]
        verify_retained_positions: bool,
        /// Pinned report from the bounded ReFS mutation workload. Allows only
        /// its exact recorded root basic-info change after reboot.
        #[arg(
            long,
            requires = "mutation_report_sha256",
            conflicts_with = "diagnose_only"
        )]
        mutation_report: Option<PathBuf>,
        #[arg(long, requires = "mutation_report")]
        mutation_report_sha256: Option<String>,
    }
    #[derive(serde::Deserialize)]
    struct MutationEvidence {
        schema_version: u32,
        kind: String,
        run_id: String,
        initial_bytes: u64,
        grown_bytes: u64,
        truncated_bytes: u64,
        directory_entries_created: u32,
        mutation_directory_removed: bool,
        only_new_test_paths_written: bool,
        root_basic_before: Vec<u8>,
        root_basic_after: Vec<u8>,
        #[serde(default)]
        request_sha256: Option<String>,
        #[serde(default)]
        source_resource_profile: Option<ntfs2refs::ntfs_admission::ResourceProfile>,
    }
    #[derive(serde::Deserialize)]
    struct InputPin {
        path: PathBuf,
        sha256: String,
    }
    // Only read-only verification inputs are consumed. Other pinned bundle
    // entries (journal/plan/ticket) are deliberately not loaded or replayed.
    #[derive(serde::Deserialize)]
    struct AllocationBundle {
        schema_version: u32,
        kind: String,
        request: InputPin,
        expectation: InputPin,
        verification: InputPin,
        source: n2r_win32::general_layout::GeneralDiskBinding,
        serialized_bundle_grants_recovery_authority: bool,
    }
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllocationVerification {
        expected_mount_paths: Vec<String>,
        expected_source_label: n2r_win32::volume_label::VolumeLabel,
    }
    struct VerificationInput {
        pair: n2r_win32::general_layout::GeneralSourceShadowBinding,
        source_resource_profile: Option<ntfs2refs::ntfs_admission::ResourceProfile>,
        expected_tree_sha256: String,
        expected_source_label: Option<n2r_win32::volume_label::VolumeLabel>,
        expected_mount_paths: Option<Vec<String>>,
        comparison: Option<ntfs2refs::retained_compare::RetainedCompareRequest>,
    }
    fn ordinary_c_input(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute(),
            "allocation verification inputs need absolute C: paths"
        );
        for component in path.components() {
            ensure!(
                match component {
                    Component::Prefix(prefix) => matches!(prefix.kind(), Prefix::Disk(b'C' | b'c')),
                    Component::RootDir | Component::Normal(_) => true,
                    _ => false,
                },
                "allocation verification input is not a traversal-free C: path"
            );
        }
        for ancestor in path.ancestors() {
            let metadata = fs::symlink_metadata(ancestor)?;
            ensure!(
                metadata.file_attributes() & 0x400 == 0,
                "reparse allocation verification ancestry refused"
            );
            ensure!(
                if ancestor == path {
                    metadata.is_file()
                } else {
                    metadata.is_dir()
                },
                "ordinary allocation verification file/ancestry required"
            );
        }
        Ok(())
    }
    fn pinned(path: &PathBuf, expected: &str, max: u64) -> Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "verification input is not an ordinary bounded file"
        );
        let mut file = OpenOptions::new().read(true).share_mode(1).open(path)?;
        let mut bytes = Vec::new();
        (&mut file).take(max + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 <= max
                && expected.len() == 64
                && hex::encode(Sha256::digest(&bytes)) == expected,
            "verification input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() <= 16 * 1024 * 1024,
            "verification report exceeds bound"
        );
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    ensure!(!args.output.exists(), "fresh verification output required");
    let request_bytes = pinned(&args.request, &args.request_sha256, 131072)?;
    let request = if let (Some(path), Some(pin)) =
        (&args.allocation_bundle, &args.allocation_bundle_sha256)
    {
        ordinary_c_input(path)?;
        ordinary_c_input(&args.request)?;
        ordinary_c_input(&args.expectation)?;
        let bundle: AllocationBundle = serde_json::from_slice(&pinned(path, pin, 65536)?)?;
        ensure!(
            bundle.schema_version == 1
                && bundle.kind == "allocation-bounded-recovery-bundle"
                && !bundle.serialized_bundle_grants_recovery_authority
                && bundle.request.path == args.request
                && bundle.request.sha256 == args.request_sha256
                && bundle.expectation.path == args.expectation
                && bundle.expectation.sha256 == args.expectation_sha256,
            "allocation bundle request/expectation pins differ from the explicit inputs"
        );
        let public: general_conversion::Request = serde_json::from_slice(&request_bytes)?;
        public.validate()?;
        ensure!(
            bundle.source == public.pair.source,
            "allocation bundle source differs from request"
        );
        ordinary_c_input(&bundle.verification.path)?;
        let verification: AllocationVerification = serde_json::from_slice(&pinned(
            &bundle.verification.path,
            &bundle.verification.sha256,
            65536,
        )?)?;
        verification.expected_source_label.validate()?;
        let mount_paths = Some(verification.expected_mount_paths);
        ntfs2refs::general_shadow::validate_mount_paths(&mount_paths)?;
        VerificationInput {
            pair: public.pair,
            source_resource_profile: public.source_resource_profile,
            expected_tree_sha256: bundle.expectation.sha256,
            expected_source_label: Some(verification.expected_source_label),
            expected_mount_paths: mount_paths,
            comparison: None,
        }
    } else {
        let legacy: general_reconstruct::Request = serde_json::from_slice(&request_bytes)?;
        legacy.validate()?;
        VerificationInput {
            pair: legacy.pair,
            source_resource_profile: legacy.source_resource_profile,
            expected_tree_sha256: legacy.expected_tree_sha256,
            expected_source_label: legacy.expected_source_label,
            expected_mount_paths: legacy.expected_mount_paths,
            comparison: Some(legacy.comparison),
        }
    };
    ensure!(
        !args.verify_retained_positions || request.comparison.is_some(),
        "--verify-retained-positions requires the legacy admitted comparison; allocation bundle mode has none"
    );
    let resources = request.source_resource_profile.unwrap_or_default();
    let expected_bytes = pinned(
        &args.expectation,
        &args.expectation_sha256,
        16 * 1024 * 1024,
    )?;
    ensure!(
        args.expectation_sha256 == request.expected_tree_sha256,
        "post-handoff expected tree differs from request"
    );
    let expected: shadow_tree::ExpectedTree = serde_json::from_slice(&expected_bytes)?;
    expected.validate_with_resource_profile(resources)?;
    let mutation = if let (Some(path), Some(pin)) =
        (&args.mutation_report, &args.mutation_report_sha256)
    {
        let proof: MutationEvidence = serde_json::from_slice(&pinned(path, pin, 8 * 1024 * 1024)?)?;
        ensure!(
            proof.source_resource_profile == request.source_resource_profile
                && (proof.request_sha256.as_deref() == Some(args.request_sha256.as_str())
                    || (proof.request_sha256.is_none()
                        && request.source_resource_profile.is_none())),
            "mutation report request/profile binding differs"
        );
        ensure!(
            proof.schema_version == 1
                && proof.kind == "general-refs-mutation-workload"
                && proof.run_id.len() == 32
                && proof
                    .run_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && proof.initial_bytes == 50 * 1024 * 1024
                && proof.grown_bytes == 80 * 1024 * 1024
                && proof.truncated_bytes == 10 * 1024 * 1024
                && proof.directory_entries_created == 128
                && proof.mutation_directory_removed
                && proof.only_new_test_paths_written
                && proof.root_basic_before.len() == 40
                && proof.root_basic_after.len() == 40
                && proof.root_basic_before[..8] == proof.root_basic_after[..8]
                && proof.root_basic_before[32..] == proof.root_basic_after[32..],
            "pinned post-mutation root evidence differs"
        );
        Some(proof)
    } else {
        None
    };
    let mut events = Vec::new();
    let mut pair = request.pair.clone();
    pair.source = rediscover_general_volume_wait(pair.source, &mut events)?;
    let filesystem = mounted_filesystem_general(pair.source.clone(), &mut events)?;
    let (mount_paths, mount_paths_error) =
        match capture_mount_paths_general(pair.source.clone(), &mut events) {
            Ok(observation) => (Some(observation), None),
            Err(error) => (None, Some(error.to_string())),
        };
    let input: Vec<_> = expected
        .objects
        .iter()
        .map(|object| shadow_native::Input {
            components: &object.path,
            additional_names: &object.additional_names,
            sparse: object.sparse.as_ref(),
            named_streams: ntfs2refs::general_shadow::native_named_streams(object),
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            expected_api_security: object.api_security.as_deref(),
            extended_attributes: object.extended_attributes.as_ref(),
            reparse: object.reparse.as_ref(),
            payload: &[],
            expected_length: if object.directory {
                None
            } else {
                Some(object.length)
            },
            expected_sha256: if object.directory {
                None
            } else {
                object.sha256.as_deref()
            },
            source_offset: object.source_offset,
            source_runs: object
                .source_extents
                .iter()
                .map(|run| shadow_native::SourceRun {
                    logical_offset: run.logical_offset,
                    physical_offset: run.physical_offset,
                    length: run.length,
                })
                .collect(),
        })
        .collect();
    let same_security = |a: &[u8], b: &[u8]| {
        ntfs_attestation::same_security(a, b)
            .map_err(|error| std::io::Error::other(error.to_string()))
    };
    let attempted = if filesystem == "ReFS" {
        if args.diagnose_only {
            shadow_native::observe_general_converted_ordinary_with_resource_profile(
                pair,
                &input,
                request.expected_source_label.as_ref(),
                same_security,
                resources.native_profile(),
            )
        } else if let Some(proof) = &mutation {
            let mut root_basic = [0u8; 40];
            root_basic.copy_from_slice(&proof.root_basic_after);
            shadow_native::verify_general_converted_after_mutation_ordinary_with_resource_profile(
                pair,
                &input,
                root_basic,
                request.expected_source_label.as_ref(),
                same_security,
                resources.native_profile(),
            )
        } else {
            if let Some(label) = &request.expected_source_label {
                shadow_native::verify_general_converted_ordinary_with_label_and_resource_profile(
                    pair,
                    &input,
                    label,
                    same_security,
                    resources.native_profile(),
                )
            } else {
                shadow_native::verify_general_converted_ordinary_with_resource_profile(
                    pair,
                    &input,
                    same_security,
                    resources.native_profile(),
                )
            }
        }
    } else {
        Err(std::io::Error::other(
            "original data disk is not mounted as ReFS",
        ))
    };
    let observation_complete = attempted.is_ok();
    let ordinary_tree_verified = !args.diagnose_only && observation_complete;
    let retained_positions = if args.verify_retained_positions {
        attempted
            .as_ref()
            .map_err(|error| error.to_string())
            .and_then(|native| {
                let tree = shadow_tree::Tree {
                    profile: resources.ordinary_shadow_profile(),
                    objects: expected.objects.clone(),
                    logical_bytes: expected.logical_bytes,
                    internal_replacement_pending: expected.internal_replacement_pending.clone(),
                };
                ntfs2refs::tree_placement::mappings_from_native(&tree, &native.native)
                    .and_then(|mappings| {
                        ntfs2refs::tree_placement::verify_native_retained_positions(
                            &tree,
                            &mappings,
                            request
                                .comparison
                                .as_ref()
                                .context("retained comparison is absent")?,
                        )
                    })
                    .map(Some)
                    .map_err(|error| error.to_string())
            })
    } else {
        Ok(None)
    };
    let mount_paths_preserved = request.expected_mount_paths.as_ref().map(|expected| {
        let before: BTreeSet<_> = expected.iter().map(|path| path.to_lowercase()).collect();
        mount_paths.as_ref().is_some_and(|observation| {
            let after: BTreeSet<_> = observation
                .paths
                .iter()
                .map(|path| path.to_lowercase())
                .collect();
            before == after
        })
    });
    let success = ordinary_tree_verified
        && mount_paths_preserved != Some(false)
        && retained_positions.is_ok();
    let error = if args.diagnose_only && observation_complete {
        Some("diagnostic native observation only; preservation comparison not passed".into())
    } else {
        retained_positions.as_ref().err().cloned().or_else(|| {
            attempted
                .as_ref()
                .err()
                .map(ToString::to_string)
                .or_else(|| {
                    (mount_paths_preserved == Some(false))
                        .then(|| "converted ReFS mount paths differ from NTFS source".into())
                })
        })
    };
    save(
        &args.output,
        &serde_json::json!({"schema_version":1,"kind":if args.diagnose_only {"general-post-handoff-refs-diagnostic"} else {"general-post-handoff-refs-verification"},
            "request_sha256":args.request_sha256,"expected_tree_sha256":args.expectation_sha256,
            "verification_input_mode":if args.allocation_bundle.is_some() {"allocation_bundle"} else {"general_reconstruction"},
            "allocation_bundle_sha256":args.allocation_bundle_sha256,
            "filesystem":filesystem,"mount_paths":mount_paths,
            "mount_paths_error":mount_paths_error,"mount_paths_preserved":mount_paths_preserved,
            "native":attempted.ok(),"error":error,
            "events":events,"source_payload_writes":0,
            "ordinary_tree_verified":ordinary_tree_verified,
            "retained_physical_positions":retained_positions.ok().flatten(),
            "diagnostic_only":args.diagnose_only,"observation_complete":observation_complete,
            "mutation_report_sha256":args.mutation_report_sha256,
            "post_mutation_root_policy":mutation.is_some(),
            "success":success,"production_conversion_qualified":false}),
    )?;
    ensure!(
        success || (args.diagnose_only && observation_complete),
        "post-handoff ReFS verification refused; report saved"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("post-handoff verification requires Windows on the owning machine");
    std::process::exit(1);
}
