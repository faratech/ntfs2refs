mod support;
use serde_json::Value;
use std::{fs, process::Command};
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ntfs2refs"))
        .args(args)
        .output()
        .unwrap()
}
#[test]
fn inspection_plan_and_verification_are_read_only() {
    let temp = tempfile::tempdir().unwrap();
    let image = temp.path().join("source.raw");
    let baseline = temp.path().join("baseline.json");
    let bytes = support::image();
    fs::write(&image, &bytes).unwrap();
    let image_arg = image.to_str().unwrap();
    let baseline_arg = baseline.to_str().unwrap();
    let result = cli(&[
        "inspect",
        "--image",
        image_arg,
        "--output",
        baseline_arg,
        "--stream-hash-budget-mib",
        "1",
    ]);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: Value = serde_json::from_slice(&fs::read(&baseline).unwrap()).unwrap();
    assert_eq!(report["filesystem"]["filesystem"], "Ntfs");
    assert_eq!(
        report["filesystem"]["details"]["stream_hash_limit_bytes"],
        1024 * 1024
    );
    let plan = cli(&[
        "plan",
        "--image",
        image_arg,
        "--target",
        "win11",
        "--target-build",
        "26300.9457",
        "--boot",
    ]);
    assert_eq!(plan.status.code(), Some(2));
    let plan: Value = serde_json::from_slice(&plan.stdout).unwrap();
    assert_eq!(plan["executable"], false);
    assert_eq!(plan["schema_version"], 2);
    assert_eq!(plan["source_stream_plan"]["schema_version"], 4);
    assert!(
        plan["source_stream_plan"]["streams"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
    assert!(plan["required_journal_bytes"].is_null());
    assert!(
        plan["blockers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|b| b["code"] == "writer_not_qualified")
    );
    assert!(
        cli(&["verify", "--image", image_arg, "--baseline", baseline_arg])
            .status
            .success()
    );
    assert!(
        !cli(&["inspect", "--image", image_arg, "--output", baseline_arg])
            .status
            .success()
    );
    assert_eq!(fs::read(&image).unwrap(), bytes);
    let mut changed = bytes;
    changed[409600] ^= 1;
    fs::write(&image, changed).unwrap();
    assert!(
        !cli(&["verify", "--image", image_arg, "--baseline", baseline_arg])
            .status
            .success()
    );
}
#[test]
fn rejects_invalid_hash_budget_before_opening_input() {
    for (budget, expected) in [
        ("0", "must be positive"),
        ("18446744073709551615", "overflow"),
    ] {
        let result = cli(&[
            "inspect",
            "--image",
            "absent-budget-probe.raw",
            "--stream-hash-budget-mib",
            budget,
        ]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains(expected));
    }
}
#[test]
fn forged_plan_cannot_enable_write_commands() {
    let temp = tempfile::tempdir().unwrap();
    let artifact = temp.path().join("plan.json");
    fs::write(&artifact, br#"{"executable":true,"blockers":[]}"#).unwrap();
    for command in ["convert", "resume", "rollback", "finalize"] {
        let arg = if command == "convert" {
            "--plan"
        } else {
            "--journal"
        };
        let result = cli(&[command, arg, artifact.to_str().unwrap()]);
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("writes are unavailable"));
    }
    assert_eq!(
        fs::read(&artifact).unwrap(),
        br#"{"executable":true,"blockers":[]}"#
    );
}
#[test]
fn corpus_diff_counts_bytes_and_coalesces_blocks() {
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a.raw");
    let b = temp.path().join("b.raw");
    let mut bytes = vec![0; 2100];
    fs::write(&a, &bytes).unwrap();
    bytes[600] = 1;
    bytes[1100] = 2;
    bytes[2099] = 3;
    fs::write(&b, bytes).unwrap();
    let report = ntfs2refs::corpus::diff(&a, &b, 512).unwrap();
    assert_eq!(report.changed_bytes, 3);
    assert_eq!(report.changed_blocks, 3);
    assert_eq!(report.ranges.len(), 2);
    assert_eq!(report.ranges[0].offset, 512);
    assert_eq!(report.ranges[0].length, 1024);
    assert_eq!(report.ranges[1].length, 52);
    assert_eq!(
        ntfs2refs::corpus::diff(&a, &a, 512).unwrap().changed_bytes,
        0
    );
    assert!(ntfs2refs::corpus::diff(&a, &b, 3).is_err());
}

#[test]
fn retained_comparison_pins_inputs_and_never_enables_writes() {
    use sha2::{Digest, Sha256};
    let sha = |bytes: &[u8]| hex::encode(Sha256::digest(bytes));
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("retained-source.raw");
    let shadow = temp.path().join("retained-shadow.raw");
    let request_path = temp.path().join("retained-request.json");
    let output = temp.path().join("comparison.json");
    let mut original = vec![0; 8192];
    original[1024..1536].fill(0x31);
    let mut native = original.clone();
    native[0] = 7;
    native[1536] = 9;
    native[1024..1536].fill(0x62);
    fs::write(&source, &original).unwrap();
    fs::write(&shadow, &native).unwrap();
    let request = serde_json::json!({
        "schema_version": 1, "sector_size": 512, "expected_length": 8192,
        "source_sha256": sha(&original), "shadow_sha256": sha(&native),
        "retained_ranges": [{"offset": 1024, "length": 512,
            "source_sha256": sha(&original[1024..1536]),
            "shadow_sha256": sha(&native[1024..1536])}],
        "max_change_bytes": 1024, "max_ranges": 2
    });
    fs::write(&request_path, serde_json::to_vec(&request).unwrap()).unwrap();
    let args = [
        "compare-retained",
        "--source",
        source.to_str().unwrap(),
        "--shadow",
        shadow.to_str().unwrap(),
        "--request",
        request_path.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ];
    let result = cli(&args);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report_bytes = fs::read(&output).unwrap();
    let report: Value = serde_json::from_slice(&report_bytes).unwrap();
    let mut expected = native.clone();
    expected[1024..1536].copy_from_slice(&original[1024..1536]);
    assert_eq!(report["expected_postimage_sha256"], sha(&expected));
    assert_eq!(report["patches"].as_array().unwrap().len(), 2);
    assert!(!cli(&args).status.success());
    assert_eq!(fs::read(&output).unwrap(), report_bytes);
    assert_eq!(fs::read(&source).unwrap(), original);
    assert_eq!(fs::read(&shadow).unwrap(), native);

    let mut unknown = request.clone();
    unknown["executable"] = true.into();
    fs::write(&request_path, serde_json::to_vec(&unknown).unwrap()).unwrap();
    let refused = cli(&args[..7]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unknown field"));
    let mut wrong_pin = request;
    wrong_pin["source_sha256"] = "0".repeat(64).into();
    fs::write(&request_path, serde_json::to_vec(&wrong_pin).unwrap()).unwrap();
    assert!(!cli(&args[..7]).status.success());
    let capabilities: Value = serde_json::from_slice(&cli(&["capabilities"]).stdout).unwrap();
    assert_eq!(capabilities["retained_range_comparison"], true);
    assert_eq!(capabilities["conversion_writes"], cfg!(windows));
    assert_eq!(capabilities["journal_recovery"], cfg!(windows));
}

#[test]
fn capabilities_report_what_the_executable_enforces() {
    let capabilities: Value = serde_json::from_slice(&cli(&["capabilities"]).stdout).unwrap();
    assert_eq!(capabilities["schema_version"], 5);
    assert_eq!(capabilities["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(capabilities["refs_metadata_builder"], "windows");
    // The documents it points at are in the tree.
    for document in ["feature_matrix", "recovery_matrix", "guide"] {
        let path = capabilities["lab_evidence"][document].as_str().unwrap();
        assert!(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join(path)
                .is_file(),
            "{path}"
        );
    }
    assert!(capabilities.get("recorded_qualification").is_none());
    // What is announced as not carried over or refused is what the code says.
    let data_volume = &capabilities["data_volume"];
    assert!(
        data_volume["not_carried_over"][0]["what"]
            .as_str()
            .unwrap()
            .starts_with("object IDs")
    );
    assert!(
        ntfs2refs::ntfs_admission::SHORT_NAME_REMEDY.contains(
            data_volume["refused_by_name"][0]["remedy"]
                .as_str()
                .unwrap()
                .split(',')
                .next()
                .unwrap()
        )
    );
    assert_eq!(
        capabilities["windows_builds"]["confirmed_builds"],
        serde_json::json!(n2r_win32::windows_build::LAB_BUILDS)
    );

    // The geometry announced is the geometry the admission gate accepts.
    let geometry = |sector: u16, cluster: u32, file_record: u32, index_record: u32| {
        ntfs2refs::ntfs_inspect::NtfsGeometry {
            bytes_per_sector: sector,
            sectors_per_cluster: cluster / u32::from(sector),
            cluster_size: cluster,
            total_sectors: 1 << 24,
            volume_size: (1 << 24) * u64::from(sector),
            total_clusters: (1 << 24) * u64::from(sector) / u64::from(cluster),
            mft_lcn: 4,
            mftmirr_lcn: 8,
            file_record_size: file_record,
            index_record_size: index_record,
            serial_number: 1,
        }
    };
    let profile = ntfs2refs::ntfs_admission::ResourceProfile::ResourceBoundedV4(None);
    let source = &capabilities["source_geometry"];
    let (low, high) = (
        source["cluster_bytes"]["minimum"].as_u64().unwrap() as u32,
        source["cluster_bytes"]["maximum"].as_u64().unwrap() as u32,
    );
    assert_eq!((low, high), (512, 2 * 1024 * 1024));
    for sector in source["sector_bytes"].as_array().unwrap() {
        let sector = sector.as_u64().unwrap() as u16;
        for record in source["file_record_bytes"].as_array().unwrap() {
            let record = record.as_u64().unwrap() as u32;
            let mut cluster = low.max(u32::from(sector));
            while cluster <= high {
                assert!(
                    profile.supports_source_geometry(&geometry(sector, cluster, record, 4096)),
                    "{sector}/{cluster}/{record}"
                );
                cluster *= 2;
            }
        }
    }
    for index_record in [512u32, 2048, 4096, 65536] {
        assert!(profile.supports_source_geometry(&geometry(512, 4096, 1024, index_record)));
    }
    assert!(!profile.supports_source_geometry(&geometry(512, 4096, 2048, 4096)));
    assert!(!profile.supports_source_geometry(&geometry(512, 4096, 1024, 256)));
    assert!(!profile.supports_source_geometry(&geometry(512, 4 * 1024 * 1024, 1024, 4096)));
    assert_eq!(
        capabilities["target"]["refs_cluster_bytes"],
        serde_json::json!([4096, 65536])
    );
    assert_eq!(
        capabilities["windows_builds"]["minimum_build"],
        n2r_win32::windows_build::MINIMUM_BUILD
    );

    // The announced boot profiles are the rows the admission gate reads.
    let announced = capabilities["qualified_boot_profiles"].as_array().unwrap();
    let enforced = ntfs2refs::boot_profile::QUALIFIED;
    assert!(!enforced.is_empty());
    assert_eq!(announced.len(), enforced.len());
    for (announced, enforced) in announced.iter().zip(enforced) {
        assert_eq!(announced["id"], enforced.id);
        assert_eq!(announced["winload_efi_sha256"], enforced.winload_efi_sha256);
        assert_eq!(announced["refs_sys_sha256"], enforced.refs_sys_sha256);
    }

    // The one route that keeps fixed limits says what they are.
    let routes = capabilities["conversion_routes"].as_array().unwrap();
    let whole_image = routes
        .iter()
        .find(|route| route["route"] == "whole-image")
        .unwrap();
    let legacy = ntfs2refs::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2.limits();
    assert_eq!(whole_image["fixed_limits"]["files"], legacy.maximum_files);
    assert_eq!(
        whole_image["fixed_limits"]["directories"],
        legacy.maximum_directories
    );
    for route in routes
        .iter()
        .filter(|route| route["route"] != "whole-image")
    {
        assert!(route.get("fixed_limits").is_none(), "{route}");
    }

    // So are the diagnose refusals and its exit code for reported failures.
    let refuses = capabilities["diagnose"]["refuses"].as_array().unwrap();
    let table = ntfs2refs::drive_cli::DriveArgs::DIAGNOSE_REFUSES;
    assert_eq!(refuses.len(), table.len());
    for (announced, (option, _)) in refuses.iter().zip(table) {
        assert_eq!(announced["option"], *option);
    }
    assert!(
        capabilities["diagnose"]["exit_codes"]
            [ntfs2refs::drive_cli::EXIT_DIAGNOSE_FAILURES.to_string()]
        .is_string()
    );

    // And the differences the listing comparison accepts.
    let accepted: Vec<&str> = capabilities["listing_comparison"]["accepted_differences"]
        .as_array()
        .unwrap()
        .iter()
        .map(|name| name.as_str().unwrap())
        .collect();
    assert_eq!(accepted, n2r_win32::volume_manifest::ALLOWED_DIFFERENCES);
}

#[test]
fn help_lists_the_product_and_capabilities_names_what_it_leaves_out() {
    let version = String::from_utf8(cli(&["--version"]).stdout).unwrap();
    assert_eq!(
        version.trim(),
        format!("ntfs2refs {}", env!("CARGO_PKG_VERSION"))
    );
    let help = String::from_utf8(cli(&["--help"]).stdout).unwrap();
    let listed: Vec<&str> = help
        .lines()
        .skip_while(|line| !line.starts_with("Commands:"))
        .skip(1)
        .take_while(|line| line.starts_with("  "))
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert_eq!(listed, ["capabilities", "help"], "{help}");
    for option in [
        "--list",
        "--drive",
        "--scratch-directory",
        "--diagnose",
        "--recover",
        "--rollback",
        "--target-cluster-bytes",
    ] {
        assert!(help.contains(option), "{option}");
    }

    let capabilities: Value = serde_json::from_slice(&cli(&["capabilities"]).stdout).unwrap();
    // A route is in the help exactly when capabilities says it is.
    for route in capabilities["conversion_routes"].as_array().unwrap() {
        let option = route["option"].as_str().unwrap();
        assert_eq!(
            help.contains(option),
            route["in_help"].as_bool().unwrap(),
            "{option}"
        );
    }
    // Every command the help leaves out is named, and still answers.
    let hidden = &capabilities["commands_not_in_help"];
    let mut named = 0;
    for group in ["raw_image_research", "request_file_route"] {
        for command in hidden[group].as_array().unwrap() {
            let command = command.as_str().unwrap();
            assert!(!listed.contains(&command), "{command}");
            let own = cli(&[command, "--help"]);
            assert!(own.status.success(), "{command}");
            named += 1;
        }
    }
    assert_eq!(named, 12);
}

#[test]
fn retained_request_is_bounded_before_images_are_opened() {
    let temp = tempfile::tempdir().unwrap();
    let request = temp.path().join("oversized.json");
    fs::write(&request, vec![b' '; 128 * 1024 + 1]).unwrap();
    let result = cli(&[
        "compare-retained",
        "--source",
        "absent-source.raw",
        "--shadow",
        "absent-shadow.raw",
        "--request",
        request.to_str().unwrap(),
    ]);
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("request exceeds 128 KiB"));
}

#[test]
fn conversion_request_requires_an_unambiguous_complete_pinned_envelope() {
    let zero = "0".repeat(64);
    for args in [
        vec!["convert"],
        vec!["convert", "--request", "absent.json"],
        vec![
            "convert",
            "--request",
            "absent.json",
            "--request-sha256",
            zero.as_str(),
        ],
        vec![
            "convert",
            "--plan",
            "plan.json",
            "--request",
            "request.json",
            "--request-sha256",
            zero.as_str(),
            "--output",
            "new-output",
        ],
    ] {
        let result = cli(&args);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
    let help = cli(&["convert", "--help"]);
    assert!(help.status.success());
    let help = String::from_utf8(help.stdout).unwrap();
    assert!(help.contains("--request-sha256") && help.contains("--plan"));
}

#[cfg(windows)]
#[test]
fn conversion_request_refuses_hash_size_and_forged_flags_before_device_io() {
    use sha2::{Digest, Sha256};
    let temp = tempfile::tempdir().unwrap();
    let request = temp.path().join("request.json");
    let output = temp.path().join("never-created");
    let invoke = |pin: &str| {
        cli(&[
            "convert",
            "--request",
            request.to_str().unwrap(),
            "--request-sha256",
            pin,
            "--output",
            output.to_str().unwrap(),
        ])
    };
    fs::write(&request, br#"{"schema_version":1,"executable":true}"#).unwrap();
    let result = invoke(&"0".repeat(64));
    assert!(String::from_utf8_lossy(&result.stderr).contains("SHA-256 differs"));
    let pin = hex::encode(Sha256::digest(fs::read(&request).unwrap()));
    let result = invoke(&pin);
    assert!(String::from_utf8_lossy(&result.stderr).contains("unknown field"));
    assert!(!output.exists());
    fs::write(&request, vec![b' '; 16 * 1024 + 1]).unwrap();
    let result = invoke(&"0".repeat(64));
    assert!(String::from_utf8_lossy(&result.stderr).contains("exceeds 16 KiB"));
    assert!(!output.exists());
}

#[test]
fn diagnose_is_refused_at_parse_time_with_options_that_would_change_the_source() {
    let cases: [&[&str]; 3] = [
        &["--whole-image-verification"],
        &["--minimize-scratch"],
        &["--offline-media", "E:\\"],
    ];
    for extra in cases {
        let mut arguments = vec!["--drive", "D", "--diagnose"];
        arguments.extend_from_slice(extra);
        let result = cli(&arguments);
        // The parser's own exit code: nothing has been opened or listed yet.
        assert_eq!(result.status.code(), Some(2), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        assert!(stderr.contains("cannot be used with"), "{stderr}");
    }
}

#[test]
fn recovery_requires_all_pinned_inputs_when_request_is_supplied() {
    for command in ["resume", "rollback", "finalize"] {
        let result = cli(&[
            command,
            "--journal",
            "journal.bin",
            "--request",
            "request.json",
        ]);
        assert_eq!(result.status.code(), Some(2));
        let help = cli(&[command, "--help"]);
        assert!(help.status.success());
        assert!(
            String::from_utf8(help.stdout)
                .unwrap()
                .contains("--ticket-sha256")
        );
    }
}

#[test]
fn operation_state_creates_nothing_when_its_pinned_inputs_do_not_validate() {
    let temp = tempfile::tempdir().unwrap();
    let run = temp.path().join("run");
    std::fs::create_dir(&run).unwrap();
    std::fs::write(run.join("conversion-intent.json"), "{}").unwrap();
    let output = temp.path().join("never-created");
    // A well-formed pin that is not the digest of that file.
    let pin = "0".repeat(64);
    let result = cli(&[
        "operation-state",
        "--run-directory",
        run.to_str().unwrap(),
        "--intent-sha256",
        &pin,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("nothing was created"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(
        !output.exists(),
        "a refused inspection left its output directory"
    );

    // The same with no run directory at all.
    let absent = cli(&[
        "operation-state",
        "--run-directory",
        temp.path().join("no-such-run").to_str().unwrap(),
        "--intent-sha256",
        &pin,
        "--output",
        output.to_str().unwrap(),
    ]);
    assert_eq!(absent.status.code(), Some(1));
    assert!(!output.exists());
}

#[test]
fn shadowless_recovery_refuses_resume_and_finalize_before_reading_inputs() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("never-created");
    let pin = "a".repeat(64);
    for command in ["resume", "finalize"] {
        let result = cli(&[
            command,
            "--without-shadow",
            "--journal",
            "absent-journal",
            "--request",
            "absent-request.json",
            "--request-sha256",
            &pin,
            "--ticket",
            "absent-ticket.json",
            "--ticket-sha256",
            &pin,
            "--output",
            output.to_str().unwrap(),
        ]);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("--without-shadow is only valid for rollback"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists());
    }
    let missing_pins = cli(&[
        "rollback",
        "--without-shadow",
        "--journal",
        "absent-journal",
    ]);
    assert_eq!(missing_pins.status.code(), Some(2));
}

#[cfg(windows)]
#[test]
fn shadowless_rollback_keeps_pinned_envelope_and_refuses_forward_expectation() {
    let temp = tempfile::tempdir().unwrap();
    let output = temp.path().join("never-created");
    let pin = "a".repeat(64);
    for after_marker in [false, true] {
        let mut args = vec![
            "rollback",
            "--without-shadow",
            "--journal",
            "absent-journal",
            "--request",
            "absent-request.json",
            "--request-sha256",
            "invalid",
            "--ticket",
            "absent-ticket.json",
            "--ticket-sha256",
            &pin,
            "--output",
            output.to_str().unwrap(),
        ];
        if after_marker {
            args.push("--after-marker");
        }
        let result = cli(&args);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("request and ticket require canonical SHA-256 pins"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists());
        let request_pin = args
            .iter()
            .position(|arg| *arg == "--request-sha256")
            .unwrap()
            + 1;
        args[request_pin] = &pin;
        args.extend([
            "--expectation",
            "absent-tree.json",
            "--expectation-sha256",
            &pin,
        ]);
        let result = cli(&args);
        assert!(!result.status.success());
        assert!(
            String::from_utf8_lossy(&result.stderr)
                .contains("only finalize operations require the expectation and its pin"),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(!output.exists());
    }
}
