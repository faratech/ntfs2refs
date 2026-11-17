use serde_json::Value;
use std::{fs, process::Command};
fn cli(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ntfs2refs"))
        .args(args)
        .output()
        .unwrap()
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
fn capabilities_report_what_the_executable_enforces() {
    let capabilities: Value = serde_json::from_slice(&cli(&["capabilities"]).stdout).unwrap();
    assert_eq!(capabilities["schema_version"], 5);
    assert_eq!(capabilities["tool_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(capabilities["refs_metadata_builder"], "windows");
    assert_eq!(capabilities["conversion_writes"], cfg!(windows));
    assert_eq!(capabilities["journal_recovery"], cfg!(windows));
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
    // A disk with other partitions is taken, and what that means for them
    // and what refuses it is said.
    let beside = &data_volume["other_partitions_on_the_disk"];
    assert_eq!(beside["allowed"], true);
    assert!(
        beside["during_the_run"]
            .as_str()
            .unwrap()
            .contains("not written to")
    );
    assert_eq!(beside["refused_when"].as_array().unwrap().len(), 4);
    assert!(
        !data_volume["disk_layout"]
            .as_str()
            .unwrap()
            .contains("only partition")
    );
    assert!(
        data_volume["not_carried_over"][0]["what"]
            .as_str()
            .unwrap()
            .starts_with("object IDs")
    );
    // Short names: refused with the remedy, or left behind when asked.
    assert!(
        data_volume["refused_by_name"][0]["or"]
            .as_str()
            .unwrap()
            .starts_with("--short-names drop")
    );
    assert!(ntfs2refs::ntfs_admission::SHORT_NAME_REMEDY.contains("--short-names drop"));
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
    // The check: what it leaves alone, what it cannot say, how it exits.
    let check = &capabilities["check"];
    assert_eq!(check["option"], "--check");
    assert_eq!(check["changes_the_volume"], false);
    assert_eq!(
        check["decided_only_when_frozen"],
        ntfs2refs::drive_cli::CHECK_DECIDED_WHEN_FROZEN
    );
    for code in ["0", "1", "3", "5"] {
        assert!(check["exit_codes"][code].is_string(), "exit code {code}");
    }
    // Both target formats, with where each is the default.
    let formats = &capabilities["target"]["formats"];
    assert_eq!(formats["option"], "--target-format");
    assert!(
        formats["standard"]
            .as_str()
            .unwrap()
            .contains("Windows Server")
    );
    assert!(
        formats["dev-drive"]
            .as_str()
            .unwrap()
            .contains("Windows boot volume")
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

    // No route keeps fixed limits: the one that did went with 0.4.0.
    let routes = capabilities["conversion_routes"].as_array().unwrap();
    assert!(routes.iter().all(|route| route["route"] != "whole-image"));
    for route in routes {
        assert!(route.get("fixed_limits").is_none(), "{route}");
    }

    // So are the diagnose refusals and its exit code for reported failures.
    assert!(
        capabilities["diagnose"]["on_a_data_volume_to_shrink"]
            .as_str()
            .unwrap()
            .contains("--check")
    );
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

    // The run's own before-and-after listing, and how it exits.
    let own = &capabilities["listing_comparison"]["by_the_run"];
    assert_eq!(own["option"], "--compare-listing");
    assert!(own["exit_codes"][ntfs2refs::drive_cli::EXIT_LISTING_DIFFERS.to_string()].is_string());
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
    // There is no command the help leaves out: the research tools and the
    // request-file commands of earlier designs are gone, and are refused.
    assert!(capabilities.get("commands_not_in_help").is_none());
    for command in [
        "inspect",
        "plan",
        "verify",
        "diff",
        "compare-retained",
        "convert",
        "resume",
        "rollback",
        "finalize",
        "complete-label",
        "operation-state",
        "cancel",
    ] {
        assert_eq!(
            cli(&[command, "--help"]).status.code(),
            Some(2),
            "{command}"
        );
    }
}

#[test]
fn an_unattended_run_has_to_name_its_volume() {
    // --yes answers the question that shows the volume, so it needs the
    // volume's serial number. Refused before anything is listed or opened.
    for arguments in [
        vec!["--drive", "D", "--yes"],
        vec!["--drive", "D", "--diagnose", "--yes"],
    ] {
        let result = cli(&arguments);
        assert!(!result.status.success(), "{arguments:?}");
        let stderr = String::from_utf8_lossy(&result.stderr);
        #[cfg(windows)]
        assert!(
            stderr.contains("--yes needs --volume-serial")
                && stderr.contains("Nothing was changed"),
            "{stderr}"
        );
        #[cfg(not(windows))]
        assert!(stderr.contains("Windows"), "{stderr}");
    }
    // A serial number that is not one is the parser's to refuse.
    for bad in ["E:", "1A2B-3C4", "not-a-serial"] {
        let result = cli(&["--drive", "D", "--yes", "--volume-serial", bad]);
        assert_eq!(result.status.code(), Some(2), "{bad}");
        assert!(
            String::from_utf8_lossy(&result.stderr).contains("eight hexadecimal digits"),
            "{bad}"
        );
    }
    // Listing asks nothing.
    assert_eq!(cli(&["--list", "--yes"]).status.code(), Some(2));
    let help = String::from_utf8(cli(&["--help"]).stdout).unwrap();
    assert!(help.contains("--yes") && help.contains("--volume-serial"));
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
