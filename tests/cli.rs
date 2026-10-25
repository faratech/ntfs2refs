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
    assert_eq!(capabilities["native_refs_writer"], false);
    assert_eq!(capabilities["conversion_writes"], cfg!(windows));
    assert_eq!(capabilities["journal_recovery"], cfg!(windows));
    assert!(
        capabilities["qualified_boot_builds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
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
