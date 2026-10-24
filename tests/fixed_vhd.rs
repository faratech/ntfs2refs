use ntfs2refs::fixed_vhd::{PartitionSelection, extract, validate_footer};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf};
use tempfile::{TempDir, tempdir};

const DISK_BYTES: u64 = 16384;

fn checksum(footer: &mut [u8; 512]) {
    footer[64..68].fill(0);
    let sum: u32 = footer.iter().map(|byte| u32::from(*byte)).sum();
    footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
}

fn footer() -> [u8; 512] {
    let mut bytes = [0_u8; 512];
    bytes[..8].copy_from_slice(b"conectix");
    bytes[8..12].copy_from_slice(&2_u32.to_be_bytes());
    bytes[12..16].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
    bytes[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    bytes[40..48].copy_from_slice(&DISK_BYTES.to_be_bytes());
    bytes[48..56].copy_from_slice(&DISK_BYTES.to_be_bytes());
    bytes[60..64].copy_from_slice(&2_u32.to_be_bytes());
    bytes[68..84].copy_from_slice(&[5_u8; 16]);
    checksum(&mut bytes);
    bytes
}

struct Fixture {
    _directory: TempDir,
    source: PathBuf,
    output: PathBuf,
    selection_path: PathBuf,
    evidence_path: PathBuf,
    selection: PartitionSelection,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempdir().unwrap();
        let source = directory.path().join("control.vhd");
        let output = directory.path().join("partition.raw");
        let selection_path = directory.path().join("selection.json");
        let evidence_path = directory.path().join("guest-result.json");
        let evidence = b"{\"status\":\"synthetic-test-only\"}";
        fs::write(&evidence_path, evidence).unwrap();
        let selection = PartitionSelection {
            schema_version: 1,
            expected_disk_bytes: DISK_BYTES,
            offset_bytes: 1024,
            length_bytes: 4096,
            logical_sector_size: 512,
            guest_disk_unique_id: "60022480D091C4251B5FFD619706C2B5".into(),
            guest_partition_guid: "a1f4246a-232c-4aba-b60b-b4d4c7becb21".into(),
            host_vhd_id: "25C491D0-5F1B-4205-9E6F-FD619706C2B5".into(),
            evidence_path: PathBuf::from("guest-result.json"),
            evidence_sha256: hex::encode(Sha256::digest(evidence)),
        };
        let mut bytes: Vec<_> = (0..DISK_BYTES).map(|n| (n % 251) as u8).collect();
        bytes[1536..2048].fill(0);
        bytes.extend(footer());
        fs::write(&source, &bytes).unwrap();
        fs::write(&selection_path, serde_json::to_vec(&selection).unwrap()).unwrap();
        Self {
            _directory: directory,
            source,
            output,
            selection_path,
            evidence_path,
            selection,
            bytes,
        }
    }

    fn write_selection(&self) {
        fs::write(
            &self.selection_path,
            serde_json::to_vec(&self.selection).unwrap(),
        )
        .unwrap();
    }

    fn run(&self) -> anyhow::Result<ntfs2refs::fixed_vhd::ExtractionRecord> {
        extract(&self.source, &self.output, &self.selection_path)
    }

    fn assert_no_output(&self) {
        assert!(!self.output.exists());
        assert!(!PathBuf::from(format!("{}.partial", self.output.display())).exists());
        assert!(!PathBuf::from(format!("{}.json", self.output.display())).exists());
    }
}

#[test]
fn extracts_every_selected_byte_and_binds_all_hashes() {
    let fixture = Fixture::new();
    let record = fixture.run().unwrap();
    assert_eq!(
        fs::read(&fixture.output).unwrap(),
        fixture.bytes[1024..5120]
    );
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
    assert_eq!(
        record.source_sha256,
        hex::encode(Sha256::digest(&fixture.bytes))
    );
    assert_eq!(
        record.output_sha256,
        hex::encode(Sha256::digest(&fixture.bytes[1024..5120]))
    );
    assert_eq!(
        record.selection_sha256,
        hex::encode(Sha256::digest(fs::read(&fixture.selection_path).unwrap()))
    );
    assert_eq!(record.evidence_sha256, fixture.selection.evidence_sha256);
    assert!(record.output_readback_verified && record.source_before_after_equal);
    assert!(
        !record.gpt_validated
            && !record.guest_identity_authenticated
            && !record.filesystem_validated
            && !record.conversion_qualified
    );
    let manifest: ntfs2refs::fixed_vhd::ExtractionRecord =
        serde_json::from_slice(&fs::read(format!("{}.json", fixture.output.display())).unwrap())
            .unwrap();
    assert_eq!(manifest.status, "complete");
    assert_eq!(manifest.output_sha256, record.output_sha256);
    assert!(!PathBuf::from(format!("{}.partial", fixture.output.display())).exists());
    assert!(!PathBuf::from(format!("{}.json.partial", fixture.output.display())).exists());
}

#[test]
fn rejects_footer_tampering_and_unsupported_layouts() {
    let valid = footer();
    assert_eq!(
        validate_footer(&valid, DISK_BYTES + 512, DISK_BYTES)
            .unwrap()
            .current_size,
        DISK_BYTES
    );
    for offset in [0, 8, 12, 16, 40, 48, 60, 64, 84, 85, 511] {
        let mut damaged = valid;
        damaged[offset] ^= 1;
        assert!(
            validate_footer(&damaged, DISK_BYTES + 512, DISK_BYTES).is_err(),
            "offset {offset}"
        );
    }
    for disk_type in [0_u32, 1, 3, 4, 5, 6] {
        let mut changed = valid;
        changed[60..64].copy_from_slice(&disk_type.to_be_bytes());
        checksum(&mut changed);
        assert!(validate_footer(&changed, DISK_BYTES + 512, DISK_BYTES).is_err());
    }
    let mut changed = valid;
    changed[68..84].fill(0);
    checksum(&mut changed);
    assert!(validate_footer(&changed, DISK_BYTES + 512, DISK_BYTES).is_err());
}

#[test]
fn rejects_old_footer_truncation_padding_and_wrong_disk_size() {
    let valid = footer();
    assert!(validate_footer(&valid[..511], DISK_BYTES + 511, DISK_BYTES).is_err());
    for length in [0, 511, DISK_BYTES + 511, DISK_BYTES + 513, u64::MAX] {
        assert!(validate_footer(&valid, length, DISK_BYTES).is_err());
    }
    assert!(validate_footer(&valid, DISK_BYTES + 512, DISK_BYTES * 2).is_err());
}

#[test]
fn rejects_bad_ranges_before_creating_artifacts() {
    for (offset, length) in [
        (0, 0),
        (1, 512),
        (512, 513),
        (DISK_BYTES, 512),
        (u64::MAX - 511, 512),
    ] {
        let mut fixture = Fixture::new();
        fixture.selection.offset_bytes = offset;
        fixture.selection.length_bytes = length;
        fixture.write_selection();
        assert!(fixture.run().is_err());
        fixture.assert_no_output();
    }
}

#[test]
fn rejects_unbound_evidence_and_identity() {
    for field in [
        "evidence_hash",
        "guest_id",
        "partition_guid",
        "vhd_guid",
        "sector_size",
        "schema",
        "disk_size",
    ] {
        let mut fixture = Fixture::new();
        match field {
            "evidence_hash" => fixture.selection.evidence_sha256 = "0".repeat(64),
            "guest_id" => fixture.selection.guest_disk_unique_id.clear(),
            "partition_guid" => {
                fixture.selection.guest_partition_guid =
                    "00000000-0000-0000-0000-000000000000".into()
            }
            "vhd_guid" => fixture.selection.host_vhd_id = "invalid".into(),
            "sector_size" => fixture.selection.logical_sector_size = 4096,
            "schema" => fixture.selection.schema_version = 2,
            "disk_size" => fixture.selection.expected_disk_bytes = 256 * 1024 * 1024 * 1024,
            _ => unreachable!(),
        }
        fixture.write_selection();
        assert!(fixture.run().is_err(), "{field}");
        fixture.assert_no_output();
    }
}

#[test]
fn never_overwrites_final_partial_or_manifest() {
    for suffix in ["", ".partial", ".json", ".json.partial"] {
        let fixture = Fixture::new();
        let existing = PathBuf::from(format!("{}{suffix}", fixture.output.display()));
        fs::write(&existing, b"existing evidence").unwrap();
        assert!(fixture.run().is_err());
        assert_eq!(fs::read(existing).unwrap(), b"existing evidence");
        assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
    }
}

#[test]
fn refuses_source_as_destination_and_missing_parent() {
    let fixture = Fixture::new();
    assert!(extract(&fixture.source, &fixture.source, &fixture.selection_path).is_err());
    let alias = fixture.output.with_file_name("source-alias.raw");
    fs::hard_link(&fixture.source, &alias).unwrap();
    assert!(extract(&fixture.source, &alias, &fixture.selection_path).is_err());
    assert!(
        extract(
            &fixture.source,
            &fixture
                .output
                .with_file_name("missing")
                .join("artifact.raw"),
            &fixture.selection_path
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.bytes);
}

#[test]
fn rejects_container_signatures_despite_appended_fixed_footer() {
    for signature in [b"vhdxfile", b"conectix"] {
        let mut fixture = Fixture::new();
        fixture.bytes[..8].copy_from_slice(signature);
        fs::write(&fixture.source, &fixture.bytes).unwrap();
        assert!(fixture.run().is_err());
        fixture.assert_no_output();
    }
}

#[test]
fn supports_utf8_bom_selection_and_absolute_evidence() {
    let mut fixture = Fixture::new();
    fixture.selection.evidence_path = fixture.evidence_path.clone();
    let mut bytes = vec![0xef, 0xbb, 0xbf];
    bytes.extend(serde_json::to_vec(&fixture.selection).unwrap());
    fs::write(&fixture.selection_path, bytes).unwrap();
    assert!(fixture.run().is_ok());
}

#[test]
fn rejects_directory_and_parent_traversal_sources() {
    let fixture = Fixture::new();
    assert!(
        extract(
            fixture.source.parent().unwrap(),
            &fixture.output,
            &fixture.selection_path
        )
        .is_err()
    );
    let traversed = fixture
        .source
        .parent()
        .unwrap()
        .join("..")
        .join("missing.vhd");
    assert!(extract(&traversed, &fixture.output, &fixture.selection_path).is_err());
    fixture.assert_no_output();
}

#[cfg(windows)]
#[test]
fn rejects_devices_alternate_streams_and_reparse_sources() {
    use std::os::windows::fs::symlink_file;
    let fixture = Fixture::new();
    for path in [
        r"\\.\PhysicalDrive0",
        r"\\?\C:\test.vhd",
        r"C:\NUL",
        r"C:\test.vhd:stream",
        r"C:test.vhd",
        r"\test.vhd",
    ] {
        assert!(
            extract(
                &PathBuf::from(path),
                &fixture.output,
                &fixture.selection_path
            )
            .is_err()
        );
    }
    let link = fixture.source.with_file_name("linked.vhd");
    if let Err(error) = symlink_file(&fixture.source, &link) {
        if error.raw_os_error() == Some(1314) {
            // A standard Windows token without Developer Mode cannot create
            // this fixture. Device/ADS refusals above still run unprivileged.
            return;
        }
        panic!("create reparse fixture: {error}");
    }
    assert!(extract(&link, &fixture.output, &fixture.selection_path).is_err());
    fixture.assert_no_output();
}

#[cfg(windows)]
#[test]
fn denies_existing_source_writer() {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    let fixture = Fixture::new();
    let _writer = OpenOptions::new()
        .write(true)
        .share_mode(7)
        .open(&fixture.source)
        .unwrap();
    assert!(fixture.run().is_err());
    fixture.assert_no_output();
}

#[test]
fn cli_requires_selection_and_never_claims_conversion() {
    let executable = env!("CARGO_BIN_EXE_n2r-extract-fixed-vhd");
    let help = std::process::Command::new(executable)
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("LAB ONLY"));
    let no_selection = std::process::Command::new(executable)
        .args(["--source", "missing.vhd", "--output", "missing.raw"])
        .output()
        .unwrap();
    assert!(!no_selection.status.success());
}
