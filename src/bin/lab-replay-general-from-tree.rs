//! Repackage one pinned legacy ordinary-tree freeze as inputs for the new
//! guest-only general engine. This touches artifacts, never disks or VMs.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{
        general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
        journal_file::GeneralJournalStorageBinding,
    };
    use ntfs2refs::{
        general_reconstruct, lab_tree_reconstruct, retained_compare::RetainedCompareRequest,
        shadow_tree::ExpectedTree,
    };
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        frozen_report: PathBuf,
        #[arg(long)]
        frozen_report_sha256: String,
        #[arg(long)]
        conversion_request: PathBuf,
        #[arg(long)]
        conversion_request_sha256: String,
        #[arg(long)]
        output_directory: PathBuf,
    }
    fn pinned(path: &PathBuf, sha256: &str, max: u64) -> anyhow::Result<Vec<u8>> {
        let metadata = fs::symlink_metadata(path)?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= max,
            "replay input is not a bounded ordinary file"
        );
        let bytes = fs::read(path)?;
        ensure!(
            sha256.len() == 64 && hex::encode(Sha256::digest(&bytes)) == sha256,
            "replay input pin differs"
        );
        Ok(bytes)
    }
    fn save(path: PathBuf, bytes: &[u8]) -> anyhow::Result<String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(hex::encode(Sha256::digest(bytes)))
    }
    let args = Args::parse();
    ensure!(
        !args.output_directory.exists(),
        "fresh replay output directory required"
    );
    let frozen_bytes = pinned(
        &args.frozen_report,
        &args.frozen_report_sha256,
        64 * 1024 * 1024,
    )?;
    let frozen: serde_json::Value = serde_json::from_slice(&frozen_bytes)?;
    ensure!(
        frozen["kind"] == "existing-tree-shadow-v1"
            && frozen["success"] == true
            && frozen["frozen_shadow"].is_object(),
        "completed ordinary shadow freeze required"
    );
    let expected: ExpectedTree = serde_json::from_value(frozen["tree"].clone())?;
    expected.validate()?;
    let comparison: RetainedCompareRequest =
        serde_json::from_value(frozen["comparison_request"].clone())?;
    let old_bytes = pinned(
        &args.conversion_request,
        &args.conversion_request_sha256,
        131072,
    )?;
    let old: lab_tree_reconstruct::Request = serde_json::from_slice(&old_bytes)?;
    old.validate()?;
    ensure!(
        old.schema_version == 3
            && serde_json::to_value(&comparison)? == serde_json::to_value(&old.comparison)?
            && frozen["frozen_shadow"]["sha256"] == comparison.shadow_sha256
            && frozen["tree"]["profile"] == "native-ordinary-tree-shadow-v2",
        "frozen shadow and old journal request differ"
    );
    let expected_bytes = serde_json::to_vec_pretty(&expected)?;
    let expected_sha256 = hex::encode(Sha256::digest(&expected_bytes));
    let request = general_reconstruct::Request {
        schema_version: 1,
        experiment_id: old.experiment_id,
        expected_tree_sha256: expected_sha256.clone(),
        pair: GeneralSourceShadowBinding {
            source: GeneralDiskBinding {
                disk_number: old.source.disk_number,
                volume_guid: old.source.volume_guid,
                identity: old.source.identity,
            },
            shadow: GeneralDiskBinding {
                disk_number: old.shadow.disk_number,
                volume_guid: old.shadow.volume_guid,
                identity: old.shadow.identity,
            },
        },
        comparison,
        journal: GeneralJournalStorageBinding {
            disk: GeneralDiskBinding {
                disk_number: old.journal.disk_number,
                volume_guid: old.journal.volume_guid,
                identity: old.journal.identity,
            },
            externally_enrolled_disk_unique_id: old.journal.externally_enrolled_disk_unique_id,
            allow_additional_partitions: false,
        },
        max_journal_bytes: old.max_journal_bytes,
    };
    request.validate()?;
    let request_bytes = serde_json::to_vec_pretty(&request)?;
    ensure!(
        request_bytes.len() <= 131072 && expected_bytes.len() <= 16 * 1024 * 1024,
        "replay artifact exceeds bound"
    );
    fs::create_dir(&args.output_directory).context("create fresh replay output")?;
    let saved_expected = save(
        args.output_directory.join("expected-tree.json"),
        &expected_bytes,
    )?;
    ensure!(
        saved_expected == expected_sha256,
        "saved expected-tree pin differs"
    );
    let saved_request = save(
        args.output_directory.join("general-request.json"),
        &request_bytes,
    )?;
    let pins = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version":1,"kind":"pinned-general-tree-replay",
        "frozen_report_sha256":args.frozen_report_sha256,
        "old_conversion_request_sha256":args.conversion_request_sha256,
        "general_request_sha256":saved_request,
        "expected_tree_sha256":expected_sha256,
        "source_sha256":request.comparison.source_sha256,
        "shadow_sha256":request.comparison.shadow_sha256,
        "source_admitted":false,"production_conversion_qualified":false
    }))?;
    save(args.output_directory.join("pins.json"), &pins)?;
    println!("General request SHA-256: {saved_request}");
    println!("Expected tree SHA-256: {expected_sha256}");
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("general tree replay preparation requires Windows");
    std::process::exit(1);
}
