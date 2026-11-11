//! Revalidate an existing native metadata report. No device/volume handles,
//! filesystem changes, source admission, or reconstruction are available here.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        attestation::NativeObservationDomain, observation_pages::PagedNativeObservation,
        tree_resources::SourceResourceAdmission,
    };
    use serde::Deserialize;
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::OpenOptionsExt,
        path::{Component, Path, PathBuf},
        time::Instant,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        assessment: PathBuf,
        #[arg(long)]
        assessment_sha256: String,
        #[arg(long)]
        native: PathBuf,
        #[arg(long)]
        native_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    #[derive(Deserialize)]
    struct Assessment {
        resource_admission: SourceResourceAdmission,
    }
    fn digest(value: &str) -> Result<[u8; 32]> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "canonical SHA256 required"
        );
        hex::decode(value)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("SHA width differs"))
    }
    fn ordinary(path: &Path) -> Result<()> {
        ensure!(
            path.is_absolute()
                && matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),std::path::Prefix::Disk(_)))
                && !path
                    .components()
                    .any(|c| matches!(c, Component::ParentDir | Component::CurDir)),
            "ordinary absolute metadata path required"
        );
        for part in path.components() {
            if let Component::Normal(name) = part {
                let name = name.to_str().context("Unicode metadata path required")?;
                ensure!(
                    !name.ends_with([' ', '.'])
                        && !name.chars().any(|c| c.is_control()
                            || matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*')),
                    "ambiguous metadata path refused"
                );
            }
        }
        for item in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
            use std::os::windows::fs::MetadataExt;
            ensure!(
                fs::symlink_metadata(item)?.file_attributes() & 0x400 == 0,
                "metadata reparse refused"
            );
        }
        Ok(())
    }
    let args = Args::parse();
    ordinary(&args.assessment)?;
    ordinary(&args.native)?;
    ordinary(args.output.parent().context("output parent absent")?)?;
    let assessment_sha = digest(&args.assessment_sha256)?;
    digest(&args.native_sha256)?;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.assessment)?;
    let before =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, 16 << 20)?;
    ensure!(before.file_bytes > 0, "empty assessment refused");
    ensure!(
        n2r_win32::sha256_native::hash_range(&mut file, 0, before.file_bytes)? == assessment_sha,
        "assessment independent SHA differs"
    );
    use std::io::{Seek, SeekFrom};
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(before.file_bytes)
        .read_to_end(&mut bytes)?;
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, 16 << 20)?
            == before,
        "held assessment identity changed"
    );
    let facts: Assessment = serde_json::from_slice(&bytes)?;
    facts.resource_admission.validate()?;
    let started = Instant::now();
    let report = PagedNativeObservation::open(
        &args.native,
        &args.native_sha256,
        facts.resource_admission.native_observation_budget()?,
    )?;
    let open_seconds = started.elapsed().as_secs_f64();
    ensure!(
        report.header().request.source_inspection_sha256
            == hex::encode(facts.resource_admission.source_inspection_sha256),
        "native/source assessment differs"
    );
    let validate = Instant::now();
    n2r_win32::attestation::validate_domain_resources(&report)?;
    let validate_seconds = validate.elapsed().as_secs_f64();
    let close = Instant::now();
    report.revalidate()?;
    let result = serde_json::json!({"kind":"existing-native-source-report-readonly-replay-v1",
        "native_sha256":args.native_sha256,"assessment_sha256":args.assessment_sha256,
        "rows":report.len(),"logical_rows":report.logical_len(),"namespace_rows":report.namespace_len(),
        "bytes":report.byte_len(),"open_and_first_validation_seconds":open_seconds,
        "repeat_validation_seconds":validate_seconds,"closing_hash_seconds":close.elapsed().as_secs_f64(),
        "wall_seconds":started.elapsed().as_secs_f64(),"complete_typed_replay":true,
        "all_native_resource_checks_retained":true,"source_devices_opened":false,
        "source_admission_issued":false,"conversion_performed":false});
    let output = serde_json::to_vec_pretty(&result)?;
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    destination.write_all(&output)?;
    destination.sync_all()?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("This metadata replay requires Windows.");
    std::process::exit(2)
}
