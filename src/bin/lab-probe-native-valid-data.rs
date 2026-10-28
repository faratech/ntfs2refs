//! Owning-guest private one-MiB ReFS validity experiment. No converter route.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        os::windows::fs::MetadataExt,
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        experiment_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, requires = "expected_file_id_info")]
        observe_existing: bool,
        #[arg(long, requires = "observe_existing")]
        expected_file_id_info: Option<String>,
        #[arg(long, conflicts_with = "observe_existing")]
        destination_lcn: Option<u64>,
        #[arg(
            long,
            requires = "destination_lcn",
            conflicts_with = "observe_existing"
        )]
        second_destination_lcn: Option<u64>,
        #[arg(
            long,
            requires = "second_destination_lcn",
            conflicts_with = "observe_existing"
        )]
        reposition: bool,
    }
    let args = Args::parse();
    ensure!(
        !args.output.exists() && args.output != args.request,
        "fresh distinct report required"
    );
    let metadata = fs::symlink_metadata(&args.request)?;
    ensure!(
        metadata.is_file() && metadata.file_attributes() & 0x400 == 0 && metadata.len() <= 131072,
        "bounded ordinary request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        bytes.len() <= 131072 && hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: ntfs2refs::general_reconstruct::Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    let attempted = if args.observe_existing {
        let id = hex::decode(
            args.expected_file_id_info
                .as_deref()
                .context("expected file ID required")?,
        )?;
        n2r_win32::shadow_native::valid_data_probe::observe_existing(
            &request.pair,
            &args.experiment_id,
            &id,
        )
    } else {
        ensure!(
            args.expected_file_id_info.is_none(),
            "file ID is only valid for observation"
        );
        if let Some(lcn) = args.destination_lcn {
            if let Some(second) = args.second_destination_lcn {
                if args.reposition {
                    n2r_win32::shadow_native::valid_data_probe::run_repositioned(
                        &request.pair,
                        &args.experiment_id,
                        lcn,
                        second,
                    )
                } else {
                    n2r_win32::shadow_native::valid_data_probe::run_split(
                        &request.pair,
                        &args.experiment_id,
                        lcn,
                        second,
                    )
                }
            } else {
                n2r_win32::shadow_native::valid_data_probe::run_placed(
                    &request.pair,
                    &args.experiment_id,
                    lcn,
                )
            }
        } else {
            n2r_win32::shadow_native::valid_data_probe::run(&request.pair, &args.experiment_id)
        }
    };
    let failure = attempted.as_ref().err().map(|error| error.to_string());
    let result = match attempted {
        Ok(value) => value,
        Err(error) => serde_json::json!({"schema_version":1,
            "kind":"native-private-valid-data-failure","experiment_id":args.experiment_id,
            "observe_existing":args.observe_existing,"error":error.to_string(),
            "native_error":error.raw_os_error(),"conversion_qualified":false}),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    file.sync_all()?;
    if let Some(error) = failure {
        anyhow::bail!("native private validity observation failed: {error}");
    }
    println!("Private validity probe complete; original source was not opened for writes.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("native validity probe requires Windows");
    std::process::exit(1);
}
