//! Explicit native marker integration experiment, never a production CLI mode.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::{Parser, Subcommand};
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt, path::PathBuf};

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        acknowledge_enrolled_disposable_devices: bool,
        #[arg(long)]
        acknowledge_unqualified_native_markers: bool,
        #[command(subcommand)]
        operation: Operation,
    }
    #[derive(Subcommand)]
    enum Operation {
        Fresh {
            #[arg(long)]
            request: PathBuf,
            #[arg(long)]
            request_sha256: String,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            maximum_placement_bytes: u64,
            #[arg(long, default_value_t = n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS)]
            maximum_placement_submissions: usize,
            #[arg(long, default_value_t = 16777216)]
            maximum_exception_bytes: u64,
            /// Exit86 after the first actual flushed selected payload write.
            #[arg(long)]
            first_write_fault: bool,
        },
        Recover {
            #[arg(long)]
            bundle: PathBuf,
            #[arg(long)]
            bundle_sha256: String,
            #[arg(long)]
            output: PathBuf,
            #[arg(long)]
            rollback: bool,
        },
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_enrolled_disposable_devices && args.acknowledge_unqualified_native_markers,
        "explicit enrolled-device and unqualified-native-marker acknowledgments required"
    );
    match args.operation {
        Operation::Fresh {
            request,
            request_sha256,
            output,
            maximum_placement_bytes,
            maximum_placement_submissions,
            maximum_exception_bytes,
            first_write_fault,
        } => {
            let mut input = OpenOptions::new()
                .read(true)
                .share_mode(1)
                .custom_flags(0x0020_0000)
                .open(request)?;
            let snapshot = n2r_win32::reference_file::observe_reference_file_handle(&input)?;
            ensure!(
                snapshot.file_bytes <= 131072 && snapshot.number_of_links == 1,
                "bounded ordinary conversion request required"
            );
            let mut bytes = Vec::new();
            (&mut input).take(131073).read_to_end(&mut bytes)?;
            ensure!(
                bytes.len() as u64 == snapshot.file_bytes
                    && hex::encode(Sha256::digest(&bytes)) == request_sha256
                    && n2r_win32::reference_file::observe_reference_file_handle(&input)?
                        == snapshot,
                "conversion request pin or identity differs"
            );
            let request = serde_json::from_slice(&bytes)?;
            let budget = ntfs2refs::general_qualification::CompactConstructionBudget {
                maximum_placement_bytes,
                maximum_placement_submissions,
                maximum_exception_bytes,
            };
            ntfs2refs::general_lab::convert_fresh_allocation_redundant_markers(
                &request,
                budget,
                &output,
                first_write_fault,
            )
        }
        Operation::Recover {
            bundle,
            bundle_sha256,
            output,
            rollback,
        } => {
            ntfs2refs::general_lab::recover_allocation_redundant_markers(
                &bundle,
                &bundle_sha256,
                rollback,
                &output,
            )?;
            Ok(())
        }
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("Windows enrolled owning-guest marker experiment required");
    std::process::exit(2);
}
