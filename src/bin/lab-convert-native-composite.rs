//! Fresh native-shadow conversion inside the disposable owning guest.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use ntfs2refs::{
        general_conversion::Request, general_qualification::CompactConstructionBudget,
    };
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt, path::PathBuf};
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        acknowledge_enrolled_disposable_devices: bool,
        /// Use actual selected-device preflight instead of fixed fixture enrollment.
        /// Still requires disposable acknowledgment and genuine fresh admission.
        #[arg(long)]
        selected_devices: bool,
        #[arg(long)]
        maximum_placement_bytes: u64,
        #[arg(long, default_value_t = n2r_win32::shadow_native::private_tree::MAX_PLACEMENT_SUBMISSIONS)]
        maximum_placement_submissions: usize,
        #[arg(long, default_value_t = 16777216)]
        maximum_exception_bytes: u64,
        #[arg(long, conflicts_with = "interrupt_after_first_copy_write")]
        interrupt_after_writes: Option<u32>,
        /// Stop after the first flushed payload write into the actual first
        /// old-payload-copy destination of the qualified allocation plan.
        #[arg(
            long,
            requires = "allocation_bounded",
            conflicts_with = "interrupt_after_writes"
        )]
        interrupt_after_first_copy_write: bool,
        /// Use the allocation-bounded backend (requires --selected-devices).
        #[arg(long, requires = "selected_devices")]
        allocation_bounded: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_enrolled_disposable_devices,
        "explicit disposable-device enrollment acknowledgment required"
    );
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.request)?;
    let snapshot = n2r_win32::reference_file::observe_reference_file_handle(&input)?;
    ensure!(
        snapshot.file_bytes <= 131072 && snapshot.number_of_links == 1,
        "bounded ordinary conversion request required"
    );
    let mut bytes = Vec::new();
    (&mut input).take(131073).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == snapshot.file_bytes
            && hex::encode(Sha256::digest(&bytes)) == args.request_sha256
            && n2r_win32::reference_file::observe_reference_file_handle(&input)? == snapshot,
        "conversion request pin or identity differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    let budget = CompactConstructionBudget {
        maximum_placement_bytes: args.maximum_placement_bytes,
        maximum_placement_submissions: args.maximum_placement_submissions,
        maximum_exception_bytes: args.maximum_exception_bytes,
    };
    if args.allocation_bounded {
        if args.interrupt_after_first_copy_write {
            ntfs2refs::general_lab::convert_fresh_allocation_selected_after_first_copy(
                &request,
                budget,
                &args.output,
            )
        } else {
            ntfs2refs::general_lab::convert_fresh_allocation_selected(
                &request,
                budget,
                &args.output,
                args.interrupt_after_writes,
            )
        }
    } else if args.selected_devices {
        ntfs2refs::general_lab::convert_fresh_compact_selected(
            &request,
            budget,
            &args.output,
            args.interrupt_after_writes,
        )
    } else {
        ntfs2refs::general_lab::convert_fresh_compact(
            &request,
            budget,
            &args.output,
            args.interrupt_after_writes,
        )
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-guest experiment required");
    std::process::exit(2);
}
