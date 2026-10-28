//! Owning-guest exercise of the certificate-backed conversion workflow.
#[cfg(windows)]
#[derive(clap::Parser)]
struct Args {
    #[arg(long)]
    request: std::path::PathBuf,
    #[arg(long)]
    request_sha256: String,
    #[arg(long)]
    output: std::path::PathBuf,
    /// Exit 86 after this many complete, flushed journaled target writes.
    /// The durable ticket remains available for explicit recovery.
    #[arg(long,value_parser=clap::value_parser!(u32).range(1..=4096),conflicts_with="interrupt_after_source_freeze")]
    interrupt_after_writes: Option<u32>,
    /// Exit 87 after qualification/source-frozen.json is durable, before
    /// target construction, journal preparation or reconstruction activation.
    #[arg(long, conflicts_with = "interrupt_after_writes")]
    interrupt_after_source_freeze: bool,
    /// Synchronize only the source's known tiny cache and metadata before
    /// strict verification; never initialize the large shadow payload again.
    #[arg(long, conflicts_with_all=["interrupt_after_writes","interrupt_after_source_freeze"])]
    refresh_existing_system_cache: bool,
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::fs;
    let args = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "disposable owning-guest exercise required"
    );
    let meta = fs::symlink_metadata(&args.request)?;
    ensure!(
        meta.is_file() && meta.len() <= 16384,
        "bounded request required"
    );
    let bytes = fs::read(&args.request)?;
    ensure!(
        hex::encode(Sha256::digest(&bytes)) == args.request_sha256,
        "request pin differs"
    );
    let request: ntfs2refs::general_conversion::Request = serde_json::from_slice(&bytes)?;
    ensure!(
        request.pair.source.disk_number == 1
            && request.pair.shadow.disk_number == 3
            && request.journal.disk.disk_number == 2,
        "enrolled disposable disk roles differ"
    );
    if args.refresh_existing_system_cache {
        ntfs2refs::general_conversion::convert_with_existing_cache_sync(&request, &args.output)
    } else if args.interrupt_after_source_freeze {
        ntfs2refs::general_conversion::convert_interrupted_after_source_freeze(
            &request,
            &args.output,
        )
    } else if let Some(writes) = args.interrupt_after_writes {
        ntfs2refs::general_conversion::convert_interrupted(&request, &args.output, writes)
    } else {
        ntfs2refs::general_conversion::convert(&request, &args.output)
    }
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-guest conversion required");
    std::process::exit(2);
}

#[cfg(all(test, windows))]
mod tests {
    use super::Args;
    use clap::{Parser, error::ErrorKind};

    fn base() -> Vec<&'static str> {
        vec![
            "lab-convert-admitted-tree",
            "--request",
            "C:\\request.json",
            "--request-sha256",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "--output",
            "C:\\fresh-output",
        ]
    }

    #[test]
    fn source_freeze_exit_is_opt_in_and_excludes_target_write_interruption() {
        let ordinary = Args::try_parse_from(base()).unwrap();
        assert!(!ordinary.interrupt_after_source_freeze);
        assert!(ordinary.interrupt_after_writes.is_none());
        let mut freeze = base();
        freeze.push("--interrupt-after-source-freeze");
        let parsed = Args::try_parse_from(freeze.clone()).unwrap();
        assert!(parsed.interrupt_after_source_freeze);
        assert!(parsed.interrupt_after_writes.is_none());
        freeze.extend(["--interrupt-after-writes", "1"]);
        assert_eq!(
            Args::try_parse_from(freeze).err().unwrap().kind(),
            ErrorKind::ArgumentConflict
        );
        let mut writes = base();
        writes.extend(["--interrupt-after-writes", "1"]);
        let parsed = Args::try_parse_from(writes).unwrap();
        assert_eq!(parsed.interrupt_after_writes, Some(1));
        assert!(!parsed.interrupt_after_source_freeze);
    }
}
