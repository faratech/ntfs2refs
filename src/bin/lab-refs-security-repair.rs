//! Hidden one-file native ReFS security-repair qualification. Never selects the
//! original Windows source, and is not the public conversion entry point.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::{
        discovery::{self, Role},
        journal_file::GeneralJournalStorageBinding,
    };
    use std::{
        fs::OpenOptions,
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        volume: String,
        #[arg(long)]
        expected_disk_guid: String,
        #[arg(long)]
        descriptor: PathBuf,
        #[arg(long)]
        descriptor_sha256: String,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    let mut descriptor_file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.descriptor)?;
    let metadata = descriptor_file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.file_attributes() & 0x400 == 0
            && (20..=65_536).contains(&metadata.len()),
        "bounded ordinary original-descriptor file required"
    );
    let mut descriptor = Vec::with_capacity(metadata.len() as usize);
    descriptor_file.read_to_end(&mut descriptor)?;
    ensure!(
        descriptor.len() as u64 == metadata.len()
            && ntfs2refs::ntfs_security::hash(&descriptor) == args.descriptor_sha256,
        "original-descriptor length or independently supplied SHA differs"
    );
    let replacement =
        ntfs2refs::refs_security_descriptor::prepare_trust_label_placeholder(&descriptor, 65_536)?
            .context("original descriptor has no supported process-trust label")?;
    let target = discovery::discover(&args.volume, Role::Shadow)?;
    ensure!(
        target.label == "N2R_TRUST_ORACLE"
            && target.filesystem == "ReFS"
            && target.binding.disk_number >= 14
            && !target.disk_is_windows_disk,
        "only the explicitly created disposable ReFS oracle may be selected"
    );
    let current = discovery::discover(
        "C:\\",
        Role::Journal {
            allow_additional_partitions: true,
        },
    )?;
    ensure!(
        current.disk_is_windows_disk
            && current.binding.disk_number == 1
            && current.filesystem == "ReFS",
        "actual independent control1 C: journal required"
    );
    let journal = GeneralJournalStorageBinding {
        disk: current.binding,
        externally_enrolled_disk_unique_id: "60022480D091C4251B5FFD619706C2B5".into(),
        allow_additional_partitions: true,
    };
    let receipt = ntfs2refs::refs_security_oracle::qualify_owned_shadow(
        target.binding,
        &args.expected_disk_guid,
        &journal,
        &args.output,
        &[replacement],
    )?;
    let encoded = serde_json::to_vec_pretty(&receipt)?;
    ensure!(
        encoded.len() <= 1024 * 1024,
        "oracle receipt exceeds metadata bound"
    );
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(1)
        .open(args.output.join("cli-result.json"))?;
    output.write_all(&encoded)?;
    output.sync_all()?;
    println!(
        "{}",
        serde_json::json!({
            "kind": receipt.kind,
            "changed_clusters": receipt.changed_clusters,
            "native_bytes_written": receipt.native_bytes_written,
            "journal_handoff_closed": receipt.journal_handoff_closed,
            "target_brought_online": receipt.target_brought_online,
            "native_security_preservation_qualified": receipt.native_security_preservation_qualified,
            "receipt": args.output.join("cli-result.json"),
        })
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("This native ReFS laboratory helper requires Windows.");
    std::process::exit(1);
}
