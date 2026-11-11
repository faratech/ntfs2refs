//! Post-restart read-only observation for the enrolled disposable V4 fixture.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::tree_resources::ResourceBudget;
    use sha2::{Digest, Sha256};
    use std::{fs::OpenOptions, io::Read, os::windows::fs::OpenOptionsExt, path::PathBuf};

    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        publication: PathBuf,
        #[arg(long)]
        publication_sha256: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long, default_value_t = 268_435_456)]
        ram_bytes: u64,
        #[arg(long, default_value_t = 536_870_912)]
        scratch_bytes: u64,
        #[arg(long, default_value_t = 1_048_576)]
        record_bytes: u64,
        #[arg(long)]
        acknowledge_disposable_fixture: bool,
    }
    fn digest(value: &str) -> anyhow::Result<[u8; 32]> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "independently supplied lowercase SHA-256 required"
        );
        Ok(hex::decode(value)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid checksum width"))?)
    }
    let args = Args::parse();
    let expected_request = digest(&args.request_sha256)?;
    let expected_publication = digest(&args.publication_sha256)?;
    let parent = args
        .output
        .parent()
        .context("recovery output parent absent")?;
    let available = n2r_win32::resource_native::observe_available_resources(parent)?;
    let max_request = available.available_physical_bytes / 128;
    let mut file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .custom_flags(0x0020_0000)
        .open(&args.request)?;
    let snapshot =
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, max_request)?;
    let modified = file.metadata()?.modified()?;
    ensure!(
        snapshot.file_bytes > 0 && snapshot.number_of_links == 1,
        "bounded ordinary fixture request required"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(snapshot.file_bytes)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 == snapshot.file_bytes
            && <[u8; 32]>::from(Sha256::digest(&bytes)) == expected_request
            && n2r_win32::reference_file::observe_reference_file_handle_with_limit(
                &file,
                max_request
            )? == snapshot
            && file.metadata()?.modified()? == modified,
        "fixture request identity or checksum differs"
    );
    let request: ntfs2refs::resource_diagnostic::ResourceDiagnosticRequest =
        serde_json::from_slice(&bytes)?;
    drop(bytes);
    let resources = ResourceBudget {
        schema_version: 1,
        ram_bytes: args.ram_bytes,
        scratch_bytes: args.scratch_bytes,
        page_bytes: 65_536,
        max_row_bytes: args.record_bytes,
        retained_index_bytes: args.ram_bytes / 8,
        handle_slots: 256,
    };
    let result = ntfs2refs::resource_diagnostic::run_guest_recovery_observation(
        request,
        &args.publication,
        expected_publication,
        &args.output,
        resources,
        args.acknowledge_disposable_fixture,
    )?;
    ensure!(
        n2r_win32::reference_file::observe_reference_file_handle_with_limit(&file, max_request)?
            == snapshot
            && file.metadata()?.modified()? == modified
            && n2r_win32::sha256_native::hash_range(&mut file, 0, snapshot.file_bytes)?
                == expected_request,
        "held fixture request changed during recovery observation"
    );
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("The resource recovery observation requires Windows.");
}
