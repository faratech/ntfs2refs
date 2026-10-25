//! Owning-guest scratch-file probe on the already converted disposable disk.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::Write,
        path::PathBuf,
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        binding: PathBuf,
        #[arg(long)]
        binding_sha256: String,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        run_id: String,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        enumerate_only: bool,
        #[arg(long, requires = "enumerate_only")]
        enumerate_root: bool,
        #[arg(long,requires_all=["pair","pair_sha256"])]
        verify_tree: bool,
        #[arg(long)]
        pair: Option<PathBuf>,
        #[arg(long)]
        pair_sha256: Option<String>,
    }
    fn pinned(path: &PathBuf, pin: &str, max: u64) -> Result<Vec<u8>> {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_file() && meta.len() <= max,
            "bounded ordinary probe input required"
        );
        let bytes = fs::read(path)?;
        ensure!(
            bytes.len() as u64 <= max && hex::encode(Sha256::digest(&bytes)) == pin,
            "probe input pin differs"
        );
        Ok(bytes)
    }
    let args = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11")
            && args.run_id.len() == 32
            && args.run_id.bytes().all(|b| b.is_ascii_hexdigit()),
        "disposable guest probe required"
    );
    let binding: n2r_win32::general_layout::GeneralDiskBinding =
        serde_json::from_slice(&pinned(&args.binding, &args.binding_sha256, 16384)?)?;
    ensure!(
        (binding.disk_number == 1
            || (args.enumerate_only || args.verify_tree) && binding.disk_number == 3)
            && binding.identity.partition_bytes == 52 * 1024 * 1024 * 1024,
        "disposable converted disk differs"
    );
    if args.enumerate_only {
        let report =
            n2r_win32::shadow_native::observe_system_directory(binding, args.enumerate_root)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.output)?;
        file.write_all(&serde_json::to_vec_pretty(&report)?)?;
        file.sync_all()?;
        return Ok(());
    }
    let expected: ntfs2refs::shadow_tree::ExpectedTree = serde_json::from_slice(&pinned(
        &args.expectation,
        &args.expectation_sha256,
        16 * 1024 * 1024,
    )?)?;
    expected.validate()?;
    if args.verify_tree {
        let pair: n2r_win32::general_layout::GeneralSourceShadowBinding =
            serde_json::from_slice(&pinned(
                args.pair.as_ref().context("pair absent")?,
                args.pair_sha256.as_deref().context("pair pin absent")?,
                16384,
            )?)?;
        ensure!(pair.shadow == binding, "shadow pair differs");
        let tree = ntfs2refs::shadow_tree::Tree {
            profile: "native-ordinary-tree-shadow-v2",
            objects: expected.objects,
            logical_bytes: expected.logical_bytes,
            internal_replacement_pending: expected.internal_replacement_pending,
        };
        let input = ntfs2refs::general_shadow::native_inputs(&tree);
        let attempted = n2r_win32::shadow_native::verify_general_ordinary(pair, &input, |a, b| {
            ntfs2refs::ntfs_attestation::same_security(a, b).map_err(std::io::Error::other)
        });
        let (report, success) = match attempted {
            Ok(report) => (serde_json::to_value(report)?, true),
            Err(error) => (serde_json::json!({"error":error.to_string()}), false),
        };
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.output)?;
        output.write_all(&serde_json::to_vec_pretty(
            &serde_json::json!({"success":success,"report":report}),
        )?)?;
        output.sync_all()?;
        ensure!(success, "native tree verification failed");
        return Ok(());
    }
    let parent = expected
        .objects
        .iter()
        .find(|o| o.path == ["System Volume Information"])
        .context("source parent absent")?;
    let child = expected
        .objects
        .iter()
        .find(|o| o.path == ["System Volume Information", "WPSettings.dat"])
        .context("source child absent")?;
    fn inputs(object: &ntfs2refs::shadow_tree::Object) -> n2r_win32::shadow_native::Input<'_> {
        n2r_win32::shadow_native::Input {
            components: &object.path,
            directory: object.directory,
            times: object.stored_times,
            attributes: object.attributes,
            security: &object.security,
            expected_api_security: object.api_security.as_deref(),
            payload: &[],
            expected_length: None,
            expected_sha256: None,
            source_offset: None,
            source_runs: vec![],
        }
    }
    let parent_input = inputs(parent);
    let child_input = inputs(child);
    let attempted = n2r_win32::shadow_native::probe_security_projection(
        binding,
        &format!("N2R-SECURITY-{}", args.run_id),
        &parent_input,
        &child_input,
        |a, b| ntfs2refs::ntfs_attestation::same_security(a, b).map_err(std::io::Error::other),
    );
    let (report, success) = match attempted {
        Ok(report) => {
            let success = report.success;
            (serde_json::to_value(report)?, success)
        }
        Err(error) => (
            serde_json::json!({"success":false,"error":error.to_string()}),
            false,
        ),
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.output)?;
    file.write_all(&serde_json::to_vec_pretty(&report)?)?;
    file.sync_all()?;
    ensure!(
        success,
        "native ReFS did not reproduce both source descriptor views"
    );
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-guest probe required");
    std::process::exit(2);
}
