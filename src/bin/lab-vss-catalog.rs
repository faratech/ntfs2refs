//! Owning-Windows read-only VSS catalog diagnostic, never conversion authority.
#![forbid(unsafe_code)]

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use serde_json::json;
    use std::{
        fs::{self, File, OpenOptions},
        io::{self, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Component, Path, PathBuf, Prefix},
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Parser)]
    #[command(about = "Read-only VSS completed-catalog diagnostic; JSON to a fresh file or stdout")]
    struct Args {
        /// Exact volume GUID path, including its trailing backslash.
        #[arg(long)]
        volume_guid: String,
        /// Check source snapshot presence only; does not attest hosted storage.
        #[arg(long)]
        snapshot_presence_only: bool,
        /// Fresh absolute ordinary JSON file; omit to write JSON to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    }

    fn open_output(path: &Path) -> Result<File> {
        ensure!(path.is_absolute(), "absolute ordinary output path required");
        ensure!(
            path.extension()
                .and_then(|s| s.to_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("json")),
            "output must have a JSON extension"
        );
        for component in path.components() {
            match component {
                Component::Prefix(prefix) => ensure!(
                    matches!(prefix.kind(), Prefix::Disk(drive) if drive.is_ascii_alphabetic()),
                    "device, UNC and verbatim output paths are refused"
                ),
                Component::RootDir => (),
                Component::Normal(value) => {
                    let value = value.to_str().context("Unicode output path required")?;
                    ensure!(
                        !value.contains(':') && !value.ends_with('.') && !value.ends_with(' '),
                        "alternate streams and ambiguous output components are refused"
                    );
                }
                _ => anyhow::bail!("output path traversal is refused"),
            }
        }
        for parent in path
            .ancestors()
            .skip(1)
            .filter(|p| !p.as_os_str().is_empty())
        {
            let metadata = fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir() && metadata.file_attributes() & 0x400 == 0,
                "ordinary non-reparse output ancestry required"
            );
        }
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)
            .context("create fresh diagnostic output")?;
        let metadata = file.metadata()?;
        ensure!(
            metadata.is_file() && metadata.file_attributes() & 0x400 == 0,
            "ordinary non-reparse diagnostic output required"
        );
        Ok(file)
    }

    let args = Args::parse();
    // Validate and own the fresh output before a query, so no existing file can
    // be overwritten even when the catalog query subsequently fails.
    let mut output = args.output.as_deref().map(open_output).transpose()?;
    let started = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();
    let queried = if args.snapshot_presence_only {
        n2r_win32::vss_observation::observe_snapshot_presence(&args.volume_guid)
    } else {
        n2r_win32::vss_observation::observe_catalog(&args.volume_guid)
    };
    let (observation, failure) = match queried {
        Ok(observation) => {
            let failure = if args.snapshot_presence_only {
                observation.require_observed_snapshot_absence()
            } else {
                observation.require_observed_catalog_clear()
            }
            .err()
            .map(|error| error.to_string());
            (Some(observation), failure)
        }
        Err(error) => (None, Some(error.to_string())),
    };
    let report = json!({
        "schema_version":1,
        "kind":"vss-completed-catalog-diagnostic",
        "requested_volume_guid":args.volume_guid,
        "started_unix_ms":started,
        "finished_unix_ms":SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
        "observation":observation,
        "observed_catalog_clear":!args.snapshot_presence_only && failure.is_none(),
        "observed_snapshot_presence_clear":failure.is_none(),
        "provider_notes":observation.as_ref().map(|o| o.provider_notes()),
        "hosted_storage_requested":!args.snapshot_presence_only,
        "refusal_or_error":failure,
        "inflight_snapshot_operations_excluded":false,
        "source_exclusion_proven":false,
        "execution_authorized":false,
        "disk_state_changed":false,
        "synchronous_com_wall_timeout_enforced":false
    });
    let mut bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(
        bytes.len() < 32 * 1024 * 1024,
        "diagnostic JSON exceeds bounded output budget"
    );
    bytes.push(b'\n');
    if let Some(output) = output.as_mut() {
        output.write_all(&bytes)?;
        output.sync_all()?;
    } else {
        let mut stdout = io::stdout().lock();
        stdout.write_all(&bytes)?;
        stdout.flush()?;
    }
    ensure!(
        failure.is_none(),
        "VSS catalog diagnostic refused; see JSON refusal_or_error"
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() -> anyhow::Result<()> {
    anyhow::bail!("VSS catalog observation requires the owning Windows machine")
}
