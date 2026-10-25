//! Read-only physical-disk and GPT binding probe for a dedicated data disk.
//! This command does not isolate, dismount, mount, format or convert anything.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::Parser;
    use n2r_win32::{
        general_layout::{GeneralDiskBinding, GeneralSourceShadowBinding},
        probe_general,
    };
    use serde::Serialize;
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
        output: PathBuf,
        /// Optional independent shadow binding for the future general
        /// data-volume conversion route.
        #[arg(long, requires = "shadow_binding_sha256")]
        shadow_binding: Option<PathBuf>,
        #[arg(long, requires = "shadow_binding")]
        shadow_binding_sha256: Option<String>,
    }
    #[derive(Serialize)]
    struct Report {
        schema_version: u32,
        kind: &'static str,
        binding_sha256: String,
        observed: n2r_win32::GeneralProbe,
        shadow_observed: Option<n2r_win32::GeneralProbe>,
        shadow_binding_sha256: Option<String>,
        events: Vec<n2r_win32::NativeEvent>,
        conversion_qualified: bool,
    }
    fn save(path: &PathBuf, value: &impl Serialize) -> Result<()> {
        ensure!(!path.exists(), "fresh output required");
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(bytes.len() <= 1024 * 1024, "probe report exceeds bound");
        let mut output = OpenOptions::new().write(true).create_new(true).open(path)?;
        output.write_all(&bytes)?;
        output.sync_all()?;
        Ok(())
    }
    let args = Args::parse();
    let metadata = fs::symlink_metadata(&args.binding)?;
    ensure!(
        metadata.is_file() && metadata.len() <= 16384,
        "bounded regular binding file required"
    );
    let bytes = fs::read(&args.binding)?;
    ensure!(
        args.binding_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == args.binding_sha256,
        "binding pin differs"
    );
    let binding: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
    let mut events = Vec::new();
    let shadow =
        if let (Some(path), Some(pin)) = (&args.shadow_binding, &args.shadow_binding_sha256) {
            let metadata = fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_file() && metadata.len() <= 16384,
                "bounded regular shadow binding file required"
            );
            let bytes = fs::read(path)?;
            ensure!(
                pin.len() == 64 && hex::encode(Sha256::digest(&bytes)) == *pin,
                "shadow binding pin differs"
            );
            let shadow: GeneralDiskBinding = serde_json::from_slice(&bytes)?;
            GeneralSourceShadowBinding {
                source: binding.clone(),
                shadow: shadow.clone(),
            }
            .validate()?;
            Some(shadow)
        } else {
            None
        };
    let observed = probe_general(binding, &mut events)?;
    let shadow_observed = shadow
        .map(|binding| probe_general(binding, &mut events))
        .transpose()?;
    save(
        &args.output,
        &Report {
            schema_version: 1,
            kind: "general-dedicated-data-disk-read-only-probe",
            binding_sha256: args.binding_sha256,
            observed,
            shadow_observed,
            shadow_binding_sha256: args.shadow_binding_sha256,
            events,
            conversion_qualified: false,
        },
    )
}

#[cfg(not(windows))]
fn main() {
    eprintln!("native disk probe requires Windows");
    std::process::exit(1);
}
