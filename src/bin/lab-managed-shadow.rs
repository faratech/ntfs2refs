//! Native smoke for new owned staging only; no source input or conversion.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::ensure;
    use clap::Parser;
    use std::{fs::OpenOptions, io::Write, path::PathBuf};
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        acknowledge_new_disposable_staging: bool,
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_new_disposable_staging,
        "new disposable staging acknowledgment required"
    );
    let system = std::env::var("SystemRoot")?;
    let path = args
        .directory
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("Unicode directory required"))?;
    ensure!(
        args.directory.is_absolute()
            && path
                .get(..3)
                .zip(system.get(..3))
                .is_some_and(|(a, b)| a.eq_ignore_ascii_case(b)),
        "smoke artifacts must be on the guest Windows volume"
    );
    let result = n2r_win32::managed_shadow::create(
        &args.directory.join("shadow.vhdx"),
        60 * 1024 * 1024 * 1024,
        512,
        4096,
    );
    let report = match &result {
        Ok(s) => {
            serde_json::json!({"success":true,"kind":"new-owned-native-managed-shadow-smoke","binding":s.binding,"path":s.path,"virtual_disk_id":s.virtual_disk_id,"source_opened":false,"source_writes":0,"conversion_authorized":false})
        }
        Err(e) => {
            serde_json::json!({"success":false,"kind":"new-owned-native-managed-shadow-smoke","error":e.to_string(),"os_error":e.raw_os_error(),"source_opened":false,"source_writes":0,"automatic_retry":false})
        }
    };
    let bytes = serde_json::to_vec_pretty(&report)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.directory.join("result.json"))?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    result?;
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows native staging is required");
    std::process::exit(2)
}
