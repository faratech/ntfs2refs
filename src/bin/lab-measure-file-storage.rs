//! Metadata-only host scratch accounting; never opens a volume or reads data.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use clap::Parser;
    use std::{fs::OpenOptions, io::Write, path::PathBuf};
    #[derive(Parser)]
    struct Args {
        #[arg(long, required = true)]
        input: Vec<PathBuf>,
        #[arg(long)]
        output: PathBuf,
    }
    let args = Args::parse();
    anyhow::ensure!(args.input.len() <= 128, "scratch path count exceeds bound");
    let mut files = Vec::new();
    for path in &args.input {
        anyhow::ensure!(path.is_absolute(), "absolute scratch path required");
        files.push(
            serde_json::json!({"path":path,"storage":n2r_win32::file_storage::observe(path)?}),
        );
    }
    let report = serde_json::json!({"schema_version":1,"kind":"filesystem-scratch-storage-observation",
        "files":files,"physical_device_io_measured":false,"conversion_qualified":false});
    let bytes = serde_json::to_vec_pretty(&report)?;
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args.output)?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("scratch storage observation requires Windows");
    std::process::exit(1);
}
