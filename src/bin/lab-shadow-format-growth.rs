//! One empty, new-owned native ReFS formatting/growth case; no source argument.
#[cfg(windows)]
fn main() {
    if let Err(error) = run() {
        eprintln!("native shadow format/growth probe: {error:#}");
        std::process::exit(1);
    }
}

#[cfg(windows)]
fn run() -> anyhow::Result<()> {
    use anyhow::{Context, ensure};
    use clap::Parser;
    use n2r_win32::managed_shadow::growth_probe::{self, Budget, Mode};
    use std::{
        fs::{self, OpenOptions},
        io::{self, Write},
        os::windows::fs::MetadataExt,
        path::{Component, PathBuf, Prefix},
    };
    #[derive(Parser)]
    struct Args {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        mode: Mode,
        #[arg(long)]
        ram_bytes: u64,
        #[arg(long)]
        scratch_bytes: u64,
        #[arg(long)]
        minimum_free_bytes: u64,
        #[arg(long)]
        acknowledge_new_disposable_staging: bool,
    }
    struct CappedWriter {
        file: std::fs::File,
        remaining: u64,
    }
    impl Write for CappedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            if bytes.len() as u64 > self.remaining {
                return Err(io::Error::other(
                    "metadata result exceeds admitted RAM-sized file allowance",
                ));
            }
            let written = self.file.write(bytes)?;
            self.remaining -= written as u64;
            Ok(written)
        }
        fn flush(&mut self) -> io::Result<()> {
            self.file.flush()
        }
    }
    let args = Args::parse();
    ensure!(
        args.acknowledge_new_disposable_staging,
        "explicit new disposable staging acknowledgement required"
    );
    args.directory
        .to_str()
        .context("Unicode directory required")?;
    ensure!(
        args.directory.is_absolute() && !args.directory.exists(),
        "fresh absolute staging directory on an ordinary local parent required"
    );
    for component in args.directory.components() {
        match component {
            Component::Prefix(p) if !matches!(p.kind(), Prefix::Disk(_)) => {
                anyhow::bail!("local drive route required")
            }
            Component::CurDir | Component::ParentDir => {
                anyhow::bail!("directory traversal refused")
            }
            Component::Normal(s)
                if s.to_str()
                    .is_none_or(|s| s.contains([':', '\0']) || s.ends_with([' ', '.'])) =>
            {
                anyhow::bail!("ambiguous directory component")
            }
            _ => {}
        }
    }
    for parent in args
        .directory
        .parent()
        .context("staging parent absent")?
        .ancestors()
    {
        let m = fs::symlink_metadata(parent)?;
        ensure!(
            m.is_dir() && m.file_attributes() & 0x400 == 0,
            "ordinary staging ancestry required"
        );
    }
    ensure!(
        args.ram_bytes > 8 * 1024 * 1024 && args.scratch_bytes >= args.ram_bytes,
        "explicit bitmap RAM and scratch budgets required"
    );
    fs::create_dir(&args.directory)?;
    let budget = Budget {
        ram_bytes: args.ram_bytes,
        scratch_bytes: args.scratch_bytes,
        minimum_free_bytes: args.minimum_free_bytes,
    };
    let result = growth_probe::run(&args.directory.join("shadow.vhdx"), args.mode, budget);
    let mut output = CappedWriter {
        file: OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(args.directory.join("result.json"))?,
        remaining: args.ram_bytes,
    };
    match &result {
        Ok(report) => serde_json::to_writer_pretty(&mut output, report)?,
        Err(error) => serde_json::to_writer_pretty(
            &mut output,
            &serde_json::json!({
            "schema_version":1,"kind":"lab-native-empty-shadow-format-growth-failure","mode":args.mode,
            "budget":budget,"error":error.to_string(),"native_error":error.raw_os_error(),
            "source_binding_supplied":false,"source_payload_bytes_read":0,"source_payload_bytes_written":0,
            "conversion_authorized":false,"automatic_retry_or_cleanup":false,"backing_and_attachment_retained":true}),
        )?,
    }
    output.write_all(b"\n")?;
    output.file.sync_all()?;
    result?;
    println!(
        "Empty-volume probe completed. Records: {}",
        args.directory.display()
    );
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    eprintln!("native shadow format/growth probe requires Windows");
    std::process::exit(1);
}
