//! A minimal Cloud Files API provider for the laboratory
//! (`n2r_win32::cloud_lab_provider`): it makes cloud placeholders on a
//! folder of a lab volume and serves their data while it runs, so that a
//! conversion meets placeholders that are fully present, partly present,
//! not present and pinned, with their provider running or stopped.
//!
//! ```text
//! lab-cloud-provider create --root V:\cloud --backing E:\backing
//!     [--present <relative>]... [--partial <relative>]... [--pinned <relative>]...
//! lab-cloud-provider serve --root V:\cloud --backing E:\backing [--stop-file <path>]
//! lab-cloud-provider unregister --root V:\cloud
//! ```
//!
//! `create` registers the sync root, makes a placeholder of every file and
//! folder of the backing folder (none of it present), then, connected,
//! brings the `--present` files wholly onto the volume, the first 64 KiB of
//! each `--partial` file, and pins and brings each `--pinned` one. `serve`
//! runs the provider until its stop file appears (or it is ended); a
//! conversion run while it is not running meets a stopped provider.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "A minimal Cloud Files API provider for the ntfs2refs laboratory")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Registers the sync root and makes its placeholders.
    Create {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        backing: PathBuf,
        /// A file, relative to the root, brought wholly onto the volume.
        #[arg(long)]
        present: Vec<PathBuf>,
        /// A file of which only the first 64 KiB are kept on the volume.
        #[arg(long)]
        partial: Vec<PathBuf>,
        /// A file pinned (always kept on this device) and brought.
        #[arg(long)]
        pinned: Vec<PathBuf>,
    },
    /// Runs the provider: serves each placeholder's data from the backing
    /// folder until the stop file appears.
    Serve {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        backing: PathBuf,
        #[arg(long)]
        stop_file: Option<PathBuf>,
    },
    /// Downloads one placeholder from its provider (which has to serve this
    /// process), as a conversion does before the freeze.
    Hydrate {
        #[arg(long)]
        path: PathBuf,
    },
    /// Says what of each placeholder under the root is on the volume.
    Report {
        #[arg(long)]
        root: PathBuf,
    },
    /// Removes the sync root registration.
    Unregister {
        #[arg(long)]
        root: PathBuf,
    },
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use n2r_win32::cloud_lab_provider as provider;
    match Args::parse().command {
        Command::Create {
            root,
            backing,
            present,
            partial,
            pinned,
        } => {
            std::fs::create_dir_all(&root)
                .with_context(|| format!("making the sync root {}", root.display()))?;
            provider::register(&root)?;
            let made = provider::create_placeholders(&root, &backing)?;
            println!("{made} placeholder(s) made under {}", root.display());
            let _connected = provider::Connection::connect(&root, &backing)?;
            for file in &present {
                n2r_win32::cloud_native::hydrate(&root.join(file))?;
            }
            for file in &partial {
                n2r_win32::cloud_native::hydrate(&root.join(file))?;
                provider::dehydrate_from(&root.join(file), 65536)?;
            }
            for file in &pinned {
                provider::pin(&root.join(file))?;
                n2r_win32::cloud_native::hydrate(&root.join(file))?;
            }
            for file in present.iter().chain(&partial).chain(&pinned) {
                let report = n2r_win32::cloud_native::report(&root.join(file))?;
                println!(
                    "{}: {}, {} of {} bytes on the volume",
                    file.display(),
                    report.presence.name(),
                    report.present_bytes,
                    report.size
                );
            }
        }
        Command::Serve {
            root,
            backing,
            stop_file,
        } => {
            let _connected = provider::Connection::connect(&root, &backing)?;
            println!("serving {} from {}", root.display(), backing.display());
            loop {
                if stop_file.as_ref().is_some_and(|stop| stop.exists()) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            println!("stopped");
        }
        Command::Report { root } => {
            match n2r_win32::cloud_native::sync_root(&root) {
                Ok(sync) => println!(
                    "provider {:?}, status {:#x}, running: {}",
                    sync.provider,
                    sync.status,
                    sync.running()
                ),
                Err(error) => println!("provider: {error}"),
            }
            for entry in std::fs::read_dir(&root)? {
                let path = entry?.path();
                match n2r_win32::cloud_native::report(&path) {
                    Ok(report) => println!(
                        "{}: {}, {} of {} bytes on the volume{}",
                        path.display(),
                        report.presence.name(),
                        report.present_bytes,
                        report.size,
                        if report.unpopulated {
                            ", not listed in full"
                        } else {
                            ""
                        }
                    ),
                    Err(error) => println!("{}: {error}", path.display()),
                }
            }
        }
        Command::Hydrate { path } => {
            n2r_win32::cloud_native::hydrate(&path)
                .with_context(|| format!("downloading {}", path.display()))?;
            let report = n2r_win32::cloud_native::report(&path)?;
            println!(
                "{}: {}, {} of {} bytes on the volume",
                path.display(),
                report.presence.name(),
                report.present_bytes,
                report.size
            );
        }
        Command::Unregister { root } => provider::unregister(&root)?,
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    let _ = Args::parse();
    eprintln!("the Cloud Files API is a Windows one");
    std::process::exit(2);
}
