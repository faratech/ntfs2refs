//! A minimal Projected File System (ProjFS) provider for the laboratory: it
//! projects a backing folder (on another volume) into a virtualization root
//! on a lab volume, so that a conversion meets ProjFS placeholders that are
//! hydrated (their data on the volume) and not (their data only with the
//! provider), with their provider running or stopped. Nothing of the
//! converter uses it. It needs the Client-ProjFS optional feature: without
//! its ProjectedFSLib.dll, Windows does not start it.
//!
//! ```text
//! lab-projfs-provider create --root V:\projected --backing C:\backing [--hydrate <relative>]...
//! lab-projfs-provider serve --root V:\projected --backing C:\backing [--stop-file <path>]
//! lab-projfs-provider report --root V:\projected
//! ```
//!
//! `create` marks the (new, empty) root as a virtualization root, runs the
//! provider, makes a placeholder on the volume of every file and folder of
//! the backing folder (by asking for each, which reads no data), reads each
//! `--hydrate` file through, which brings its data onto the volume, and
//! stops. `serve` runs the provider until its stop file appears (or it is
//! ended). `report` says what ProjFS reports of each object under the root.
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(about = "A minimal ProjFS provider for the ntfs2refs laboratory")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Marks the root, and makes its placeholders.
    Create {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        backing: PathBuf,
        /// A file, relative to the root, read through: its data is brought
        /// onto the volume.
        #[arg(long)]
        hydrate: Vec<PathBuf>,
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
    /// Says what ProjFS reports of each object under the root.
    Report {
        #[arg(long)]
        root: PathBuf,
    },
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::Context;
    use n2r_win32::projfs_lab_provider as provider;
    match Args::parse().command {
        Command::Create {
            root,
            backing,
            hydrate,
        } => {
            std::fs::create_dir_all(&root)
                .with_context(|| format!("making the root {}", root.display()))?;
            provider::mark(&root)?;
            let running = provider::start(&root, &backing)?;
            let made = provider::walk(&backing)?;
            // Asking for each object makes its placeholder on the volume;
            // listing each folder lists it there. No data is read.
            for relative in &made {
                let at = root.join(relative);
                let metadata = std::fs::metadata(&at)
                    .with_context(|| format!("making the placeholder {}", at.display()))?;
                if metadata.is_dir() {
                    for entry in std::fs::read_dir(&at)? {
                        entry?;
                    }
                }
            }
            for file in &hydrate {
                let at = root.join(file);
                std::fs::read(&at).with_context(|| format!("hydrating {}", at.display()))?;
            }
            drop(running);
            println!(
                "{} placeholder(s) made under {}",
                made.len(),
                root.display()
            );
            for relative in &made {
                println!(
                    "{}: {}",
                    relative.display(),
                    provider::state(&root.join(relative))
                );
            }
        }
        Command::Serve {
            root,
            backing,
            stop_file,
        } => {
            let _running = provider::start(&root, &backing)?;
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
            println!("{}: {}", root.display(), provider::state(&root));
            for relative in provider::walk(&root)? {
                println!(
                    "{}: {}",
                    relative.display(),
                    provider::state(&root.join(&relative))
                );
            }
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn main() {
    let _ = Args::parse();
    eprintln!("ProjFS is a Windows one");
    std::process::exit(2);
}
