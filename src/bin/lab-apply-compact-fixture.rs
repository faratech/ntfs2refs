//! Explicit fixed-fixture experiment; general conversion stays gated.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Result, ensure};
    use clap::{Parser, ValueEnum};
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, OpenOptions},
        io::Read,
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::PathBuf,
    };
    #[derive(Clone, ValueEnum)]
    enum Mode {
        Apply,
        Resume,
        Rollback,
        Finalize,
    }
    #[derive(Parser)]
    struct Args {
        #[arg(long, value_enum)]
        operation: Mode,
        #[arg(long)]
        acknowledge_enrolled_disposable_fixture: bool,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        ticket_sha256: String,
        #[arg(long)]
        capture: PathBuf,
        #[arg(long)]
        capture_sha256: String,
        #[arg(long)]
        packed: PathBuf,
        #[arg(long)]
        expectation: PathBuf,
        #[arg(long)]
        expectation_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        output: PathBuf,
        #[arg(long)]
        finalize: bool,
        #[arg(long)]
        interrupt_after_writes: Option<u32>,
    }
    fn pinned(p: &PathBuf, pin: &str, n: u64) -> Result<(File, Vec<u8>)> {
        let m = std::fs::symlink_metadata(p)?;
        ensure!(
            m.is_file() && m.file_attributes() & 0x400 == 0,
            "ordinary pinned input required"
        );
        let mut f = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(0x200000)
            .open(p)?;
        ensure!(f.metadata()?.len() <= n, "input bound exceeded");
        let mut b = Vec::new();
        (&mut f).take(n + 1).read_to_end(&mut b)?;
        ensure!(
            b.len() as u64 <= n && hex::encode(Sha256::digest(&b)) == pin,
            "input pin differs"
        );
        Ok((f, b))
    }
    let x = Args::parse();
    ensure!(
        x.acknowledge_enrolled_disposable_fixture,
        "fixture acknowledgment required"
    );
    let (_r, b) = pinned(&x.request, &x.request_sha256, 131072)?;
    let r: ntfs2refs::general_reconstruct::Request = serde_json::from_slice(&b)?;
    let (_t, b) = pinned(&x.ticket, &x.ticket_sha256, 65536)?;
    let t: ntfs2refs::lab_reconstruct::JournalTicket = serde_json::from_slice(&b)?;
    let (_e, expected) = pinned(&x.expectation, &x.expectation_sha256, 16 * 1024 * 1024)?;
    let mut a = ntfs2refs::refs_hybrid::delta::VerifiedDeltaArtifact::open(
        &x.capture,
        &x.capture_sha256,
        &x.packed,
        r.comparison.expected_length,
        768 * 1024 * 1024,
    )?;
    let m = std::fs::symlink_metadata(&x.journal)?;
    ensure!(
        m.is_file() && m.file_attributes() & 0x400 == 0,
        "ordinary external journal required"
    );
    let mut j = OpenOptions::new()
        .read(true)
        .write(true)
        .share_mode(0)
        .custom_flags(0x200000)
        .open(&x.journal)?;
    let op = match x.operation {
        Mode::Apply => ntfs2refs::compact_fixture::Operation::Apply,
        Mode::Resume => ntfs2refs::compact_fixture::Operation::Resume,
        Mode::Rollback => ntfs2refs::compact_fixture::Operation::Rollback,
        Mode::Finalize => ntfs2refs::compact_fixture::Operation::Finalize,
    };
    ntfs2refs::compact_fixture::run(
        op,
        &r,
        &t,
        &mut a,
        &mut j,
        &expected,
        &x.output,
        x.acknowledge_enrolled_disposable_fixture,
        x.finalize,
        x.interrupt_after_writes,
    )
}
#[cfg(not(windows))]
fn main() {
    eprintln!("native fixture requires Windows");
    std::process::exit(1);
}
