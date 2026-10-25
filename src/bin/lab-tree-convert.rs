//! Single owning-machine command for the enrolled natural-tree conversion.
//! Hyper-V is not part of this executable's conversion or recovery path.
#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    use anyhow::{Context, Result, ensure};
    use clap::Parser;
    use ntfs2refs::{
        lab_reconstruct::JournalTicket,
        lab_tree_expectation,
        lab_tree_reconstruct::{self, Operation, Request},
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };
    #[derive(Parser)]
    #[command(
        about = "Convert the enrolled frozen NTFS tree through a durable journal and native ReFS verification"
    )]
    struct Args {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        /// New private recovery/evidence directory on the independent C: disk.
        #[arg(long)]
        artifacts: PathBuf,
        #[arg(long)]
        journal: PathBuf,
        /// Exit with code 86 after this many durable target writes; recover
        /// with lab-tree-reconstruct resume/rollback and the saved ticket.
        #[arg(long)]
        interrupt_after_writes: Option<u32>,
    }
    fn syntax(p: &Path) -> Result<()> {
        let t = p.to_str().context("non-Unicode artifact path")?;
        ensure!(
            t.starts_with("C:\\ntfs2refs\\")
                && !t[3..].contains(':')
                && !t.contains('/')
                && !t.contains("..")
                && !t.ends_with([' ', '.']),
            "ordinary independent guest C: artifacts required"
        );
        Ok(())
    }
    fn ancestors(p: &Path, leaf_file: bool) -> Result<()> {
        for (i, a) in p.ancestors().enumerate() {
            let m = fs::symlink_metadata(a)?;
            ensure!(
                m.file_attributes() & 0x400 == 0
                    && if i == 0 && leaf_file {
                        m.is_file()
                    } else {
                        m.is_dir()
                    },
                "reparse or wrong artifact ancestry"
            );
        }
        Ok(())
    }
    fn save(root: &Path, name: &str, value: &impl Serialize) -> Result<String> {
        ancestors(root, false)?;
        let path = root.join(name);
        syntax(&path)?;
        let b = serde_json::to_vec_pretty(value)?;
        ensure!(
            b.len() <= 16 * 1024 * 1024,
            "complete artifact exceeds bound"
        );
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&path)?;
        f.write_all(&b)?;
        f.sync_all()?;
        Ok(hex::encode(Sha256::digest(&b)))
    }
    let a = Args::parse();
    ensure!(
        std::env::var("COMPUTERNAME").ok().as_deref() == Some("N2R-WIN11"),
        "enrolled owning-guest laboratory profile required"
    );
    ensure!(
        a.interrupt_after_writes
            .is_none_or(|n| (1..=4096).contains(&n)),
        "interruption count must be 1..=4096"
    );
    syntax(&a.request)?;
    ancestors(&a.request, true)?;
    let mut input = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&a.request)?;
    ensure!(input.metadata()?.len() <= 131072, "request exceeds bound");
    let mut bytes = vec![];
    (&mut input).take(131073).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 131072
            && a.request_sha256.len() == 64
            && hex::encode(Sha256::digest(&bytes)) == a.request_sha256,
        "request pin differs"
    );
    let request: Request = serde_json::from_slice(&bytes)?;
    request.validate()?;
    ensure!(
        a.journal.to_str()
            == Some(
                format!(
                    "J:\\ntfs2refs-shadow\\{}\\reconstruction.journal",
                    request.experiment_id
                )
                .as_str()
            ),
        "exact independent journal path required"
    );
    syntax(&a.artifacts)?;
    ensure!(!a.artifacts.exists(), "fresh recovery directory required");
    ancestors(
        a.artifacts.parent().context("artifact parent absent")?,
        false,
    )?;
    fs::create_dir(&a.artifacts)?;
    save(
        &a.artifacts,
        "intent.json",
        &serde_json::json!({"schema_version":1,"kind":"native-tree-convert-intent",
        "request_sha256":a.request_sha256,"request":request,"journal":a.journal,
        "interrupt_after_writes":a.interrupt_after_writes,"recovery_expires_at_handoff":true}),
    )?;
    let saved_request_sha = save(&a.artifacts, "request.json", &request)?;
    println!("Capturing exact source tree expectations.");
    let mut events = vec![];
    let expected = lab_tree_expectation::capture(&request, &mut events)?;
    let expectation_sha = save(&a.artifacts, "expectation.json", &expected)?;
    println!("Preparing durable old/new reconstruction journal.");
    let mut journal = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(0)
        .custom_flags(0x00200000)
        .open(&a.journal)?;
    let prepared = lab_tree_reconstruct::prepare(&request, &mut journal);
    save(&a.artifacts, "prepare.json", &prepared)?;
    ensure!(
        prepared.success,
        "journal preparation refused: {:?}",
        prepared.error
    );
    let summary = prepared
        .preparation
        .as_ref()
        .context("prepared ticket absent")?;
    ensure!(summary.preparation_durable, "journal is not durable");
    let ticket_sha = save(&a.artifacts, "ticket.json", &summary.ticket)?;
    // Keep the independently stored, read-back ticket protected throughout all
    // destructive stages. No serialized success field authorizes activation.
    let mut ticket_file = OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(a.artifacts.join("ticket.json"))?;
    let mut ticket_bytes = vec![];
    (&mut ticket_file)
        .take(65537)
        .read_to_end(&mut ticket_bytes)?;
    ensure!(
        ticket_bytes.len() <= 65536 && hex::encode(Sha256::digest(&ticket_bytes)) == ticket_sha,
        "durable ticket readback differs"
    );
    let ticket: JournalTicket = serde_json::from_slice(&ticket_bytes)?;
    ensure!(
        serde_json::to_vec(&ticket)? == serde_json::to_vec(&summary.ticket)?,
        "ticket content differs"
    );
    save(
        &a.artifacts,
        "ticket-pin.json",
        &serde_json::json!({"sha256":ticket_sha,"journal_bytes":ticket.journal_length}),
    )?;
    save(
        &a.artifacts,
        "recovery.json",
        &serde_json::json!({
        "schema_version":1,"request":a.artifacts.join("request.json"),"request_sha256":saved_request_sha,
        "ticket":a.artifacts.join("ticket.json"),"ticket_sha256":ticket_sha,"journal":a.journal,
        "expectation":a.artifacts.join("expectation.json"),"expectation_sha256":expectation_sha,
        "recovery_command":"lab-tree-finalize recover resumes an activated offline target and finalizes only after success; lab-tree-reconstruct rollback remains available before handoff; supply the independently saved pins",
        "recovery_closes_at_handoff":true}),
    )?;
    println!("Activating journaled writes while keeping the original offline.");
    let activation =
        lab_tree_reconstruct::execute(Operation::Activate, &request, &mut journal, &ticket);
    save(&a.artifacts, "activate.json", &activation)?;
    ensure!(
        activation.success,
        "offline activation refused: {:?}",
        activation.error
    );
    save(
        &a.artifacts,
        "apply.intent.json",
        &serde_json::json!({"ticket_sha256":ticket_sha,"interrupt_after_writes":a.interrupt_after_writes}),
    )?;
    println!(
        "Applying {} patches to the original partition.",
        summary.patch_count
    );
    let applied = match a.interrupt_after_writes {
        Some(n) => lab_tree_reconstruct::execute_interrupted(
            Operation::Apply,
            &request,
            &mut journal,
            &ticket,
            n,
        ),
        None => lab_tree_reconstruct::execute(Operation::Apply, &request, &mut journal, &ticket),
    };
    save(&a.artifacts, "apply.json", &applied)?;
    ensure!(
        applied.success,
        "apply refused; preserve journal and ticket: {:?}",
        applied.error
    );
    save(
        &a.artifacts,
        "handoff.intent.json",
        &serde_json::json!({"ticket_sha256":ticket_sha,"rollback_will_close":true}),
    )?;
    println!("Recording handoff and verifying the converted original through native ReFS.");
    let finished = lab_tree_reconstruct::finalize(&request, &mut journal, &ticket, &expected)?;
    save(&a.artifacts, "finish.json", &finished)?;
    ensure!(
        finished.success,
        "native verification refused after handoff; rollback remains closed: {:?}",
        finished.error
    );
    println!("Same-partition tree conversion and native content/metadata verification passed.");
    Ok(())
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Windows owning-machine conversion required");
    std::process::exit(1);
}
