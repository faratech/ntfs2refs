//! Explicit Windows lab entry point. No isolation or online command exists.
#[cfg(windows)]
mod windows {
    use anyhow::{Context, Result, ensure};
    use clap::{Parser, ValueEnum};
    use n2r_win32::journal_file::{OrdinaryFileSnapshot, observe_ordinary_file_handle};
    use ntfs2refs::{
        lab_native_reconstruct::{
            self, NativeReconstructOperation, NativeReconstructReport, NativeReconstructRequest,
        },
        lab_reconstruct::JournalTicket,
    };
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{self, File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::windows::fs::{MetadataExt, OpenOptionsExt},
        path::{Path, PathBuf},
    };

    const REQUEST_LIMIT: u64 = 128 * 1024;
    const TICKET_LIMIT: u64 = 64 * 1024;
    const INTENT_LIMIT: u64 = 256 * 1024;
    const REPORT_LIMIT: u64 = 16 * 1024 * 1024;
    const OPEN_REPARSE_POINT: u32 = 0x0020_0000;

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, ValueEnum)]
    #[serde(rename_all = "kebab-case")]
    enum Operation {
        Prepare,
        Apply,
        Resume,
        Rollback,
        Handoff,
    }
    impl Operation {
        fn bridge(self) -> Option<NativeReconstructOperation> {
            match self {
                Self::Prepare => None,
                Self::Apply => Some(NativeReconstructOperation::Apply),
                Self::Resume => Some(NativeReconstructOperation::Resume),
                Self::Rollback => Some(NativeReconstructOperation::Rollback),
                Self::Handoff => Some(NativeReconstructOperation::Handoff),
            }
        }
        fn may_write_payload(self) -> bool {
            matches!(self, Self::Apply | Self::Resume | Self::Rollback)
        }
    }
    #[derive(Debug, Parser)]
    #[command(
        about = "Explicit offline-partition lab reconstruction; never isolates or brings a disk online"
    )]
    struct Arguments {
        #[arg(value_enum)]
        operation: Operation,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        request_sha256: String,
        #[arg(long)]
        journal: PathBuf,
        #[arg(long)]
        ticket: PathBuf,
        #[arg(long)]
        ticket_sha256: Option<String>,
        #[arg(long)]
        output: PathBuf,
    }
    fn pin(value: &str) -> Result<()> {
        ensure!(
            value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "SHA-256 pins must contain 64 lowercase hex digits"
        );
        Ok(())
    }
    fn artifact_syntax(path: &Path) -> Result<String> {
        let text = path.to_str().context("non-Unicode artifact path")?;
        let folded = text.to_ascii_lowercase();
        ensure!(
            text.len() <= 1024 && folded.starts_with("c:\\ntfs2refs\\"),
            "artifacts must be absolute ordinary paths under C:\\ntfs2refs"
        );
        for part in text[3..].split('\\') {
            ensure!(
                !part.is_empty()
                    && part.len() <= 255
                    && part != "."
                    && part != ".."
                    && !part.ends_with([' ', '.'])
                    && part
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')),
                "ambiguous artifact component, namespace, ADS or traversal refused"
            );
            let base = part.split('.').next().unwrap().to_ascii_uppercase();
            ensure!(
                !matches!(
                    base.as_str(),
                    "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                ) && !(base.len() == 4
                    && (base.starts_with("COM") || base.starts_with("LPT"))
                    && base.as_bytes()[3].is_ascii_digit()),
                "reserved Windows device name refused"
            );
        }
        Ok(folded)
    }
    fn intent_path(args: &Arguments) -> PathBuf {
        args.output.with_extension("intent.json")
    }
    fn argument_guards(args: &Arguments) -> Result<()> {
        pin(&args.request_sha256)?;
        match (args.operation, args.ticket_sha256.as_deref()) {
            (Operation::Prepare, None) => (),
            (Operation::Prepare, Some(_)) => {
                anyhow::bail!("prepare creates a new ticket and does not accept --ticket-sha256")
            }
            (_, Some(value)) => pin(value)?,
            (_, None) => {
                anyhow::bail!("execution requires an independently supplied --ticket-sha256")
            }
        }
        let intent = intent_path(args);
        let paths = [&args.request, &args.ticket, &args.output, &intent];
        let mut seen = Vec::new();
        for path in paths {
            let key = artifact_syntax(path)?;
            ensure!(!seen.contains(&key), "artifact paths alias each other");
            seen.push(key);
        }
        Ok(())
    }
    fn request_guards(args: &Arguments, request: &NativeReconstructRequest) -> Result<()> {
        argument_guards(args)?;
        request.validate()?;
        journal_syntax(&args.journal, &request.experiment_id)
    }
    fn journal_syntax(path: &Path, experiment_id: &str) -> Result<()> {
        ensure!(
            experiment_id.len() == 32
                && experiment_id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid journal experiment identity"
        );
        let expected = format!(
            "J:\\ntfs2refs-shadow\\{}\\reconstruction.journal",
            experiment_id
        );
        ensure!(
            path.to_str() == Some(expected.as_str()),
            "journal must be the exact enrolled experiment reconstruction.journal path"
        );
        Ok(())
    }
    #[derive(Clone, Copy)]
    enum Leaf {
        Existing,
        Absent,
    }
    fn ordinary_path(path: &Path, leaf: Leaf) -> Result<()> {
        for (index, part) in path.ancestors().enumerate() {
            if index == 0 && matches!(leaf, Leaf::Absent) {
                match fs::symlink_metadata(part) {
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                    Err(e) => return Err(e.into()),
                    Ok(_) => {
                        anyhow::bail!("create-new artifact already exists: {}", part.display())
                    }
                }
            }
            let meta = fs::symlink_metadata(part)?;
            ensure!(
                meta.file_attributes() & 0x400 == 0,
                "reparse path or ancestor refused: {}",
                part.display()
            );
            ensure!(
                if index == 0 {
                    meta.is_file()
                } else {
                    meta.is_dir()
                },
                "unexpected artifact or ancestor type: {}",
                part.display()
            );
        }
        Ok(())
    }
    fn same_file(a: &OrdinaryFileSnapshot, b: &OrdinaryFileSnapshot) -> bool {
        a.volume_serial_number == b.volume_serial_number && a.file_id_128 == b.file_id_128
    }
    struct PinnedFile {
        _handle: File,
        bytes: Vec<u8>,
        snapshot: OrdinaryFileSnapshot,
        sha256: String,
    }
    fn read_pinned(path: &Path, expected: &str, limit: u64) -> Result<PinnedFile> {
        artifact_syntax(path)?;
        pin(expected)?;
        ordinary_path(path, Leaf::Existing)?;
        let mut file = OpenOptions::new()
            .read(true)
            .share_mode(1)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(path)?;
        let before = observe_ordinary_file_handle(&file)?;
        ensure!(
            before.file_bytes <= limit,
            "input exceeds bounded JSON size"
        );
        let mut bytes = Vec::new();
        (&mut file).take(limit + 1).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == before.file_bytes && bytes.len() as u64 <= limit,
            "input length changed or exceeds bound"
        );
        let sha256 = hex::encode(Sha256::digest(&bytes));
        ensure!(
            sha256 == expected,
            "input SHA-256 differs: {}",
            path.display()
        );
        ensure!(
            observe_ordinary_file_handle(&file)? == before,
            "input identity or metadata changed"
        );
        ordinary_path(path, Leaf::Existing)?;
        Ok(PinnedFile {
            _handle: file,
            bytes,
            snapshot: before,
            sha256,
        })
    }
    struct ReservedFile {
        file: File,
        snapshot: OrdinaryFileSnapshot,
    }
    fn reserve_new(path: &Path) -> Result<ReservedFile> {
        artifact_syntax(path)?;
        ordinary_path(path, Leaf::Absent)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(path)?;
        let snapshot = observe_ordinary_file_handle(&file)?;
        ensure!(snapshot.file_bytes == 0, "new JSON artifact is not empty");
        ordinary_path(path, Leaf::Existing)?;
        Ok(ReservedFile { file, snapshot })
    }
    fn persist_reserved(
        path: &Path,
        mut reserved: ReservedFile,
        value: &impl Serialize,
        limit: u64,
    ) -> Result<PinnedFile> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(
            bytes.len() as u64 <= limit,
            "JSON artifact exceeds complete output budget"
        );
        let hash = hex::encode(Sha256::digest(&bytes));
        ensure!(
            observe_ordinary_file_handle(&reserved.file)? == reserved.snapshot,
            "reserved artifact changed before write"
        );
        reserved.file.seek(SeekFrom::Start(0))?;
        reserved.file.write_all(&bytes)?;
        reserved.file.sync_all()?; // File::sync_all is FlushFileBuffers on Windows.
        let after = observe_ordinary_file_handle(&reserved.file)?;
        ensure!(
            same_file(&after, &reserved.snapshot) && after.file_bytes == bytes.len() as u64,
            "written artifact identity or length changed"
        );
        drop(reserved.file);
        // A separately opened read handle performs the post-flush readback and
        // stays held with FileShare.Read, excluding later writers/deletion.
        let verified = read_pinned(path, &hash, limit)?;
        ensure!(
            same_file(&verified.snapshot, &reserved.snapshot),
            "artifact was replaced before independent readback"
        );
        Ok(verified)
    }
    fn save_new(path: &Path, value: &impl Serialize, limit: u64) -> Result<PinnedFile> {
        persist_reserved(path, reserve_new(path)?, value, limit)
    }

    #[derive(Serialize)]
    struct CliReport {
        schema_version: u32,
        kind: &'static str,
        operation: Operation,
        success: bool,
        phase: String,
        error: Option<String>,
        request_sha256: String,
        input_ticket_sha256: Option<String>,
        request_file: OrdinaryFileSnapshot,
        input_ticket_file: Option<OrdinaryFileSnapshot>,
        journal_path: PathBuf,
        intent_path: PathBuf,
        intent_sha256: String,
        journal_open_attempted: bool,
        journal_create_may_have_been_issued: bool,
        journal_file: Option<OrdinaryFileSnapshot>,
        native_operation_invoked: bool,
        native: Option<NativeReconstructReport>,
        ticket_write_may_have_been_issued: bool,
        ticket_persisted: bool,
        ticket_sha256: Option<String>,
        ticket_file: Option<OrdinaryFileSnapshot>,
        artifacts_preserved_on_failure: bool,
        online_transition_requested: bool,
        conversion_qualified: bool,
        boot_qualified: bool,
    }
    fn run(args: Arguments) -> Result<()> {
        argument_guards(&args)?;
        ordinary_path(&args.output, Leaf::Absent)?;
        ordinary_path(&intent_path(&args), Leaf::Absent)?;
        let request_file = read_pinned(&args.request, &args.request_sha256, REQUEST_LIMIT)?;
        let request: NativeReconstructRequest = serde_json::from_slice(&request_file.bytes)?;
        request_guards(&args, &request)?; // Before any intent, journal or device operation.
        let input_ticket = if args.operation == Operation::Prepare {
            ordinary_path(&args.ticket, Leaf::Absent)?;
            None
        } else {
            let file = read_pinned(
                &args.ticket,
                args.ticket_sha256
                    .as_deref()
                    .expect("validated independent pin"),
                TICKET_LIMIT,
            )?;
            ensure!(
                !same_file(&request_file.snapshot, &file.snapshot),
                "request and ticket are the same native file"
            );
            Some(file)
        };
        let ticket: Option<JournalTicket> = input_ticket
            .as_ref()
            .map(|file| serde_json::from_slice(&file.bytes))
            .transpose()?;
        if let Some(ticket) = &ticket {
            ensure!(
                ticket.schema_version == 1 && ticket.binding.experiment_id == request.experiment_id,
                "ticket experiment or schema differs"
            );
        }
        ordinary_path(
            &args.journal,
            if args.operation == Operation::Prepare {
                Leaf::Absent
            } else {
                Leaf::Existing
            },
        )?;
        let shadow_path = args.journal.with_file_name("shadow.vhdx");
        ordinary_path(&shadow_path, Leaf::Existing)?;
        let intent = save_new(
            &intent_path(&args),
            &serde_json::json!({
                "schema_version":1,"kind":"native-reconstruction-intent","operation":args.operation,
                "request_sha256":args.request_sha256,"request":request,"request_file":request_file.snapshot,
                "ticket_path":args.ticket,"independent_ticket_sha256":args.ticket_sha256,"journal_path":args.journal,
                "phase":"before-journal-open","may_modify_journal_after_this_intent":true,
                "may_issue_target_payload_writes_after_this_intent":args.operation.may_write_payload(),
                "online_transition_allowed":false,"conversion_qualified":false,"boot_qualified":false
            }),
            INTENT_LIMIT,
        )?;
        // Reserve the report before starting the native operation, so another
        // file cannot claim its name while a long comparison is running.
        let output = reserve_new(&args.output)?;
        ensure!(
            !same_file(&output.snapshot, &request_file.snapshot)
                && input_ticket
                    .as_ref()
                    .is_none_or(|f| !same_file(&output.snapshot, &f.snapshot)),
            "output aliases an input"
        );
        let mut report = CliReport {
            schema_version: 1,
            kind: "native-reconstruction-cli-result",
            operation: args.operation,
            success: false,
            phase: "journal-open".into(),
            error: None,
            request_sha256: request_file.sha256.clone(),
            input_ticket_sha256: input_ticket.as_ref().map(|f| f.sha256.clone()),
            request_file: request_file.snapshot.clone(),
            input_ticket_file: input_ticket.as_ref().map(|f| f.snapshot.clone()),
            journal_path: args.journal.clone(),
            intent_path: intent_path(&args),
            intent_sha256: intent.sha256.clone(),
            journal_open_attempted: false,
            journal_create_may_have_been_issued: false,
            journal_file: None,
            native_operation_invoked: false,
            native: None,
            ticket_write_may_have_been_issued: false,
            ticket_persisted: false,
            ticket_sha256: None,
            ticket_file: None,
            artifacts_preserved_on_failure: true,
            online_transition_requested: false,
            conversion_qualified: false,
            boot_qualified: false,
        };
        let mut new_ticket: Option<PinnedFile> = None;
        let outcome = (|| -> Result<()> {
            ordinary_path(
                &args.journal,
                if args.operation == Operation::Prepare {
                    Leaf::Absent
                } else {
                    Leaf::Existing
                },
            )?;
            report.journal_open_attempted = true;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .share_mode(0)
                .custom_flags(OPEN_REPARSE_POINT);
            if args.operation == Operation::Prepare {
                report.journal_create_may_have_been_issued = true;
                options.create_new(true);
            }
            let mut journal = options.open(&args.journal)?;
            report.journal_file = Some(observe_ordinary_file_handle(&journal)?);
            ordinary_path(&args.journal, Leaf::Existing)?;
            if args.operation == Operation::Prepare {
                ensure!(
                    report.journal_file.as_ref().unwrap().file_bytes == 0,
                    "new journal is not empty"
                );
            }
            report.phase = "native-operation".into();
            report.native_operation_invoked = true;
            report.native = Some(match args.operation.bridge() {
                None => lab_native_reconstruct::prepare(&request, &mut journal),
                Some(operation) => lab_native_reconstruct::execute(
                    operation,
                    &request,
                    &mut journal,
                    ticket.as_ref().expect("independently pinned ticket"),
                ),
            });
            let native = report.native.as_ref().unwrap();
            ensure!(
                native.success,
                "native {} failed at {}: {}",
                native.operation,
                native.phase,
                native.error.as_deref().unwrap_or("unknown")
            );
            if args.operation == Operation::Prepare {
                report.phase = "persist-independent-ticket".into();
                let summary = native
                    .preparation
                    .as_ref()
                    .context("successful preparation has no ticket")?;
                ensure!(
                    summary.preparation_durable,
                    "preparation did not report a durable journal"
                );
                report.ticket_write_may_have_been_issued = true;
                let saved = save_new(&args.ticket, &summary.ticket, TICKET_LIMIT)?;
                let checked: JournalTicket = serde_json::from_slice(&saved.bytes)?;
                ensure!(
                    serde_json::to_vec(&checked)? == serde_json::to_vec(&summary.ticket)?,
                    "independent ticket readback differs"
                );
                report.ticket_persisted = true;
                report.ticket_sha256 = Some(saved.sha256.clone());
                report.ticket_file = Some(saved.snapshot.clone());
                new_ticket = Some(saved); // Hold the independently verified ticket through report durability.
            }
            Ok(())
        })();
        match outcome {
            Ok(()) => {
                report.success = true;
                report.phase = "complete-disks-remain-offline".into();
            }
            Err(e) => report.error = Some(format!("{e:#}")),
        }
        let _output_pin=persist_reserved(&args.output,output,&report,REPORT_LIMIT)
            .with_context(||format!("could not persist complete report; preserve intent {} and all journal/ticket artifacts",intent_path(&args).display()))?;
        ensure!(
            report.success,
            "lab operation failed; artifacts preserved: {}",
            report.error.as_deref().unwrap_or("unknown")
        );
        if let Some(ticket) = &new_ticket {
            println!(
                "Preparation complete; ticket SHA-256: {}. No apply performed; disks remain offline.",
                ticket.sha256
            );
        } else {
            println!("Lab operation complete; disks remain offline.");
        }
        Ok(())
    }
    pub fn main() -> Result<()> {
        run(Arguments::parse())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        fn arguments(operation: &str) -> Vec<String> {
            vec![
                "lab-native-reconstruct",
                operation,
                "--request",
                "C:\\ntfs2refs\\case\\request.json",
                "--request-sha256",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "--journal",
                "J:\\ntfs2refs-shadow\\1234567890abcdef1234567890abcdef\\reconstruction.journal",
                "--ticket",
                "C:\\ntfs2refs\\case\\ticket.json",
                "--output",
                "C:\\ntfs2refs\\case\\result.json",
            ]
            .into_iter()
            .map(str::to_string)
            .collect()
        }
        fn args(operation: &str) -> Arguments {
            let mut values = arguments(operation);
            if operation != "prepare" {
                values.extend(["--ticket-sha256".into(), "b".repeat(64)]);
            }
            Arguments::try_parse_from(values).unwrap()
        }
        #[test]
        fn independent_ticket_pin_is_required_only_for_execution() {
            argument_guards(&args("prepare")).unwrap();
            for operation in ["apply", "resume", "rollback", "handoff"] {
                let a = Arguments::try_parse_from(arguments(operation)).unwrap();
                assert!(argument_guards(&a).is_err());
                argument_guards(&args(operation)).unwrap();
            }
            let mut a = args("prepare");
            a.ticket_sha256 = Some("b".repeat(64));
            assert!(argument_guards(&a).is_err());
            for bad in ["", "A", "g"] {
                let mut a = args("apply");
                a.ticket_sha256 = Some(bad.repeat(64));
                assert!(argument_guards(&a).is_err());
            }
        }
        #[test]
        fn only_explicit_bounded_operations_exist() {
            for operation in ["online", "isolate", "convert", "format", ""] {
                assert!(Arguments::try_parse_from(arguments(operation)).is_err());
            }
            for operation in ["prepare", "apply", "resume", "rollback", "handoff"] {
                assert!(Arguments::try_parse_from(arguments(operation)).is_ok());
            }
            assert!(Operation::Prepare.bridge().is_none());
            assert!(!Operation::Handoff.may_write_payload());
            assert!(!Operation::Prepare.may_write_payload());
            assert!(
                Operation::Apply.may_write_payload()
                    && Operation::Resume.may_write_payload()
                    && Operation::Rollback.may_write_payload()
            );
        }
        #[test]
        fn paths_refuse_namespaces_devices_ads_traversal_and_short_aliases() {
            for bad in [
                "request.json",
                "C:ntfs2refs\\request.json",
                "D:\\ntfs2refs\\a.json",
                "C:\\other\\a.json",
                "\\\\?\\C:\\ntfs2refs\\a.json",
                "\\\\.\\PhysicalDrive1",
                "\\\\server\\share\\a.json",
                "C:\\ntfs2refs\\..\\a.json",
                "C:\\ntfs2refs\\.\\a.json",
                "C:\\ntfs2refs\\a.json:ads",
                "C:\\ntfs2refs\\NUL",
                "C:\\ntfs2refs\\con.txt",
                "C:\\ntfs2refs\\LPT1.json",
                "C:\\ntfs2refs\\a.\\b.json",
                "C:\\ntfs2refs\\a \\b.json",
                "C:\\ntfs2refs\\CASE~1\\a.json",
                "C:\\ntfs2refs\\\\a.json",
                "C:/ntfs2refs/a.json",
                "C:\\ntfs2refs\\a\0b.json",
            ] {
                assert!(artifact_syntax(Path::new(bad)).is_err(), "{bad:?}");
            }
            assert_eq!(
                artifact_syntax(Path::new("C:\\ntfs2refs\\Case\\Request.json")).unwrap(),
                "c:\\ntfs2refs\\case\\request.json"
            );
            assert!(
                artifact_syntax(Path::new(&format!(
                    "C:\\ntfs2refs\\{}.json",
                    "a".repeat(256)
                )))
                .is_err()
            );
        }
        #[test]
        fn all_artifacts_including_derived_intent_are_distinct() {
            for change in 0..4 {
                let mut a = args("prepare");
                match change {
                    0 => a.ticket = a.request.clone(),
                    1 => a.output = PathBuf::from("c:\\NTFS2REFS\\CASE\\REQUEST.JSON"),
                    2 => a.ticket = intent_path(&a),
                    _ => a.request = intent_path(&a),
                };
                assert!(argument_guards(&a).is_err());
            }
        }
        #[test]
        fn actual_file_aliases_use_volume_and_full_128_bit_file_id() {
            let base = OrdinaryFileSnapshot {
                final_path: "a".into(),
                volume_serial_number: 1,
                file_id_128: [2; 16],
                file_bytes: 0,
                allocation_bytes: 0,
                file_attributes: 0x20,
                number_of_links: 1,
            };
            let mut other = base.clone();
            other.final_path = "b".into();
            assert!(same_file(&base, &other));
            other.file_id_128[15] ^= 1;
            assert!(!same_file(&base, &other));
            other = base.clone();
            other.volume_serial_number = 2;
            assert!(!same_file(&base, &other));
        }

        #[test]
        fn journal_path_is_exact_and_never_the_shadow_backing_file() {
            let experiment = "1234567890abcdef1234567890abcdef";
            let good = format!("J:\\ntfs2refs-shadow\\{experiment}\\reconstruction.journal");
            journal_syntax(Path::new(&good), experiment).unwrap();
            for bad in [
                good.replace("reconstruction.journal", "shadow.vhdx"),
                good.replace("J:", "C:"),
                good.replace(experiment, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                good.replace("reconstruction.journal", "reconstruction.journal:ads"),
                format!("\\\\?\\{good}"),
                good.replace("reconstruction.journal", "..\\reconstruction.journal"),
            ] {
                assert!(journal_syntax(Path::new(&bad), experiment).is_err());
            }
            for bad_id in ["", "../x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"] {
                assert!(journal_syntax(Path::new(&good), bad_id).is_err());
            }
        }

        #[test]
        fn malformed_requests_never_reach_an_intent_phase() {
            let values = [
                serde_json::json!({}),
                serde_json::json!({"schema_version":1,"experiment_id":"1234567890abcdef1234567890abcdef","online":true}),
            ];
            for value in values {
                assert!(serde_json::from_value::<NativeReconstructRequest>(value).is_err());
            }
            for value in [
                serde_json::json!({}),
                serde_json::json!({"schema_version":1,"binding":{},"immutable_sha256":"a","journal_length":8192,"authorize_writes":true}),
            ] {
                assert!(serde_json::from_value::<JournalTicket>(value).is_err());
            }
        }
    }
}

#[cfg(windows)]
fn main() -> anyhow::Result<()> {
    windows::main()
}
#[cfg(not(windows))]
fn main() {
    eprintln!("Native laboratory reconstruction requires Windows.");
    std::process::exit(1);
}
