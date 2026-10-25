use ntfs2refs::{
    lab_reconstruct::{self, DurableIo, JournalBinding, JournalSummary, JournalTicket, ReadSeek},
    retained_compare::{RetainedCompareRequest, RetainedRangeRequest},
};
use sha2::{Digest, Sha256};
use std::{
    cell::RefCell,
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    rc::Rc,
};

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn rw(path: &Path) -> File {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap()
}
fn binding() -> JournalBinding {
    JournalBinding {
        experiment_id: "a".repeat(32),
        target_identity_sha256: "1".repeat(64),
        shadow_identity_sha256: "2".repeat(64),
        journal_identity_sha256: "3".repeat(64),
    }
}
#[test]
fn relocation_only_apply_rollback_and_handoff_preserve_both_exact_images() {
    let mut f = Fixture::new();
    f.request.schema_version = 2;
    f.request.retained_ranges.clear();
    f.request.max_change_bytes = f.original.len() as u64;
    f.request.max_ranges = 8;
    let prepared = f.prepare();
    assert_eq!(prepared.expected_postimage_sha256, sha(&f.native));
    let mut target = rw(&f.target);
    let mut shadow = File::open(&f.shadow).unwrap();
    let mut journal = rw(&f.journal);
    lab_reconstruct::apply(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    assert_eq!(fs::read(&f.target).unwrap(), f.native);
    lab_reconstruct::rollback(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    assert_eq!(fs::read(&f.target).unwrap(), f.original);
    lab_reconstruct::resume(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    let handoff = lab_reconstruct::mark_handoff(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    assert!(handoff.handoff_recorded);
    lab_reconstruct::verify_completed_marker(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
        lab_reconstruct::CompletionKind::Refs,
        f.original.len() as u64,
        &sha(&f.native),
        &sha(&f.native),
    )
    .unwrap();
    assert_eq!(fs::read(&f.target).unwrap(), f.native);
    assert!(
        lab_reconstruct::rollback(
            &mut target,
            &mut shadow,
            &mut journal,
            &prepared.ticket,
            &binding()
        )
        .is_err()
    );
}

#[test]
fn completed_ntfs_rollback_closes_replay_before_writable_mount() {
    let mut fixture = Fixture::new();
    fixture.request.schema_version = 2;
    fixture.request.retained_ranges.clear();
    fixture.request.max_change_bytes = fixture.original.len() as u64;
    fixture.request.max_ranges = 8;
    let prepared = fixture.prepare();
    let mut target = rw(&fixture.target);
    let mut shadow = File::open(&fixture.shadow).unwrap();
    let mut journal = rw(&fixture.journal);
    lab_reconstruct::apply(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    lab_reconstruct::rollback(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    let completed = lab_reconstruct::mark_rollback_complete(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
    )
    .unwrap();
    assert_eq!(completed.target_sha256, sha(&fixture.original));
    lab_reconstruct::verify_completed_marker(
        &mut target,
        &mut shadow,
        &mut journal,
        &prepared.ticket,
        &binding(),
        lab_reconstruct::CompletionKind::NtfsRollback,
        fixture.original.len() as u64,
        &sha(&fixture.original),
        &sha(&fixture.native),
    )
    .unwrap();
    assert_eq!(&fs::read(&fixture.journal).unwrap()[..8], b"N2RABT01");
    journal.seek(SeekFrom::Start(512)).unwrap();
    journal.write_all(&[0x7f]).unwrap();
    journal.sync_all().unwrap();
    assert!(
        lab_reconstruct::verify_completed_marker(
            &mut target,
            &mut shadow,
            &mut journal,
            &prepared.ticket,
            &binding(),
            lab_reconstruct::CompletionKind::NtfsRollback,
            fixture.original.len() as u64,
            &sha(&fixture.original),
            &sha(&fixture.native),
        )
        .is_err()
    );
    assert!(
        lab_reconstruct::resume(
            &mut target,
            &mut shadow,
            &mut journal,
            &prepared.ticket,
            &binding()
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.target).unwrap(), fixture.original);
}

#[test]
fn missing_shadow_allows_only_exact_ntfs_rollback_and_completion() {
    let mut fixture = Fixture::new();
    fixture.request.schema_version = 2;
    fixture.request.retained_ranges.clear();
    fixture.request.max_change_bytes = fixture.original.len() as u64;
    fixture.request.max_ranges = 8;
    let ticket = fixture.prepare().ticket;
    {
        let mut target = rw(&fixture.target);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
            .unwrap();
    }
    fs::remove_file(&fixture.shadow).unwrap();
    let mut target = rw(&fixture.target);
    let mut journal = rw(&fixture.journal);
    let restored =
        lab_reconstruct::rollback_without_shadow(&mut target, &mut journal, &ticket, &binding())
            .unwrap();
    assert_eq!(restored.target_sha256, sha(&fixture.original));
    assert_eq!(fs::read(&fixture.target).unwrap(), fixture.original);
    lab_reconstruct::mark_rollback_complete_without_shadow(
        &mut target,
        &mut journal,
        &ticket,
        &binding(),
    )
    .unwrap();
    let proof = lab_reconstruct::verify_completed_rollback_marker_without_shadow(
        &mut target,
        &mut journal,
        &ticket,
        &binding(),
        fixture.original.len() as u64,
        &sha(&fixture.original),
    )
    .unwrap();
    assert!(proof.marker_exact && proof.target_exact);
    assert!(!proof.shadow_exact && proof.shadow_sha256.is_none());
    assert!(
        lab_reconstruct::rollback_without_shadow(&mut target, &mut journal, &ticket, &binding(),)
            .is_err()
    );
}

#[test]
fn missing_shadow_rollback_refuses_foreign_unjournaled_bytes() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let mut foreign = fixture.original.clone();
    foreign[8192] ^= 1;
    fs::write(&fixture.target, &foreign).unwrap();
    fs::remove_file(&fixture.shadow).unwrap();
    let original_journal = fs::read(&fixture.journal).unwrap();
    let mut target = rw(&fixture.target);
    let mut journal = rw(&fixture.journal);
    assert!(
        lab_reconstruct::rollback_without_shadow(&mut target, &mut journal, &ticket, &binding(),)
            .is_err()
    );
    assert_eq!(fs::read(&fixture.target).unwrap(), foreign);
    assert_eq!(fs::read(&fixture.journal).unwrap(), original_journal);
}

#[test]
fn retained_handoff_verifies_hybrid_target_from_immutable_journal() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    assert_ne!(sha(&fixture.expected), sha(&fixture.native));
    let mut target = rw(&fixture.target);
    let mut shadow = File::open(&fixture.shadow).unwrap();
    let mut journal = rw(&fixture.journal);
    lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding()).unwrap();
    lab_reconstruct::mark_handoff(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        .unwrap();
    let proof = lab_reconstruct::verify_completed_refs_marker_from_journal(
        &mut target,
        &mut shadow,
        &mut journal,
        &ticket,
        &binding(),
        fixture.original.len() as u64,
    )
    .unwrap();
    assert_eq!(proof.target_sha256, sha(&fixture.expected));
    assert_eq!(
        proof.shadow_sha256.as_deref(),
        Some(sha(&fixture.native).as_str())
    );
    assert!(proof.target_exact && proof.shadow_exact);
}
struct Fixture {
    _dir: tempfile::TempDir,
    source: PathBuf,
    target: PathBuf,
    shadow: PathBuf,
    journal: PathBuf,
    original: Vec<u8>,
    native: Vec<u8>,
    expected: Vec<u8>,
    request: RetainedCompareRequest,
}
impl Fixture {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.raw");
        let target = dir.path().join("target.raw");
        let shadow = dir.path().join("shadow.raw");
        let journal = dir.path().join("journal.bin");
        let original = vec![0x31; 32_768];
        let mut native = original.clone();
        for start in [0, 12_288, 24_576] {
            native[start..start + 4096].fill(0x72);
        }
        native[4096..12_288].fill(0x55);
        let mut expected = native.clone();
        expected[4096..12_288].copy_from_slice(&original[4096..12_288]);
        fs::write(&source, &original).unwrap();
        fs::write(&target, &original).unwrap();
        fs::write(&shadow, &native).unwrap();
        let request = RetainedCompareRequest {
            schema_version: 1,
            sector_size: 4096,
            expected_length: original.len() as u64,
            source_sha256: sha(&original),
            shadow_sha256: sha(&native),
            retained_ranges: vec![RetainedRangeRequest {
                offset: 4096,
                length: 8192,
                source_sha256: sha(&original[4096..12_288]),
                shadow_sha256: sha(&native[4096..12_288]),
            }],
            max_change_bytes: 12_288,
            max_ranges: 3,
        };
        Self {
            _dir: dir,
            source,
            target,
            shadow,
            journal,
            original,
            native,
            expected,
            request,
        }
    }
    fn prepare(&self) -> JournalSummary {
        let mut source = File::open(&self.source).unwrap();
        let mut shadow = File::open(&self.shadow).unwrap();
        let mut journal = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&self.journal)
            .unwrap();
        lab_reconstruct::prepare_journal(
            &mut source,
            &mut shadow,
            &mut journal,
            &self.request,
            &binding(),
            1024 * 1024,
        )
        .unwrap()
    }
    fn execute(&self, ticket: &JournalTicket, forward: bool) {
        let mut target = rw(&self.target);
        let mut shadow = File::open(&self.shadow).unwrap();
        let mut journal = rw(&self.journal);
        let report = if forward {
            lab_reconstruct::resume(&mut target, &mut shadow, &mut journal, ticket, &binding())
        } else {
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, ticket, &binding())
        }
        .unwrap();
        assert!(
            !report.conversion_qualified
                && !report.handoff_recorded
                && report.retained_bytes_unchanged
        );
        assert_eq!(report.target_bytes_written, 12_288);
        assert_eq!(report.patches_written, 3);
        assert_eq!(
            fs::read(&self.target).unwrap(),
            if forward {
                &self.expected
            } else {
                &self.original
            }
            .clone()
        );
        assert_eq!(fs::read(&self.source).unwrap(), self.original);
        assert_eq!(fs::read(&self.shadow).unwrap(), self.native);
    }
}

#[derive(Debug, Clone)]
enum Event {
    Write(&'static str, u64, usize),
    Sync(&'static str),
}
#[derive(Clone, Copy)]
enum Fault {
    None,
    Write {
        call: usize,
        prefix: usize,
        short: bool,
    },
    Sync(usize),
}
struct FaultFile {
    file: File,
    role: &'static str,
    trace: Rc<RefCell<Vec<Event>>>,
    fault: Fault,
    writes: usize,
    syncs: usize,
}
impl FaultFile {
    fn new(file: File, role: &'static str, trace: Rc<RefCell<Vec<Event>>>, fault: Fault) -> Self {
        Self {
            file,
            role,
            trace,
            fault,
            writes: 0,
            syncs: 0,
        }
    }
}
impl Read for FaultFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.file.read(buf)
    }
}
impl Seek for FaultFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.file.seek(pos)
    }
}
impl ReadSeek for FaultFile {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}
impl Write for FaultFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        let position = self.file.stream_position()?;
        self.trace
            .borrow_mut()
            .push(Event::Write(self.role, position, buf.len()));
        if let Fault::Write {
            call,
            prefix,
            short,
        } = self.fault
            && call == self.writes
        {
            let n = prefix.min(buf.len());
            self.file.write_all(&buf[..n])?;
            if short {
                return Ok(n);
            }
            return Err(io::Error::other("injected interrupted write"));
        }
        self.file.write(buf)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
impl DurableIo for FaultFile {
    fn sync_all(&mut self) -> io::Result<()> {
        self.syncs += 1;
        self.trace.borrow_mut().push(Event::Sync(self.role));
        self.file.sync_all()?;
        if matches!(self.fault, Fault::Sync(call) if call == self.syncs) {
            return Err(io::Error::other("injected failed flush"));
        }
        Ok(())
    }
}

#[test]
fn actual_journal_reopens_and_preserves_retained_bytes() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare();
    assert_eq!(prepared.before_payload_bytes, 12_288);
    assert_eq!(prepared.after_payload_bytes, 12_288);
    assert_eq!(
        prepared.ticket.journal_length,
        prepared.overhead_bytes + 24_576
    );
    assert!(prepared.preparation_durable);
    assert!(!prepared.conversion_qualified);
    let ticket_json = serde_json::to_vec(&prepared.ticket).unwrap();
    let ticket: JournalTicket = serde_json::from_slice(&ticket_json).unwrap();
    fixture.execute(&ticket, true);
    fixture.execute(&ticket, true);
    fixture.execute(&ticket, false);
    fixture.execute(&ticket, false);
    fixture.execute(&ticket, true);
}

#[test]
fn durable_intent_precedes_writes_and_discovery_is_last_both_directions() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    for forward in [true, false] {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace.clone(), Fault::None);
        let mut journal =
            FaultFile::new(rw(&fixture.journal), "journal", trace.clone(), Fault::None);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        if forward {
            lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        } else {
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        }
        .unwrap();
        let events = trace.borrow();
        let first_write = events
            .iter()
            .position(|e| matches!(e, Event::Write("target", _, _)))
            .unwrap();
        assert!(
            events[..first_write]
                .iter()
                .any(|e| matches!(e, Event::Sync("journal")))
        );
        let writes: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let Event::Write("target", offset, count) = e {
                    Some((*offset, *count))
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(writes, [(12_288, 4096), (24_576, 4096), (0, 4096)]);
        let discovery = events
            .iter()
            .position(|e| matches!(e, Event::Write("target", 0, _)))
            .unwrap();
        assert!(matches!(events[discovery - 1], Event::Sync("target")));
        assert!(matches!(events[discovery + 1], Event::Sync("target")));
    }
}

#[test]
fn every_target_write_interruption_can_resume_or_rollback_after_reopen() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let pristine = fs::read(&fixture.journal).unwrap();
    for initial_forward in [true, false] {
        for call in 1..=3 {
            for prefix in [0, 1, 511, 512, 4095, 4096] {
                for recover_forward in [true, false] {
                    fs::write(
                        &fixture.target,
                        if initial_forward {
                            &fixture.original
                        } else {
                            &fixture.expected
                        },
                    )
                    .unwrap();
                    fs::write(&fixture.journal, &pristine).unwrap();
                    {
                        let trace = Rc::new(RefCell::new(Vec::new()));
                        let mut target = FaultFile::new(
                            rw(&fixture.target),
                            "target",
                            trace,
                            Fault::Write {
                                call,
                                prefix,
                                short: false,
                            },
                        );
                        let mut shadow = File::open(&fixture.shadow).unwrap();
                        let mut journal = rw(&fixture.journal);
                        let result = if initial_forward {
                            lab_reconstruct::apply(
                                &mut target,
                                &mut shadow,
                                &mut journal,
                                &ticket,
                                &binding(),
                            )
                        } else {
                            lab_reconstruct::rollback(
                                &mut target,
                                &mut shadow,
                                &mut journal,
                                &ticket,
                                &binding(),
                            )
                        };
                        assert!(
                            result.is_err(),
                            "direction {initial_forward}, write {call}, prefix {prefix}"
                        );
                    }
                    fixture.execute(&ticket, recover_forward);
                }
            }
        }
    }
}

#[test]
fn short_target_write_is_not_retried_as_an_unaligned_write() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(
            rw(&fixture.target),
            "target",
            trace,
            Fault::Write {
                call: 1,
                prefix: 513,
                short: true,
            },
        );
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        assert!(
            lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .unwrap_err()
                .to_string()
                .contains("short target write")
        );
        assert_eq!(target.writes, 1);
    }
    fixture.execute(&ticket, false);
}

#[test]
fn every_target_flush_failure_recovers_after_file_reopen() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let pristine = fs::read(&fixture.journal).unwrap();
    for call in 1..=5 {
        for forward in [true, false] {
            fs::write(&fixture.target, &fixture.original).unwrap();
            fs::write(&fixture.journal, &pristine).unwrap();
            {
                let trace = Rc::new(RefCell::new(Vec::new()));
                let mut target =
                    FaultFile::new(rw(&fixture.target), "target", trace, Fault::Sync(call));
                let mut shadow = File::open(&fixture.shadow).unwrap();
                let mut journal = rw(&fixture.journal);
                assert!(
                    lab_reconstruct::apply(
                        &mut target,
                        &mut shadow,
                        &mut journal,
                        &ticket,
                        &binding()
                    )
                    .is_err()
                );
            }
            fixture.execute(&ticket, forward);
        }
    }
}

#[test]
fn journal_intent_write_or_flush_failure_never_reaches_target_write() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let pristine = fs::read(&fixture.journal).unwrap();
    for fault in [
        Fault::Write {
            call: 1,
            prefix: 17,
            short: false,
        },
        Fault::Sync(1),
    ] {
        fs::write(&fixture.journal, &pristine).unwrap();
        {
            let trace = Rc::new(RefCell::new(Vec::new()));
            let mut target =
                FaultFile::new(rw(&fixture.target), "target", trace.clone(), Fault::None);
            let mut journal = FaultFile::new(rw(&fixture.journal), "journal", trace, fault);
            let mut shadow = File::open(&fixture.shadow).unwrap();
            assert!(
                lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                    .is_err()
            );
            assert_eq!(target.writes, 0);
        }
        assert_eq!(fs::read(&fixture.target).unwrap(), fixture.original);
        fixture.execute(&ticket, true);
        fixture.execute(&ticket, false);
    }
}

#[test]
fn incomplete_or_corrupt_journal_never_permits_target_writes() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let pristine = fs::read(&fixture.journal).unwrap();
    let mut cuts = vec![0, 1, 4095, 4096, 8191, 8192];
    cuts.extend(8192..8320);
    cuts.extend(pristine.len() - 128..pristine.len());
    for cut in cuts {
        fs::write(&fixture.journal, &pristine[..cut]).unwrap();
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace, Fault::None);
        let mut journal = rw(&fixture.journal);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        assert!(
            lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .is_err()
        );
        assert_eq!(target.writes, 0);
    }
    for position in [8192, 8204, 8320, pristine.len() / 2, pristine.len() - 1] {
        let mut changed = pristine.clone();
        changed[position] ^= 0x80;
        fs::write(&fixture.journal, changed).unwrap();
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace, Fault::None);
        let mut journal = rw(&fixture.journal);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        assert!(
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .is_err()
        );
        assert_eq!(target.writes, 0);
    }
    assert_eq!(fs::read(&fixture.target).unwrap(), fixture.original);
}

#[test]
fn preparation_is_bounded_and_failure_leaves_source_and_target_untouched() {
    let fixture = Fixture::new();
    for case in 0..4 {
        let mut request = fixture.request.clone();
        let mut id = binding();
        let budget = if case == 0 { 8192 } else { 1024 * 1024 };
        if case == 1 {
            request.source_sha256 = "0".repeat(64);
        }
        if case == 2 {
            request.sector_size = 512;
        }
        if case == 3 {
            id.journal_identity_sha256 = id.target_identity_sha256.clone();
        }
        fs::write(&fixture.journal, []).unwrap();
        let mut source = File::open(&fixture.source).unwrap();
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        assert!(
            lab_reconstruct::prepare_journal(
                &mut source,
                &mut shadow,
                &mut journal,
                &request,
                &id,
                budget
            )
            .is_err()
        );
        assert_eq!(journal.metadata().unwrap().len(), 0);
    }
    for call in 1..=13 {
        fs::write(&fixture.journal, []).unwrap();
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut source = File::open(&fixture.source).unwrap();
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = FaultFile::new(
            rw(&fixture.journal),
            "journal",
            trace,
            Fault::Write {
                call,
                prefix: 1,
                short: false,
            },
        );
        assert!(
            lab_reconstruct::prepare_journal(
                &mut source,
                &mut shadow,
                &mut journal,
                &fixture.request,
                &binding(),
                1024 * 1024
            )
            .is_err(),
            "journal write {call}"
        );
    }
    fs::write(&fixture.journal, []).unwrap();
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut source = File::open(&fixture.source).unwrap();
    let mut shadow = File::open(&fixture.shadow).unwrap();
    let mut journal = FaultFile::new(rw(&fixture.journal), "journal", trace, Fault::Sync(1));
    assert!(
        lab_reconstruct::prepare_journal(
            &mut source,
            &mut shadow,
            &mut journal,
            &fixture.request,
            &binding(),
            1024 * 1024
        )
        .is_err()
    );
    assert_eq!(fs::read(&fixture.source).unwrap(), fixture.original);
    assert_eq!(fs::read(&fixture.target).unwrap(), fixture.original);
}

#[test]
fn foreign_bytes_shadow_and_storage_bindings_fail_before_writes() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    for position in [0, 4096, 16_384] {
        let mut damaged = fixture.original.clone();
        damaged[position] = 0xfa;
        fs::write(&fixture.target, damaged).unwrap();
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace, Fault::None);
        let mut journal = rw(&fixture.journal);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        assert!(
            lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .is_err()
        );
        assert_eq!(target.writes, 0);
    }
    fs::write(&fixture.target, &fixture.original).unwrap();
    let mut native = fixture.native.clone();
    native[10] ^= 1;
    fs::write(&fixture.shadow, native).unwrap();
    {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace, Fault::None);
        let mut journal = rw(&fixture.journal);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        assert!(
            lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .is_err()
        );
        assert_eq!(target.writes, 0);
    }
    fs::write(&fixture.shadow, &fixture.native).unwrap();
    let mut changed_binding = binding();
    changed_binding.target_identity_sha256 = "4".repeat(64);
    let trace = Rc::new(RefCell::new(Vec::new()));
    let mut target = FaultFile::new(rw(&fixture.target), "target", trace, Fault::None);
    let mut journal = rw(&fixture.journal);
    let mut shadow = File::open(&fixture.shadow).unwrap();
    assert!(
        lab_reconstruct::rollback(
            &mut target,
            &mut shadow,
            &mut journal,
            &ticket,
            &changed_binding
        )
        .is_err()
    );
    assert_eq!(target.writes, 0);
}

#[test]
fn handoff_requires_postimage_and_permanently_closes_recovery() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    {
        let mut target = rw(&fixture.target);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        assert!(
            lab_reconstruct::mark_handoff(
                &mut target,
                &mut shadow,
                &mut journal,
                &ticket,
                &binding()
            )
            .is_err()
        );
    }
    assert!(
        fs::read(&fixture.journal).unwrap()[..4096]
            .iter()
            .all(|b| *b == 0)
    );
    fixture.execute(&ticket, true);
    {
        let mut target = rw(&fixture.target);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        let report = lab_reconstruct::mark_handoff(
            &mut target,
            &mut shadow,
            &mut journal,
            &ticket,
            &binding(),
        )
        .unwrap();
        assert!(report.handoff_recorded);
        assert_eq!(report.target_bytes_written, 0);
        assert!(!report.conversion_qualified);
    }
    for forward in [true, false] {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace, Fault::None);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        let result = if forward {
            lab_reconstruct::resume(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        } else {
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        };
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("handoff may have started")
        );
        assert_eq!(target.writes, 0);
    }
    assert_eq!(fs::read(&fixture.target).unwrap(), fixture.expected);
}

#[test]
fn torn_handoff_and_failed_handoff_flush_never_reopen_rollback() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let pristine = fs::read(&fixture.journal).unwrap();
    fs::write(&fixture.target, &fixture.expected).unwrap();
    for fault in [
        Fault::Write {
            call: 1,
            prefix: 1,
            short: false,
        },
        Fault::Write {
            call: 1,
            prefix: 4095,
            short: false,
        },
        Fault::Write {
            call: 1,
            prefix: 4096,
            short: false,
        },
        Fault::Sync(1),
    ] {
        fs::write(&fixture.journal, &pristine).unwrap();
        {
            let trace = Rc::new(RefCell::new(Vec::new()));
            let mut journal = FaultFile::new(rw(&fixture.journal), "journal", trace, fault);
            let mut target = rw(&fixture.target);
            let mut shadow = File::open(&fixture.shadow).unwrap();
            assert!(
                lab_reconstruct::mark_handoff(
                    &mut target,
                    &mut shadow,
                    &mut journal,
                    &ticket,
                    &binding()
                )
                .is_err()
            );
        }
        let mut target = rw(&fixture.target);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        assert!(
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .is_err()
        );
        assert!(
            lab_reconstruct::resume(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .is_err()
        );
    }
    for at in [0, 127, 2048, 4095] {
        let mut journal_bytes = pristine.clone();
        journal_bytes[at] = 1;
        fs::write(&fixture.journal, journal_bytes).unwrap();
        let mut target = rw(&fixture.target);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        assert!(
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .unwrap_err()
                .to_string()
                .contains("handoff may have started")
        );
    }
}

#[test]
fn coalesced_discovery_range_tail_flushes_before_first_granule() {
    let mut fixture = Fixture::new();
    fixture.native = fixture.original.clone();
    fixture.native[..8192].fill(0x72);
    fixture.native[24_576..28_672].fill(0x72);
    fixture.native[8192..16_384].fill(0x55);
    fixture.expected = fixture.native.clone();
    fixture.expected[8192..16_384].copy_from_slice(&fixture.original[8192..16_384]);
    fixture.request.shadow_sha256 = sha(&fixture.native);
    fixture.request.retained_ranges = vec![RetainedRangeRequest {
        offset: 8192,
        length: 8192,
        source_sha256: sha(&fixture.original[8192..16_384]),
        shadow_sha256: sha(&fixture.native[8192..16_384]),
    }];
    fs::write(&fixture.shadow, &fixture.native).unwrap();
    let ticket = fixture.prepare().ticket;
    for forward in [true, false] {
        let trace = Rc::new(RefCell::new(Vec::new()));
        let mut target = FaultFile::new(rw(&fixture.target), "target", trace.clone(), Fault::None);
        let mut shadow = File::open(&fixture.shadow).unwrap();
        let mut journal = rw(&fixture.journal);
        if forward {
            lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        } else {
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
        }
        .unwrap();
        let events = trace.borrow();
        let writes: Vec<_> = events
            .iter()
            .filter_map(|e| {
                if let Event::Write("target", offset, _) = e {
                    Some(*offset)
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(writes, [4096, 24_576, 0]);
        assert_eq!(
            fs::read(&fixture.target).unwrap(),
            if forward {
                &fixture.expected
            } else {
                &fixture.original
            }
            .clone()
        );
    }
}

#[test]
fn full_64k_retained_payload_has_distinct_per_cluster_bytes() {
    let mut fixture = Fixture::new();
    fixture.original = vec![0x31; 131_072];
    for (index, value) in fixture.original[16_384..81_920].iter_mut().enumerate() {
        *value = ((index * 37 + index / 4096 * 13) % 256) as u8;
    }
    fixture.native = fixture.original.clone();
    for offset in [0, 98_304, 122_880] {
        fixture.native[offset..offset + 4096].fill(0x72);
    }
    fixture.native[16_384..81_920].fill(0x55);
    fixture.expected = fixture.native.clone();
    fixture.expected[16_384..81_920].copy_from_slice(&fixture.original[16_384..81_920]);
    fixture.request.expected_length = 131_072;
    fixture.request.source_sha256 = sha(&fixture.original);
    fixture.request.shadow_sha256 = sha(&fixture.native);
    fixture.request.retained_ranges = vec![RetainedRangeRequest {
        offset: 16_384,
        length: 65_536,
        source_sha256: sha(&fixture.original[16_384..81_920]),
        shadow_sha256: sha(&fixture.native[16_384..81_920]),
    }];
    fs::write(&fixture.source, &fixture.original).unwrap();
    fs::write(&fixture.target, &fixture.original).unwrap();
    fs::write(&fixture.shadow, &fixture.native).unwrap();
    let ticket = fixture.prepare().ticket;
    fixture.execute(&ticket, true);
    fixture.execute(&ticket, false);
}

#[test]
#[ignore = "invoked by separate_process_recovery with private ordinary test files"]
fn child_recovery_process() {
    let directory =
        PathBuf::from(std::env::var_os("N2R_TEST_JOURNAL_CHILD").expect("private child fixture"));
    let ticket: JournalTicket =
        serde_json::from_slice(&fs::read(directory.join("ticket.json")).unwrap()).unwrap();
    let mut target = rw(&directory.join("target.raw"));
    let mut shadow = File::open(directory.join("shadow.raw")).unwrap();
    let mut journal = rw(&directory.join("journal.bin"));
    match std::env::var("N2R_TEST_JOURNAL_ACTION").unwrap().as_str() {
        "resume" => {
            lab_reconstruct::resume(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .unwrap()
        }
        "rollback" => {
            lab_reconstruct::rollback(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                .unwrap()
        }
        _ => panic!("unexpected child operation"),
    };
}

#[test]
fn separate_process_recovery_uses_persistent_journal_and_ticket() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    fs::write(
        fixture.target.parent().unwrap().join("ticket.json"),
        serde_json::to_vec(&ticket).unwrap(),
    )
    .unwrap();
    for action in ["resume", "rollback"] {
        fs::write(&fixture.target, &fixture.original).unwrap();
        {
            let trace = Rc::new(RefCell::new(Vec::new()));
            let mut target = FaultFile::new(
                rw(&fixture.target),
                "target",
                trace,
                Fault::Write {
                    call: 2,
                    prefix: 777,
                    short: false,
                },
            );
            let mut shadow = File::open(&fixture.shadow).unwrap();
            let mut journal = rw(&fixture.journal);
            assert!(
                lab_reconstruct::apply(&mut target, &mut shadow, &mut journal, &ticket, &binding())
                    .is_err()
            );
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "child_recovery_process",
                "--nocapture",
            ])
            .env("N2R_TEST_JOURNAL_CHILD", fixture.target.parent().unwrap())
            .env("N2R_TEST_JOURNAL_ACTION", action)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            fs::read(&fixture.target).unwrap(),
            if action == "resume" {
                &fixture.expected
            } else {
                &fixture.original
            }
            .clone()
        );
    }
}

#[test]
fn journal_descriptor_is_read_only_and_has_exact_validated_ranges() {
    let fixture = Fixture::new();
    let ticket = fixture.prepare().ticket;
    let original = fs::read(&fixture.journal).unwrap();
    let mut journal = File::open(&fixture.journal).unwrap();
    let descriptor = lab_reconstruct::inspect_journal(&mut journal, &ticket, &binding()).unwrap();
    assert_eq!(descriptor.changed_bytes, 12_288);
    assert_eq!(descriptor.expected_postimage_sha256, sha(&fixture.expected));
    assert_eq!(
        descriptor.request.source_sha256,
        fixture.request.source_sha256
    );
    assert_eq!(descriptor.immutable_sha256, ticket.immutable_sha256);
    assert_eq!(
        descriptor
            .patches
            .iter()
            .map(|range| (range.offset, range.length))
            .collect::<Vec<_>>(),
        [(0, 4096), (12_288, 4096), (24_576, 4096)]
    );
    assert_eq!(fs::read(&fixture.journal).unwrap(), original);
    assert_eq!(fs::read(&fixture.target).unwrap(), fixture.original);
    let mut wrong_binding = binding();
    wrong_binding.target_identity_sha256 = "4".repeat(64);
    assert!(lab_reconstruct::inspect_journal(&mut journal, &ticket, &wrong_binding).is_err());
    let mut wrong_ticket = ticket.clone();
    wrong_ticket.immutable_sha256 = "0".repeat(64);
    assert!(lab_reconstruct::inspect_journal(&mut journal, &wrong_ticket, &binding()).is_err());
    drop(journal);
    let mut changed = original;
    changed[4095] = 1;
    fs::write(&fixture.journal, changed).unwrap();
    let mut journal = File::open(&fixture.journal).unwrap();
    assert!(
        lab_reconstruct::inspect_journal(&mut journal, &ticket, &binding())
            .unwrap_err()
            .to_string()
            .contains("handoff may have started")
    );
}
