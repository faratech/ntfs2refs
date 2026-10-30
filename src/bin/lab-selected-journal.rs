//! Owned ordinary-file integration experiment; no caller image/device options.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use ntfs2refs::{
    lab_reconstruct::{DurableIo, ReadSeek},
    selected_journal as sj,
};
use serde::Serialize;
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Component, Path, PathBuf},
};
const IMAGE: u64 = 8 * 1024 * 1024;
const G: usize = 4096;
const JOURNAL: u64 = 65536;
#[derive(Parser)]
struct Args {
    #[arg(long)]
    directory: PathBuf,
    /// Exercise the zero-new representation, keeping the legacy case default.
    #[arg(long)]
    zero_new: bool,
}
#[derive(Default, Clone, Serialize)]
struct Counts {
    reads: u64,
    bytes_read: u64,
    writes: u64,
    bytes_written: u64,
    seeks: u64,
    syncs: u64,
    fault_syncs: u64,
    denied: u64,
    short_writes: u64,
}
struct Fenced {
    file: File,
    pos: u64,
    limit: u64,
    ranges: Option<Vec<sj::SelectedRange>>,
    writable: bool,
    fault: bool,
    count: Counts,
}
impl Fenced {
    fn open(
        path: &Path,
        ranges: Option<&[sj::SelectedRange]>,
        writable: bool,
        create: bool,
    ) -> Result<Self> {
        let mut o = OpenOptions::new();
        o.read(true).write(writable).create_new(create);
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            o.share_mode(0).custom_flags(0x0020_0000);
        }
        let file = o.open(path)?;
        ensure!(file.metadata()?.is_file(), "owned ordinary file required");
        Ok(Self {
            file,
            pos: 0,
            limit: if ranges.is_some() { IMAGE } else { JOURNAL },
            ranges: ranges.map(|r| r.to_vec()),
            writable,
            fault: false,
            count: Counts::default(),
        })
    }
    fn permit(&mut self, n: usize, write: bool) -> io::Result<()> {
        let end = self.pos.checked_add(n as u64);
        let ok = end.is_some_and(|end| {
            end <= self.limit
                && self.ranges.as_ref().is_none_or(|rs| {
                    rs.iter()
                        .any(|r| self.pos >= r.offset && end <= r.offset + r.length)
                })
        });
        if !ok || (write && !self.writable) {
            self.count.denied += 1;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "core I/O outside selected image ranges/journal bound",
            ));
        }
        Ok(())
    }
}
impl Read for Fenced {
    fn read(&mut self, b: &mut [u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        self.permit(b.len(), false)?;
        let n = self.file.read(b)?;
        self.pos += n as u64;
        self.count.reads += 1;
        self.count.bytes_read += n as u64;
        Ok(n)
    }
}
impl Write for Fenced {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        if b.is_empty() {
            return Ok(0);
        }
        self.permit(b.len(), true)?;
        self.count.writes += 1;
        if self.fault && self.pos == 1024 * 1024 && b.len() > G {
            self.file.write_all(&b[..G])?;
            self.file.sync_all()?;
            self.pos += G as u64;
            self.count.bytes_written += G as u64;
            self.count.short_writes += 1;
            self.count.fault_syncs += 1;
            self.fault = false;
            return Ok(G);
        }
        let n = self.file.write(b)?;
        self.pos += n as u64;
        self.count.bytes_written += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.sync_all()
    }
}
impl Seek for Fenced {
    fn seek(&mut self, s: SeekFrom) -> io::Result<u64> {
        let p = match s {
            SeekFrom::Start(n) => i128::from(n),
            SeekFrom::Current(n) => i128::from(self.pos) + i128::from(n),
            SeekFrom::End(n) => i128::from(self.file.metadata()?.len()) + i128::from(n),
        };
        if p < 0 || p > i128::from(self.limit) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside owned file bound",
            ));
        }
        self.file.seek(SeekFrom::Start(p as u64))?;
        self.pos = p as u64;
        self.count.seeks += 1;
        Ok(self.pos)
    }
}
impl ReadSeek for Fenced {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }
}
impl DurableIo for Fenced {
    fn sync_all(&mut self) -> io::Result<()> {
        self.file.sync_all()?;
        self.count.syncs += 1;
        Ok(())
    }
}
fn fresh(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute()
            && fs::symlink_metadata(path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound),
        "fresh absolute directory required"
    );
    for c in path.components() {
        match c {
            Component::ParentDir | Component::CurDir => anyhow::bail!("traversal refused"),
            #[cfg(windows)]
            Component::Prefix(p) => ensure!(
                matches!(p.kind(), std::path::Prefix::Disk(_)),
                "device/UNC paths refused"
            ),
            Component::Normal(n) => {
                let n = n.to_str().context("Unicode path required")?;
                ensure!(
                    !n.ends_with([' ', '.'])
                        && !n.chars().any(|c| c.is_control()
                            || matches!(c, ':' | '"' | '<' | '>' | '|' | '?' | '*')),
                    "ambiguous directory component"
                );
            }
            _ => {}
        }
    }
    for p in path
        .ancestors()
        .skip(1)
        .filter(|p| !p.as_os_str().is_empty())
    {
        let m = fs::symlink_metadata(p)?;
        ensure!(
            m.is_dir() && !m.file_type().is_symlink(),
            "ordinary existing ancestry required"
        );
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            ensure!(m.file_attributes() & 0x400 == 0, "reparse ancestry refused");
        }
    }
    fs::create_dir(path)?;
    Ok(())
}
fn setup(path: &Path, candidate: bool, ranges: &[sj::SelectedRange]) -> Result<u64> {
    let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
    let mut b = vec![0u8; 65536];
    let mut at = 0;
    while at < IMAGE {
        for (i, v) in b.iter_mut().enumerate() {
            let p = at + i as u64;
            *v = (p % 251) as u8;
            if candidate
                && ranges
                    .iter()
                    .any(|r| p >= r.offset && p < r.offset + r.length)
            {
                *v ^= 0xa5;
            }
        }
        f.write_all(&b)?;
        at += b.len() as u64;
    }
    f.sync_all()?;
    Ok(at)
}
fn exercise(
    dir: &Path,
    source: &mut Fenced,
    candidate: &mut Fenced,
    plan: &sj::SelectedPlan,
    forward: bool,
) -> Result<serde_json::Value> {
    let role = if forward { "resume" } else { "rollback" };
    let mut target = Fenced::open(
        &dir.join(format!("{role}-target.bin")),
        Some(&plan.ranges),
        true,
        false,
    )?;
    let mut journal = Fenced::open(&dir.join(format!("{role}.journal")), None, true, true)?;
    let ticket = sj::prepare(source, candidate, &mut journal, plan)?;
    ensure!(
        !ticket.whole_image_verified,
        "selected ticket cannot claim whole image"
    );
    let validation_before = journal.count.bytes_read;
    ensure!(
        sj::lifecycle(&mut journal, plan, &ticket)? == sj::SelectedLifecycle::PreparedClear,
        "fresh journal lifecycle differs"
    );
    let validation_read_bytes = journal.count.bytes_read - validation_before;
    // The immutable body is read exactly once; lifecycle then reads the two
    // 4 KiB marker slots. This assertion covers both actual payload formats.
    ensure!(
        validation_read_bytes == ticket.journal_length,
        "lifecycle validation reread or omitted journal bytes"
    );
    let duplicate_pass_read_bytes = 2 * (ticket.journal_length - 2 * G as u64) + 2 * G as u64;
    target.fault = true;
    let error = sj::apply(&mut target, &mut journal, plan, &ticket)
        .err()
        .context("one-granule persisted short write must stop apply")?;
    ensure!(
        target.count.short_writes == 1 && target.count.bytes_written == G as u64,
        "exactly one persisted granule required before recovery"
    );
    let result = if forward {
        let r = sj::resume(&mut target, &mut journal, plan, &ticket)?;
        ensure!(
            !r.replay_closed && r.selected_sha256 == ticket.new_selected_sha256,
            "resume digest differs"
        );
        sj::handoff(&mut target, &mut journal, plan, &ticket)?
    } else {
        sj::rollback(&mut target, &mut journal, plan, &ticket)?
    };
    let expected = if forward {
        ticket.new_selected_sha256
    } else {
        ticket.old_selected_sha256
    };
    ensure!(
        result.replay_closed
            && result.selected_sha256 == expected
            && !result.whole_image_verified
            && !result.conversion_qualified,
        "completion digest/scope differs"
    );
    let resume_rejected = sj::resume(&mut target, &mut journal, plan, &ticket).is_err();
    let rollback_rejected = sj::rollback(&mut target, &mut journal, plan, &ticket).is_err();
    ensure!(
        resume_rejected
            && rollback_rejected
            && target.count.denied == 0
            && journal.count.denied == 0,
        "closed replay or core fence failed"
    );
    Ok(
        serde_json::json!({"role":role,"interrupted_apply_error":format!("{error:#}"),"fault_persisted_bytes":G,"selected_sha256":hex::encode(result.selected_sha256),"replay_closed":true,"resume_after_close_rejected":resume_rejected,"rollback_after_close_rejected":rollback_rejected,"single_pass_lifecycle_bytes_read":validation_read_bytes,"previous_duplicate_pass_lifecycle_bytes":duplicate_pass_read_bytes,"lifecycle_read_bytes_saved":duplicate_pass_read_bytes-validation_read_bytes,"target_core_io":target.count,"journal_core_io":journal.count}),
    )
}
fn verify(dir: &Path, ranges: &[sj::SelectedRange]) -> Result<u64> {
    let mut read = 0;
    for (target_name, expected_name) in [
        ("resume-target.bin", "candidate.bin"),
        ("rollback-target.bin", "source.bin"),
    ] {
        let mut target = File::open(dir.join(target_name))?;
        let mut expected = File::open(dir.join(expected_name))?;
        ensure!(
            target.metadata()?.len() == IMAGE && expected.metadata()?.len() == IMAGE,
            "verification length differs"
        );
        for r in ranges {
            let mut a = vec![0; r.length as usize];
            let mut b = vec![0; r.length as usize];
            target.seek(SeekFrom::Start(r.offset))?;
            expected.seek(SeekFrom::Start(r.offset))?;
            target.read_exact(&mut a)?;
            expected.read_exact(&mut b)?;
            read += r.length * 2;
            ensure!(a == b, "selected bytes differ after wrapper drop");
        }
        let mut source = File::open(dir.join("source.bin"))?;
        for at in [
            4096,
            1024 * 1024 - 4096,
            1024 * 1024 + 8192,
            4 * 1024 * 1024,
            IMAGE - 8192,
        ] {
            ensure!(
                !ranges
                    .iter()
                    .any(|r| at < r.offset + r.length && r.offset < at + G as u64),
                "sentinel overlaps selection"
            );
            let mut a = [0u8; G];
            let mut b = [0u8; G];
            target.seek(SeekFrom::Start(at))?;
            source.seek(SeekFrom::Start(at))?;
            target.read_exact(&mut a)?;
            source.read_exact(&mut b)?;
            read += 2 * G as u64;
            ensure!(a == b, "outside sentinel changed");
        }
    }
    Ok(read)
}
fn planned(dir: &Path) -> Result<serde_json::Value> {
    const MIB: u64 = 1024 * 1024;
    let coarse = vec![
        sj::SelectedRange {
            offset: 2 * MIB,
            length: 3 * MIB,
        },
        sj::SelectedRange {
            offset: 7 * MIB,
            length: 65536,
        },
    ];
    let differing = vec![
        sj::SelectedRange {
            offset: 2 * MIB + 8192,
            length: 4096,
        },
        sj::SelectedRange {
            offset: 3 * MIB - 4096,
            length: 8192,
        },
        sj::SelectedRange {
            offset: 7 * MIB + 16384,
            length: 4096,
        },
    ];
    setup(&dir.join("plan-source.bin"), false, &[])?;
    setup(&dir.join("plan-candidate.bin"), true, &differing)?;
    setup(&dir.join("plan-target.bin"), false, &[])?;
    let mut source = Fenced::open(&dir.join("plan-source.bin"), Some(&coarse), false, false)?;
    let mut candidate = Fenced::open(&dir.join("plan-candidate.bin"), Some(&coarse), false, false)?;
    let coarse_bytes: u64 = coarse.iter().map(|r| r.length).sum();
    let plan = sj::changed_plan(&mut source, &mut candidate, IMAGE, &coarse, 16384, JOURNAL)?;
    let planning_source = source.count.clone();
    let planning_candidate = candidate.count.clone();
    ensure!(
        plan.ranges == differing
            && planning_source.bytes_read == coarse_bytes
            && planning_candidate.bytes_read == coarse_bytes
            && planning_source.denied == 0
            && planning_candidate.denied == 0,
        "planned ranges or planning reads differ from the exact expectation"
    );
    let (planned_bytes, planned_journal) = plan.validate()?;
    let (_, coarse_journal) = sj::SelectedPlan {
        image_length: IMAGE,
        ranges: coarse.clone(),
        max_selected_bytes: IMAGE,
        max_journal_bytes: u64::MAX,
        new_zero_ranges: Vec::new(),
    }
    .validate()?;
    ensure!(
        planned_journal < JOURNAL && coarse_journal > JOURNAL,
        "pruning must bring the journal inside a bound the coarse selection exceeds"
    );
    let mut target = Fenced::open(
        &dir.join("plan-target.bin"),
        Some(&plan.ranges),
        true,
        false,
    )?;
    let mut journal = Fenced::open(&dir.join("plan.journal"), None, true, true)?;
    let ticket = sj::prepare(&mut source, &mut candidate, &mut journal, &plan)?;
    sj::apply(&mut target, &mut journal, &plan, &ticket)?;
    let result = sj::handoff(&mut target, &mut journal, &plan, &ticket)?;
    ensure!(
        result.replay_closed
            && result.selected_sha256 == ticket.new_selected_sha256
            && source.count.denied == 0
            && candidate.count.denied == 0
            && target.count.denied == 0
            && journal.count.denied == 0,
        "pruned apply scope or core fence failed"
    );
    drop((source, candidate, target, journal));
    let mut verified = 0u64;
    let mut target = File::open(dir.join("plan-target.bin"))?;
    let mut expected = File::open(dir.join("plan-candidate.bin"))?;
    for r in &coarse {
        let mut a = vec![0; r.length as usize];
        let mut b = vec![0; r.length as usize];
        target.seek(SeekFrom::Start(r.offset))?;
        expected.seek(SeekFrom::Start(r.offset))?;
        target.read_exact(&mut a)?;
        expected.read_exact(&mut b)?;
        verified += r.length * 2;
        ensure!(
            a == b,
            "coarse region differs from the candidate after pruned apply"
        );
    }
    let mut original = File::open(dir.join("plan-source.bin"))?;
    for at in [0, MIB, 5 * MIB + 4096, 6 * MIB, IMAGE - 4096] {
        let mut a = [0u8; G];
        let mut b = [0u8; G];
        target.seek(SeekFrom::Start(at))?;
        original.seek(SeekFrom::Start(at))?;
        target.read_exact(&mut a)?;
        original.read_exact(&mut b)?;
        verified += 2 * G as u64;
        ensure!(a == b, "block outside the coarse selection changed");
    }
    Ok(serde_json::json!({
        "coarse_ranges": coarse,
        "coarse_bytes": coarse_bytes,
        "coarse_journal_bytes": coarse_journal,
        "planned_ranges": plan.ranges,
        "planned_bytes": planned_bytes,
        "planned_journal_bytes": planned_journal,
        "planning_source_io": planning_source,
        "planning_candidate_io": planning_candidate,
        "selected_sha256": hex::encode(result.selected_sha256),
        "independent_verification_bytes_read": verified,
        "outside_sentinel_blocks_checked": 5,
        "whole_image_verified": false
    }))
}
fn main() -> Result<()> {
    let args = Args::parse();
    fresh(&args.directory)?;
    let mut plan = sj::SelectedPlan {
        image_length: IMAGE,
        ranges: vec![
            sj::SelectedRange {
                offset: 0,
                length: 4096,
            },
            sj::SelectedRange {
                offset: 1024 * 1024,
                length: 8192,
            },
            sj::SelectedRange {
                offset: IMAGE - 4096,
                length: 4096,
            },
        ],
        max_selected_bytes: 16384,
        max_journal_bytes: JOURNAL,
        new_zero_ranges: Vec::new(),
    };
    let legacy_journal_bytes = plan.validate()?.1;
    if args.zero_new {
        plan.new_zero_ranges = plan.ranges[..2].to_vec();
    }
    plan.validate()?;
    let mut setup_bytes = 0;
    for (name, candidate) in [
        ("source.bin", false),
        ("candidate.bin", true),
        ("resume-target.bin", false),
        ("rollback-target.bin", false),
    ] {
        setup_bytes += setup(&args.directory.join(name), candidate, &plan.ranges)?;
    }
    if args.zero_new {
        let mut file = OpenOptions::new()
            .write(true)
            .open(args.directory.join("candidate.bin"))?;
        for range in &plan.new_zero_ranges {
            file.seek(SeekFrom::Start(range.offset))?;
            file.write_all(&vec![0; range.length as usize])?;
        }
        file.sync_all()?;
    }
    let mut source = Fenced::open(
        &args.directory.join("source.bin"),
        Some(&plan.ranges),
        false,
        false,
    )?;
    let mut candidate = Fenced::open(
        &args.directory.join("candidate.bin"),
        Some(&plan.ranges),
        false,
        false,
    )?;
    let resumed = exercise(&args.directory, &mut source, &mut candidate, &plan, true)?;
    let rolled_back = exercise(&args.directory, &mut source, &mut candidate, &plan, false)?;
    ensure!(
        source.count.denied == 0 && candidate.count.denied == 0,
        "core complement input read attempted"
    );
    let source_io = source.count.clone();
    let candidate_io = candidate.count.clone();
    let false_zero_claim_rejected = if args.zero_new {
        let mut false_plan = plan.clone();
        false_plan.new_zero_ranges = vec![plan.ranges[2].clone()];
        let mut rejected = Fenced::open(
            &args.directory.join("false-zero-claim.journal"),
            None,
            true,
            true,
        )?;
        sj::prepare(&mut source, &mut candidate, &mut rejected, &false_plan).is_err()
    } else {
        false
    };
    ensure!(
        !args.zero_new || false_zero_claim_rejected,
        "nonzero candidate accepted as zero"
    );
    drop(source);
    drop(candidate);
    let verification_bytes = verify(&args.directory, &plan.ranges)?;
    let pruned = planned(&args.directory)?;
    let report = serde_json::json!({"kind":"ordinary-file-selected-journal-integration","success":true,"plan":plan,"zero_new_encoding":args.zero_new,"journal_bytes":plan.validate()?.1,"legacy_journal_bytes":legacy_journal_bytes,"new_zero_payload_bytes_omitted":plan.new_zero_bytes()?,"false_zero_claim_rejected":false_zero_claim_rejected,"changed_granule_planning":pruned,"setup_image_bytes_written":setup_bytes,"source_core_io":source_io,"candidate_core_io":candidate_io,"resume":resumed,"rollback":rolled_back,"independent_verification_bytes_read":verification_bytes,"outside_sentinel_blocks_checked":10,"core_complement_io_permitted":false,"whole_image_verified":false,"conversion_qualified":false,"scope":"Owned ordinary8MiB files only. Selected bytes and sampled outside sentinels verified independently after all core wrappers closed. No metadata ownership or native conversion qualification."});
    let bytes = serde_json::to_vec_pretty(&report)?;
    ensure!(bytes.len() <= 65536, "report exceeds64KiB");
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(args.directory.join("report.json"))?;
    output.write_all(&bytes)?;
    output.sync_all()?;
    println!("{}", String::from_utf8(bytes)?);
    Ok(())
}
