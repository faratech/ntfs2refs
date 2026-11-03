//! Raw ancestry classification with disk states and RAM-accounted DFS frames.
use super::*;
use super::{
    paged_files::{PagedRawFiles, file_key},
    paged_storage::{SourceRamLease, SourceScratch, SourceTemporaryLease},
    record_store::SortedRecordWriter,
};
use std::{
    fs::{File, OpenOptions},
    os::windows::fs::OpenOptionsExt,
    path::Path,
};

struct States {
    file: File,
    rows: u64,
    _lease: SourceTemporaryLease,
}
fn issue(value: u8) -> Result<MetadataRoleIssue> {
    use MetadataRoleIssue::*;
    Ok(match value {
        0 => InvalidRootAnchor,
        1 => InvalidExtendAnchor,
        2 => ExtensionRecord,
        3 => AttributeListUnassembled,
        4 => ZeroSequenceNumber,
        5 => MissingNames,
        6 => LinkCountMismatch,
        7 => InvalidName,
        8 => MissingParent,
        9 => ParentSequenceMismatch,
        10 => ParentNotDirectory,
        11 => UnsupportedReservedParent,
        12 => Cycle,
        13 => MixedAncestry,
        14 => AncestorUnresolved,
        15 => DepthLimit,
        _ => anyhow::bail!("invalid ancestry state byte"),
    })
}
impl States {
    fn new(path: &Path, rows: u64, scratch: &SourceScratch) -> Result<Self> {
        let lease = scratch.reserve_temporary_file(path, rows, 4096)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .share_mode(0)
            .custom_flags(0x0020_0000)
            .open(path)?;
        file.set_len(rows)?;
        Ok(Self {
            file,
            rows,
            _lease: lease,
        })
    }
    fn get(&mut self, row: u64) -> Result<AncestryState> {
        ensure!(
            row < self.rows,
            "ancestry state escapes complete file domain"
        );
        let mut byte = [0];
        self.file.seek(SeekFrom::Start(row))?;
        self.file.read_exact(&mut byte)?;
        Ok(match byte[0] {
            0 => AncestryState::Unseen,
            1 => AncestryState::Visiting,
            2 => AncestryState::OutsideExtend,
            3 => AncestryState::WithinExtend,
            n => AncestryState::Unresolved(issue(n - 4)?),
        })
    }
    fn set(&mut self, row: u64, state: AncestryState) -> Result<()> {
        ensure!(
            row < self.rows,
            "ancestry state escapes complete file domain"
        );
        let byte = match state {
            AncestryState::Unseen => 0,
            AncestryState::Visiting => 1,
            AncestryState::OutsideExtend => 2,
            AncestryState::WithinExtend => 3,
            AncestryState::Unresolved(problem) => 4 + problem as u8,
        };
        self.file.seek(SeekFrom::Start(row))?;
        self.file.write_all(&[byte])?;
        Ok(())
    }
}
struct Frame {
    ordinal: u64,
    next_name: usize,
    mask: u8,
    _ram: SourceRamLease,
}
fn push(stack: &mut Vec<Frame>, ordinal: u64, scratch: &SourceScratch) -> Result<()> {
    let ram = scratch.lease_ram((2 * std::mem::size_of::<Frame>()) as u64)?;
    stack.try_reserve(1)?;
    stack.push(Frame {
        ordinal,
        next_name: 0,
        mask: 0,
        _ram: ram,
    });
    Ok(())
}
pub(super) fn classify(
    files: &mut PagedRawFiles,
    root: &Path,
    scratch: &SourceScratch,
    mut blocked: impl FnMut(InspectionBlocker) -> Result<()>,
) -> Result<()> {
    use AncestryState as State;
    use MetadataRoleIssue as Issue;
    files.revalidate()?;
    let _rows = scratch.lease_ram(
        scratch
            .budget()
            .record_bytes
            .checked_mul(8)
            .context("ancestry row RAM overflow")?,
    )?;
    let mut states = States::new(&root.join("ancestry.states"), files.file_count(), scratch)?;
    let root_file = files.find_record(5, None)?;
    let root_valid = root_file
        .as_ref()
        .is_some_and(|file| valid_role_anchor(file, &[u16::from(b'.')], file.sequence_number));
    for ordinal in 0..files.file_count() {
        let file = files.file(ordinal)?;
        if file.record_number < 16 {
            states.set(
                ordinal,
                match file.record_number {
                    5 if root_valid => State::OutsideExtend,
                    5 => State::Unresolved(Issue::InvalidRootAnchor),
                    11 if root_valid
                        && valid_role_anchor(
                            &file,
                            &[36, 69, 120, 116, 101, 110, 100],
                            root_file
                                .as_ref()
                                .context("validated root absent")?
                                .sequence_number,
                        ) =>
                    {
                        State::WithinExtend
                    }
                    11 => State::Unresolved(Issue::InvalidExtendAnchor),
                    _ => State::Unresolved(Issue::UnsupportedReservedParent),
                },
            )?;
        } else if let Some(problem) = local_ancestry_issue(&file) {
            states.set(ordinal, State::Unresolved(problem))?;
        }
    }
    drop(root_file);
    let mut stack = Vec::new();
    for start in 0..files.file_count() {
        if !matches!(states.get(start)?, State::Unseen) {
            continue;
        }
        states.set(start, State::Visiting)?;
        push(&mut stack, start, scratch)?;
        while !stack.is_empty() {
            let current = stack.last().context("ancestry frame absent")?.ordinal;
            let file = files.file(current)?;
            let at = stack.last().context("ancestry frame absent")?.next_name;
            if at == file.names.len() {
                let mask = stack.last().context("ancestry frame absent")?.mask;
                states.set(
                    current,
                    match mask {
                        1 => State::OutsideExtend,
                        2 => State::WithinExtend,
                        3 => State::Unresolved(Issue::MixedAncestry),
                        _ => State::Unresolved(Issue::MissingNames),
                    },
                )?;
                stack.pop();
                continue;
            }
            let name = &file.names[at];
            let parent = files.ordinal(name.parent_record_number)?;
            let parent_file = parent.map(|ordinal| files.file(ordinal)).transpose()?;
            let problem = match &parent_file {
                None => Some(Issue::MissingParent),
                Some(p) if p.sequence_number != name.parent_sequence_number => {
                    Some(Issue::ParentSequenceMismatch)
                }
                Some(p) if !p.is_directory => Some(Issue::ParentNotDirectory),
                _ => None,
            };
            if let Some(problem) = problem {
                states.set(current, State::Unresolved(problem))?;
                stack.pop();
                continue;
            }
            let parent = parent.context("checked parent absent")?;
            match states.get(parent)? {
                State::OutsideExtend | State::WithinExtend => {
                    let bit = if matches!(states.get(parent)?, State::WithinExtend) {
                        2
                    } else {
                        1
                    };
                    let frame = stack.last_mut().context("ancestry frame absent")?;
                    frame.mask |= bit;
                    frame.next_name += 1;
                }
                State::Unresolved(_) => {
                    states.set(current, State::Unresolved(Issue::AncestorUnresolved))?;
                    stack.pop();
                }
                State::Visiting => {
                    states.set(current, State::Unresolved(Issue::Cycle))?;
                    stack.pop();
                }
                State::Unseen => {
                    states.set(parent, State::Visiting)?;
                    push(&mut stack, parent, scratch)?;
                }
            }
        }
    }
    let mut output =
        SortedRecordWriter::new(&root.join("classified-files"), *b"N2RFILE1", scratch)?;
    for ordinal in 0..files.file_count() {
        let state = states.get(ordinal)?;
        let mut file = files.file(ordinal)?;
        let problem = if file.record_number < 16 {
            file.metadata_role = MetadataRole::ReservedSystemRecord;
            match (file.record_number, state) {
                (5 | 11, State::Unresolved(problem)) => Some(problem),
                _ => None,
            }
        } else {
            file.metadata_role = match state {
                State::OutsideExtend => MetadataRole::OutsideExtendCandidate,
                State::WithinExtend => MetadataRole::ExtendDescendantCandidate,
                _ => MetadataRole::Unresolved,
            };
            match state {
                State::Unresolved(problem) => Some(problem),
                State::Unseen | State::Visiting => {
                    anyhow::bail!("incomplete metadata ancestry traversal")
                }
                _ => None,
            }
        };
        file.metadata_role_issue = problem;
        file.is_metadata = matches!(
            file.metadata_role,
            MetadataRole::ReservedSystemRecord | MetadataRole::ExtendDescendantCandidate
        );
        if let Some(problem) = problem {
            blocked(InspectionBlocker {
                code: "metadata_role_ancestry_unresolved".into(),
                message: format!("MFT metadata role has unresolved ancestry: {problem:?}"),
                file_record_number: Some(file.record_number),
            })?;
        }
        output.push(file_key(file.record_number), &file)?;
    }
    drop(_rows);
    files.replace_files(&output.finish()?)?;
    files.revalidate()
}
