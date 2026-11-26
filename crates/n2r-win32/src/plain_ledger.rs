//! Objects a conversion turns into plain files, and the records that say so.
//!
//! Some NTFS features have nothing on ReFS to become: an EFS-encrypted
//! file, a file WOF keeps compressed, a deduplicated or single-instance
//! file, a cloud or ProjFS placeholder, and the TEMPORARY and OFFLINE
//! attributes. With the user's explicit consent, given for a list that
//! names each such object, a conversion makes each into a plain file: the
//! bytes a user reading it through Windows saw, every other piece of its
//! metadata as it was, and the feature itself gone.
//!
//! Three things are kept apart here, and each has its own type:
//!
//! - [`PlainList`]: what the user is asked to agree to, before anything is
//!   frozen. Its text is written to a file and its SHA-256 is what
//!   `--accept-plain` names.
//! - [`PlainLedger`]: what a run converted, written once the source is
//!   frozen, one row per object with its state before and after and what
//!   witnessed it.
//! - The content verdict (`volume_manifest::compare_with_plain`), which holds
//!   every ledger row to the listings taken before and after the run.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The run's records: the ledger of what was converted to plain.
pub const LEDGER_FILE: &str = "plain-conversions.json";
/// The schema of [`PlainLedger`].
pub const LEDGER_KIND: &str = "plain-conversions-v1";
/// The first line of a list file, which names its format.
pub const LIST_HEADER: &str = "ntfs2refs plain-conversions list v1";

/// FILE_ATTRIBUTE_TEMPORARY.
pub const TEMPORARY: u32 = 0x100;
/// FILE_ATTRIBUTE_OFFLINE.
pub const OFFLINE: u32 = 0x1000;
/// FILE_ATTRIBUTE_ENCRYPTED.
pub const ENCRYPTED: u32 = 0x4000;
/// FILE_ATTRIBUTE_REPARSE_POINT.
pub const REPARSE_POINT: u32 = 0x400;
/// FILE_ATTRIBUTE_SPARSE_FILE.
pub const SPARSE_FILE: u32 = 0x200;
/// FILE_ATTRIBUTE_PINNED, FILE_ATTRIBUTE_UNPINNED,
/// FILE_ATTRIBUTE_RECALL_ON_OPEN and FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS:
/// what a cloud provider's placeholder carries.
pub const CLOUD_ATTRIBUTES: u32 = 0x8_0000 | 0x10_0000 | 0x4_0000 | 0x40_0000;
/// The attributes [`PlainKind::AttributesCleared`] may clear. Nothing else
/// is ever taken off an object by that kind.
pub const CLEARABLE_ATTRIBUTES: u32 = TEMPORARY | OFFLINE;

/// What a conversion does to an object to make it a plain file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlainKind {
    /// The TEMPORARY or OFFLINE attribute (with no reparse point) is
    /// cleared; nothing else changes.
    AttributesCleared,
    /// An EFS-encrypted file becomes the plain text its owner read.
    EfsDecrypted,
    /// A file WOF keeps compressed (compact /exe, CompactOS) becomes its
    /// uncompressed bytes.
    WofExpanded,
    /// A deduplicated file becomes its whole contents.
    DedupRehydrated,
    /// A cloud-files placeholder, present on the volume, becomes the file
    /// its provider showed.
    CloudPlaceholderPlain,
    /// A ProjFS placeholder becomes the file it projected.
    ProjfsPlaceholderPlain,
    /// A single-instance-storage link becomes its own copy of the file.
    SisExpanded,
    /// A cloud placeholder that could not be brought onto the volume is
    /// left out of the conversion, as the user agreed: it stays in the
    /// cloud and is not on the new volume.
    CloudLeftOut,
}

impl PlainKind {
    pub const ALL: [PlainKind; 8] = [
        PlainKind::AttributesCleared,
        PlainKind::EfsDecrypted,
        PlainKind::WofExpanded,
        PlainKind::DedupRehydrated,
        PlainKind::CloudPlaceholderPlain,
        PlainKind::ProjfsPlaceholderPlain,
        PlainKind::SisExpanded,
        PlainKind::CloudLeftOut,
    ];

    /// The name the list, the ledger and the reports use.
    pub fn name(self) -> &'static str {
        match self {
            PlainKind::AttributesCleared => "attributes_cleared",
            PlainKind::EfsDecrypted => "efs_decrypted",
            PlainKind::WofExpanded => "wof_expanded",
            PlainKind::DedupRehydrated => "dedup_rehydrated",
            PlainKind::CloudPlaceholderPlain => "cloud_placeholder_plain",
            PlainKind::ProjfsPlaceholderPlain => "projfs_placeholder_plain",
            PlainKind::SisExpanded => "sis_expanded",
            PlainKind::CloudLeftOut => "cloud_left_out",
        }
    }

    pub fn parse(name: &str) -> Option<PlainKind> {
        PlainKind::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// What it means for the user, in the words a run prints.
    pub fn describe(self) -> &'static str {
        match self {
            PlainKind::AttributesCleared => {
                "the TEMPORARY or OFFLINE attribute is cleared; contents and every other attribute stay as they are"
            }
            PlainKind::EfsDecrypted => "EFS encryption is removed: the file holds its plain text",
            PlainKind::WofExpanded => {
                "WOF compression (compact /exe, CompactOS) is removed: the file holds its uncompressed bytes"
            }
            PlainKind::DedupRehydrated => {
                "Data Deduplication is removed: the file holds its whole contents"
            }
            PlainKind::CloudPlaceholderPlain => {
                "the cloud placeholder becomes an ordinary file; the provider no longer syncs it"
            }
            PlainKind::ProjfsPlaceholderPlain => {
                "the ProjFS placeholder becomes an ordinary file; the provider no longer projects it"
            }
            PlainKind::SisExpanded => "the single-instance link becomes the file's own copy",
            PlainKind::CloudLeftOut => {
                "not on the volume and could not be brought there: it is left out and stays in the cloud"
            }
        }
    }

    /// Whether this build converts objects of this kind. The others are
    /// modelled, so that a list, a ledger and the verdict can name them,
    /// and are still refused where they are found.
    pub fn implemented(self) -> bool {
        matches!(
            self,
            PlainKind::AttributesCleared
                | PlainKind::WofExpanded
                | PlainKind::EfsDecrypted
                | PlainKind::CloudPlaceholderPlain
                | PlainKind::CloudLeftOut
        )
    }
}

impl std::fmt::Display for PlainKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// One object the user is asked to agree to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainEntry {
    pub kind: PlainKind,
    /// As a listing names it: below the volume root, starting with `\`.
    pub path: String,
    /// The file attributes the conversion takes off (for the kinds that
    /// take any off).
    pub cleared_attributes: u32,
    /// The bytes of its streams, as a user reads them.
    pub bytes: u64,
    /// What it takes on the new volume beyond what it takes on the source.
    pub volume_extra_bytes: u64,
    /// What it takes in the working storage while the run lasts.
    pub working_extra_bytes: u64,
    /// What has to be downloaded onto the source before it is frozen.
    pub download_bytes: u64,
}

impl PlainEntry {
    /// What makes two entries the same agreement: the kind, the object and
    /// what is taken off it. Sizes are reported, not agreed to.
    fn key(&self) -> (&str, PlainKind, u32) {
        (self.path.as_str(), self.kind, self.cleared_attributes)
    }
}

/// The list of objects a run converts to plain files, in path order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PlainList {
    entries: Vec<PlainEntry>,
}

/// What each kind amounts to in a list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct KindTotal {
    pub objects: u64,
    pub bytes: u64,
    pub volume_extra_bytes: u64,
    pub working_extra_bytes: u64,
    pub download_bytes: u64,
}

impl PlainList {
    /// Sorts the entries and refuses a list that could not be read back as
    /// it was written: a path that is not a listing's, or with a tab or a
    /// line break in it, and an object named twice for one kind.
    pub fn new(mut entries: Vec<PlainEntry>) -> Result<Self, String> {
        for entry in &entries {
            if !entry.path.starts_with('\\')
                || entry.path.chars().any(|c| matches!(c, '\t' | '\n' | '\r'))
            {
                return Err(format!(
                    "{:?} is not a path a plain-conversions list can hold",
                    entry.path
                ));
            }
            if entry.cleared_attributes & !CLEARABLE_ATTRIBUTES != 0 {
                return Err(format!(
                    "{}: a conversion to plain clears TEMPORARY and OFFLINE only, not {:#x}",
                    entry.path, entry.cleared_attributes
                ));
            }
        }
        entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.kind.cmp(&b.kind)));
        if let Some(pair) = entries
            .windows(2)
            .find(|pair| pair[0].path == pair[1].path && pair[0].kind == pair[1].kind)
        {
            return Err(format!(
                "{} is in the list twice as {}",
                pair[0].path, pair[0].kind
            ));
        }
        Ok(Self { entries })
    }

    pub fn entries(&self) -> &[PlainEntry] {
        &self.entries
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// The list as the file a user reads and agrees to. One line per
    /// object: kind, attributes taken off, bytes, path.
    pub fn text(&self) -> String {
        let mut text = String::with_capacity(64 + self.entries.len() * 64);
        text.push_str(LIST_HEADER);
        text.push('\n');
        for entry in &self.entries {
            text.push_str(&format!(
                "{}\t{:#x}\t{}\t{}\n",
                entry.kind, entry.cleared_attributes, entry.bytes, entry.path
            ));
        }
        text
    }

    /// The SHA-256 of [`Self::text`], which `--accept-plain` names.
    pub fn sha256(&self) -> String {
        hex::encode(Sha256::digest(self.text().as_bytes()))
    }

    /// Each kind's objects and bytes.
    pub fn totals(&self) -> BTreeMap<PlainKind, KindTotal> {
        let mut totals: BTreeMap<PlainKind, KindTotal> = BTreeMap::new();
        for entry in &self.entries {
            let total = totals.entry(entry.kind).or_default();
            total.objects += 1;
            total.bytes = total.bytes.saturating_add(entry.bytes);
            total.volume_extra_bytes = total
                .volume_extra_bytes
                .saturating_add(entry.volume_extra_bytes);
            total.working_extra_bytes = total
                .working_extra_bytes
                .saturating_add(entry.working_extra_bytes);
            total.download_bytes = total.download_bytes.saturating_add(entry.download_bytes);
        }
        totals
    }

    /// The entries of this list that `agreed` does not hold exactly (the
    /// same object, the same kind, the same attributes taken off). Empty
    /// when this list is a subset of the agreed one.
    pub fn not_in<'a>(&'a self, agreed: &PlainList) -> Vec<&'a PlainEntry> {
        let held: std::collections::BTreeSet<_> =
            agreed.entries.iter().map(PlainEntry::key).collect();
        // What is below a folder agreed to be left out is left out with it.
        let folders: Vec<&str> = agreed
            .entries
            .iter()
            .filter(|entry| entry.kind == PlainKind::CloudLeftOut)
            .map(|entry| entry.path.as_str())
            .collect();
        let below = |entry: &PlainEntry| {
            entry.kind == PlainKind::CloudLeftOut
                && folders.iter().any(|folder| {
                    entry.path.len() > folder.len()
                        && entry.path.starts_with(folder)
                        && entry.path.as_bytes()[folder.len()] == b'\\'
                })
        };
        self.entries
            .iter()
            .filter(|entry| !held.contains(&entry.key()) && !below(entry))
            .collect()
    }
}

/// An object's state as the ledger records it, before or after.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerState {
    /// The Win32 file attributes.
    pub attributes: u32,
    /// The reparse tag, where there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse_tag: Option<u32>,
}

/// One object a run converted to plain.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerRow {
    pub kind: PlainKind,
    /// Every name of the object, as a listing names them; the first is the
    /// one the agreed list names.
    pub paths: Vec<String>,
    pub record_number: u64,
    pub sequence_number: u16,
    pub before: LedgerState,
    pub after: LedgerState,
    /// What the before state was read from.
    pub witness: String,
    /// For an object made from its plain copy: that copy, as it was taken
    /// on the frozen source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_copy: Option<LedgerCopy>,
    /// For an EFS file decrypted: what the raw source held of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub efs: Option<LedgerEfs>,
    /// For a cloud placeholder made plain or left out: what the raw source
    /// held of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloud: Option<LedgerCloud>,
    /// For an object left out of the conversion (`cloud_left_out`): what
    /// the source's admission counted of it, which the new tree does not
    /// hold.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left_out: Option<LedgerLeftOut>,
}

/// What a left-out object took in the source's admission: the object, its
/// data streams and their bytes. Nothing else of the admission is changed
/// by leaving it out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerLeftOut {
    pub directory: bool,
    /// Its data streams, unnamed and named, as the admission counted them.
    pub streams: u64,
    /// Their logical bytes.
    pub bytes: u64,
}

/// What every left-out object of a ledger takes in all.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LeftOutTotals {
    pub files: u64,
    pub directories: u64,
    pub streams: u64,
    pub bytes: u64,
}

impl LeftOutTotals {
    pub fn objects(&self) -> u64 {
        self.files + self.directories
    }
}

/// What the raw source held of a cloud placeholder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCloud {
    /// Its reparse tag (0x9000x01A).
    pub tag: u32,
    pub directory: bool,
    /// Its length as a program reads it.
    pub plain_bytes: u64,
    /// The bytes below its length that the frozen source held no clusters
    /// for: 0 for one made plain, which has to be wholly on the volume.
    pub raw_missing_bytes: u64,
}

/// What the raw source held of an EFS file made plain, to tie its plain
/// copy to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerEfs {
    /// The raw `$EFS` attribute's digest (resident), or a SHA-256 of where
    /// it lies.
    pub efs_attribute_digest: String,
    /// A SHA-256 of where the ciphertext lies and its sizes.
    pub ciphertext_extents_sha256: String,
}

/// The plain copy a new file was made from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerCopy {
    pub bytes: u64,
    pub sha256: String,
    /// XXH3-128, as the new file's stream is held to it.
    pub content_digest: String,
}

/// What a run converted to plain, as it keeps it in its records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlainLedger {
    /// [`LEDGER_KIND`].
    pub kind: String,
    /// The SHA-256 of the list the user agreed to.
    pub agreed_list_sha256: String,
    /// The SHA-256 of the list made from the frozen source, a subset of
    /// the agreed one.
    pub frozen_list_sha256: String,
    pub source_inspection_sha256: String,
    pub rows: Vec<LedgerRow>,
}

impl PlainLedger {
    /// Refuses a ledger that is not one this build writes, or whose rows
    /// could not be what a conversion to plain did.
    pub fn validate(&self) -> Result<(), String> {
        if self.kind != LEDGER_KIND {
            return Err(format!(
                "the plain-conversions ledger is of kind {:?}, not {LEDGER_KIND}",
                self.kind
            ));
        }
        let mut names = std::collections::BTreeSet::new();
        for row in &self.rows {
            if row.paths.is_empty() {
                return Err(format!(
                    "a ledger row for MFT record {} names no path",
                    row.record_number
                ));
            }
            for path in &row.paths {
                if !names.insert(path.as_str()) {
                    return Err(format!("{path} is in the plain-conversions ledger twice"));
                }
            }
        }
        Ok(())
    }

    /// Each kind's number of objects.
    pub fn counts(&self) -> BTreeMap<PlainKind, usize> {
        let mut counts = BTreeMap::new();
        for row in &self.rows {
            *counts.entry(row.kind).or_default() += 1;
        }
        counts
    }
}

/// The source streams a ledger row's kind leaves off the new object, by
/// name: WofCompressedData for a file WOF kept compressed, none for any
/// other kind.
pub fn dropped_stream_names(kind: PlainKind) -> &'static [&'static str] {
    match kind {
        PlainKind::WofExpanded => &[crate::reparse_layout::WOF_COMPRESSED_DATA],
        _ => &[],
    }
}

/// The source streams a run's ledger declares left off its new objects,
/// object by object. The source's admission counts every stream the raw
/// volume holds; the new volume holds those less exactly these, and only
/// where they are declared.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DeclaredDrops {
    by_object: BTreeMap<(u64, u16), Vec<Vec<u16>>>,
    /// The objects left out of the new tree altogether (`cloud_left_out`),
    /// each declared by its own row.
    left_out: BTreeMap<(u64, u16), LedgerLeftOut>,
}

impl DeclaredDrops {
    /// The drops `ledger` declares: those of each row's kind, for that
    /// row's object alone.
    pub fn from_ledger(ledger: &PlainLedger) -> Result<Self, String> {
        ledger.validate()?;
        let mut by_object: BTreeMap<(u64, u16), Vec<Vec<u16>>> = BTreeMap::new();
        let mut left_out: BTreeMap<(u64, u16), LedgerLeftOut> = BTreeMap::new();
        for row in &ledger.rows {
            let key = (row.record_number, row.sequence_number);
            match (row.kind, row.left_out) {
                (PlainKind::CloudLeftOut, Some(counted)) => {
                    if left_out.insert(key, counted).is_some() {
                        return Err(format!(
                            "MFT record {} is left out in more than one row of the plain-conversions ledger",
                            row.record_number
                        ));
                    }
                    continue;
                }
                (PlainKind::CloudLeftOut, None) => {
                    return Err(format!(
                        "MFT record {} is left out, and its ledger row does not say what the admission counted of it",
                        row.record_number
                    ));
                }
                (_, Some(_)) => {
                    return Err(format!(
                        "MFT record {} is {} and declares what it left out, which only cloud_left_out does",
                        row.record_number, row.kind
                    ));
                }
                (_, None) => {}
            }
            let names = dropped_stream_names(row.kind);
            if names.is_empty() {
                continue;
            }
            let key = (row.record_number, row.sequence_number);
            if by_object.contains_key(&key) {
                return Err(format!(
                    "MFT record {} has more than one row in the plain-conversions ledger",
                    row.record_number
                ));
            }
            by_object.insert(
                key,
                names
                    .iter()
                    .map(|name| name.encode_utf16().collect())
                    .collect(),
            );
        }
        if let Some((record, _)) = left_out.keys().find(|key| by_object.contains_key(key)) {
            return Err(format!(
                "MFT record {record} is both left out and declared to drop a stream"
            ));
        }
        Ok(Self {
            by_object,
            left_out,
        })
    }

    /// Whether this object of the source is left out of the new tree.
    pub fn is_left_out(&self, record_number: u64, sequence_number: u16) -> bool {
        self.left_out
            .contains_key(&(record_number, sequence_number))
    }

    /// The objects left out, by identity.
    pub fn left_out_objects(&self) -> impl Iterator<Item = &(u64, u16)> {
        self.left_out.keys()
    }

    /// What the left-out objects take in all.
    pub fn left_out_totals(&self) -> LeftOutTotals {
        self.left_out
            .values()
            .fold(LeftOutTotals::default(), |mut totals, object| {
                if object.directory {
                    totals.directories += 1;
                } else {
                    totals.files += 1;
                }
                totals.streams += object.streams;
                totals.bytes += object.bytes;
                totals
            })
    }

    /// Every object declared left out has to have been met in the source,
    /// and not made: `skipped` holds those a tree build passed over.
    pub fn require_left_out(
        &self,
        skipped: &std::collections::BTreeSet<(u64, u16)>,
    ) -> Result<(), String> {
        match self.left_out.keys().find(|key| !skipped.contains(key)) {
            Some((record, _)) => Err(format!(
                "the plain-conversions ledger leaves out MFT record {record}, which the tree build did not meet"
            )),
            None => match skipped.iter().find(|key| !self.left_out.contains_key(key)) {
                Some((record, _)) => Err(format!(
                    "MFT record {record} was left out of the tree, and the ledger does not declare it"
                )),
                None => Ok(()),
            },
        }
    }

    /// The counts the source's admission holds, from the new tree's: its
    /// files, directories and data streams with every left-out object and
    /// every declared stream drop added back. Each is exact: an admission
    /// that differs from this differs from the new tree in something the
    /// ledger does not declare.
    pub fn admitted_from_new(
        &self,
        files: u64,
        directories: u64,
        streams: u64,
    ) -> Result<(u64, u64, u64), String> {
        let left_out = self.left_out_totals();
        let overflow = || {
            "the counts of the new tree with what the ledger declares left out overflow".to_owned()
        };
        Ok((
            files.checked_add(left_out.files).ok_or_else(overflow)?,
            directories
                .checked_add(left_out.directories)
                .ok_or_else(overflow)?,
            streams
                .checked_add(left_out.streams)
                .and_then(|n| n.checked_add(self.total()))
                .ok_or_else(overflow)?,
        ))
    }

    /// The admission's directories less those left out: what the new
    /// volume holds.
    pub fn expected_directories(&self, admitted: u64) -> Result<u64, String> {
        let left_out = self.left_out_totals().directories;
        admitted.checked_sub(left_out).ok_or_else(|| {
            format!("{left_out} directories are declared left out and the source holds {admitted}")
        })
    }

    /// The admission's objects less those left out.
    pub fn expected_objects(&self, admitted: u64) -> Result<u64, String> {
        let left_out = self.left_out_totals().objects();
        admitted.checked_sub(left_out).ok_or_else(|| {
            format!("{left_out} objects are declared left out and the source holds {admitted}")
        })
    }

    /// The admission's logical bytes less those of the left-out objects.
    pub fn expected_bytes(&self, admitted: u64) -> Result<u64, String> {
        let left_out = self.left_out_totals().bytes;
        admitted.checked_sub(left_out).ok_or_else(|| {
            format!("{left_out} bytes are declared left out and the source holds {admitted}")
        })
    }

    /// How many streams are declared dropped in all.
    pub fn total(&self) -> u64 {
        self.by_object
            .values()
            .map(|names| names.len() as u64)
            .sum()
    }

    /// The streams declared dropped from one object of the new tree, given
    /// the names of its named streams: 0 for an object no row declares
    /// anything of. An object that still has a stream declared dropped is
    /// an error.
    pub fn for_object<'a>(
        &self,
        record_number: u64,
        sequence_number: u16,
        mut named_streams: impl Iterator<Item = &'a [u16]>,
    ) -> Result<u64, String> {
        let Some(names) = self.by_object.get(&(record_number, sequence_number)) else {
            return Ok(0);
        };
        if named_streams.any(|name| names.iter().any(|dropped| dropped.as_slice() == name)) {
            return Err(format!(
                "MFT record {record_number} keeps a stream its plain-conversions ledger row declares dropped"
            ));
        }
        Ok(names.len() as u64)
    }

    /// Every object a drop was declared for has to have been met in the new
    /// tree: a declaration of an object the tree does not hold is an error.
    pub fn require_met(&self, met: &std::collections::BTreeSet<(u64, u16)>) -> Result<(), String> {
        match self.by_object.keys().find(|key| !met.contains(key)) {
            Some((record, _)) => Err(format!(
                "the plain-conversions ledger declares streams dropped from MFT record {record}, which the new tree does not hold"
            )),
            None => Ok(()),
        }
    }

    /// The admission's raw stream count less the declared drops and the
    /// streams of the objects left out: what the new volume holds.
    pub fn expected_streams(&self, admitted: u64) -> Result<u64, String> {
        let gone = self.total() + self.left_out_totals().streams;
        admitted.checked_sub(gone).ok_or_else(|| {
            format!(
                "{gone} streams are declared dropped or left out and the source holds {admitted}"
            )
        })
    }
}

static DECLARED: std::sync::Mutex<Option<DeclaredDrops>> = std::sync::Mutex::new(None);

/// This process's declared drops: those of the run it converts or
/// recovers, from its ledger.
pub fn declare(drops: DeclaredDrops) {
    *DECLARED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(drops);
}

/// What this process declared; none where nothing was.
pub fn declared() -> DeclaredDrops {
    DECLARED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wof_row(record: u64, kind: PlainKind) -> LedgerRow {
        LedgerRow {
            kind,
            paths: vec![format!("\\wof-{record}.bin")],
            record_number: record,
            sequence_number: 1,
            before: LedgerState::default(),
            after: LedgerState::default(),
            witness: "raw".into(),
            plain_copy: None,
            efs: None,
            cloud: None,
            left_out: None,
        }
    }

    fn ledger_of(rows: Vec<LedgerRow>) -> PlainLedger {
        PlainLedger {
            kind: LEDGER_KIND.into(),
            agreed_list_sha256: String::new(),
            frozen_list_sha256: String::new(),
            source_inspection_sha256: String::new(),
            rows,
        }
    }

    #[test]
    fn a_wof_object_verifies_with_its_compressed_data_dropped() {
        let drops = DeclaredDrops::from_ledger(&ledger_of(vec![
            wof_row(40, PlainKind::WofExpanded),
            wof_row(41, PlainKind::AttributesCleared),
        ]))
        .unwrap();
        // One stream, for the WOF row alone.
        assert_eq!(drops.total(), 1);
        assert_eq!(drops.for_object(40, 1, std::iter::empty()), Ok(1));
        assert_eq!(drops.expected_streams(10), Ok(9));
        let met: std::collections::BTreeSet<_> = [(40, 1), (41, 1)].into();
        assert!(drops.require_met(&met).is_ok());
    }

    #[test]
    fn the_new_tree_is_held_to_the_admission_with_its_drops_added_back() {
        let drops =
            DeclaredDrops::from_ledger(&ledger_of(vec![wof_row(40, PlainKind::WofExpanded)]))
                .unwrap();
        // The new tree holds one stream fewer than the admission counted:
        // the paged projection, the paged expected tree and the cached body
        // compare (files, directories, streams) with it added back.
        assert_eq!(drops.admitted_from_new(3, 2, 4), Ok((3, 2, 5)));
        // A stream dropped leaves its object.
        assert_eq!(drops.expected_objects(5), Ok(5));
        // Nothing declared: the counts stand as they are.
        assert_eq!(
            DeclaredDrops::default().admitted_from_new(3, 2, 4),
            Ok((3, 2, 4))
        );
        assert!(drops.admitted_from_new(0, 0, u64::MAX).is_err());
    }

    #[test]
    fn a_stream_missing_where_nothing_declares_it_is_not_excused() {
        let drops =
            DeclaredDrops::from_ledger(&ledger_of(vec![wof_row(40, PlainKind::WofExpanded)]))
                .unwrap();
        // Another object, or the same record of another sequence, or a row
        // of a kind that drops nothing: no drop.
        assert_eq!(drops.for_object(42, 1, std::iter::empty()), Ok(0));
        assert_eq!(drops.for_object(40, 2, std::iter::empty()), Ok(0));
        let cleared =
            DeclaredDrops::from_ledger(&ledger_of(vec![wof_row(40, PlainKind::AttributesCleared)]))
                .unwrap();
        assert_eq!(cleared.total(), 0);
        assert_eq!(cleared.for_object(40, 1, std::iter::empty()), Ok(0));
        // Nothing declared: the admission's count stands as it is.
        assert_eq!(DeclaredDrops::default().expected_streams(10), Ok(10));
    }

    #[test]
    fn a_declared_drop_holds_only_for_its_own_object_as_it_is() {
        let drops =
            DeclaredDrops::from_ledger(&ledger_of(vec![wof_row(40, PlainKind::WofExpanded)]))
                .unwrap();
        // Declared for an object the new tree does not hold.
        let met: std::collections::BTreeSet<_> = [(41, 1)].into();
        assert!(drops.require_met(&met).is_err());
        // The object still holds the stream declared dropped.
        let compressed: Vec<u16> = "WofCompressedData".encode_utf16().collect();
        assert!(
            drops
                .for_object(40, 1, [compressed.as_slice()].into_iter())
                .is_err()
        );
        // More dropped than there are streams.
        assert!(drops.expected_streams(0).is_err());
        // One object in two rows.
        assert!(
            DeclaredDrops::from_ledger(&ledger_of(vec![
                wof_row(40, PlainKind::WofExpanded),
                LedgerRow {
                    paths: vec!["\\other".into()],
                    ..wof_row(40, PlainKind::WofExpanded)
                },
            ]))
            .is_err()
        );
    }

    fn entry(path: &str, kind: PlainKind, cleared: u32) -> PlainEntry {
        PlainEntry {
            kind,
            path: path.to_owned(),
            cleared_attributes: cleared,
            bytes: 3000,
            volume_extra_bytes: 0,
            working_extra_bytes: 0,
            download_bytes: 0,
        }
    }

    #[test]
    fn every_kind_has_one_name_that_reads_back() {
        let mut names = std::collections::BTreeSet::new();
        for kind in PlainKind::ALL {
            assert!(names.insert(kind.name()), "{kind:?}");
            assert_eq!(PlainKind::parse(kind.name()), Some(kind));
            assert_eq!(
                serde_json::to_string(&kind).unwrap(),
                format!("\"{}\"", kind.name())
            );
            assert!(!kind.describe().is_empty());
        }
        assert_eq!(PlainKind::parse("plain"), None);
        // What this build converts.
        assert_eq!(
            PlainKind::ALL
                .iter()
                .filter(|kind| kind.implemented())
                .collect::<Vec<_>>(),
            [
                &PlainKind::AttributesCleared,
                &PlainKind::EfsDecrypted,
                &PlainKind::WofExpanded,
                &PlainKind::CloudPlaceholderPlain,
                &PlainKind::CloudLeftOut
            ]
        );
    }

    #[test]
    fn a_list_reads_the_same_whatever_order_it_was_found_in() {
        let a = PlainList::new(vec![
            entry("\\b\\offline.dat", PlainKind::AttributesCleared, OFFLINE),
            entry(
                "\\a\\temporary.tmp",
                PlainKind::AttributesCleared,
                TEMPORARY,
            ),
        ])
        .unwrap();
        let b = PlainList::new(vec![
            entry(
                "\\a\\temporary.tmp",
                PlainKind::AttributesCleared,
                TEMPORARY,
            ),
            entry("\\b\\offline.dat", PlainKind::AttributesCleared, OFFLINE),
        ])
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(a.sha256(), b.sha256());
        assert_eq!(
            a.text(),
            format!(
                "{LIST_HEADER}\nattributes_cleared\t0x100\t3000\t\\a\\temporary.tmp\nattributes_cleared\t0x1000\t3000\t\\b\\offline.dat\n"
            )
        );
        assert_eq!(a.sha256().len(), 64);
        assert_ne!(a.sha256(), PlainList::default().sha256());
    }

    #[test]
    fn a_list_refuses_what_it_could_not_say_back() {
        assert!(PlainList::new(vec![entry("a", PlainKind::AttributesCleared, 0x100)]).is_err());
        assert!(
            PlainList::new(vec![entry("\\a\tb", PlainKind::AttributesCleared, 0x100)]).is_err()
        );
        assert!(
            PlainList::new(vec![entry("\\a\nb", PlainKind::AttributesCleared, 0x100)]).is_err()
        );
        // Nothing but TEMPORARY and OFFLINE is ever taken off.
        assert!(
            PlainList::new(vec![entry(
                "\\a",
                PlainKind::AttributesCleared,
                TEMPORARY | ENCRYPTED
            )])
            .is_err()
        );
        assert!(
            PlainList::new(vec![
                entry("\\a", PlainKind::AttributesCleared, TEMPORARY),
                entry("\\a", PlainKind::AttributesCleared, OFFLINE),
            ])
            .is_err()
        );
    }

    #[test]
    fn what_was_frozen_is_held_to_what_was_agreed() {
        let agreed = PlainList::new(vec![
            entry("\\a", PlainKind::AttributesCleared, TEMPORARY),
            entry("\\b", PlainKind::AttributesCleared, OFFLINE),
        ])
        .unwrap();
        // Fewer objects are a subset.
        let fewer =
            PlainList::new(vec![entry("\\b", PlainKind::AttributesCleared, OFFLINE)]).unwrap();
        assert!(fewer.not_in(&agreed).is_empty());
        assert!(PlainList::default().not_in(&agreed).is_empty());
        // A new object, and one that now loses another attribute, are not.
        let more = PlainList::new(vec![
            entry("\\a", PlainKind::AttributesCleared, TEMPORARY | OFFLINE),
            entry("\\c", PlainKind::AttributesCleared, TEMPORARY),
        ])
        .unwrap();
        let missing: Vec<_> = more
            .not_in(&agreed)
            .iter()
            .map(|e| e.path.as_str())
            .collect();
        assert_eq!(missing, ["\\a", "\\c"]);
        // A size that changed is reported, not a new agreement.
        let mut resized = entry("\\a", PlainKind::AttributesCleared, TEMPORARY);
        resized.bytes = 1;
        assert!(
            PlainList::new(vec![resized])
                .unwrap()
                .not_in(&agreed)
                .is_empty()
        );
    }

    #[test]
    fn what_is_below_a_folder_left_out_is_agreed_with_it() {
        let agreed =
            PlainList::new(vec![entry("\\c\\folder", PlainKind::CloudLeftOut, 0)]).unwrap();
        let frozen = PlainList::new(vec![
            entry("\\c\\folder", PlainKind::CloudLeftOut, 0),
            entry("\\c\\folder\\x.txt", PlainKind::CloudLeftOut, 0),
        ])
        .unwrap();
        assert!(frozen.not_in(&agreed).is_empty());
        // Made plain below it, or a sibling of a similar name, is not.
        let other = PlainList::new(vec![
            entry("\\c\\folder\\y.txt", PlainKind::CloudPlaceholderPlain, 0),
            entry("\\c\\folder2", PlainKind::CloudLeftOut, 0),
        ])
        .unwrap();
        assert_eq!(other.not_in(&agreed).len(), 2);
    }

    #[test]
    fn left_out_objects_are_taken_off_the_counts_and_nothing_else() {
        let left = |record: u64, directory: bool, streams: u64, bytes: u64| LedgerRow {
            left_out: Some(LedgerLeftOut {
                directory,
                streams,
                bytes,
            }),
            ..wof_row(record, PlainKind::CloudLeftOut)
        };
        let drops = DeclaredDrops::from_ledger(&ledger_of(vec![
            left(50, false, 2, 1000),
            left(51, true, 0, 0),
            wof_row(40, PlainKind::WofExpanded),
        ]))
        .unwrap();
        assert!(drops.is_left_out(50, 1) && drops.is_left_out(51, 1));
        assert!(!drops.is_left_out(50, 2) && !drops.is_left_out(40, 1));
        let totals = drops.left_out_totals();
        assert_eq!(
            (
                totals.files,
                totals.directories,
                totals.streams,
                totals.bytes
            ),
            (1, 1, 2, 1000)
        );
        // The admission from the new tree: the objects and their streams
        // added back, and the WOF stream drop.
        assert_eq!(drops.admitted_from_new(10, 4, 20), Ok((11, 5, 23)));
        assert_eq!(drops.expected_streams(23), Ok(20));
        assert_eq!(drops.expected_directories(5), Ok(4));
        assert_eq!(drops.expected_objects(16), Ok(14));
        assert_eq!(drops.expected_bytes(5000), Ok(4000));
        assert!(drops.expected_objects(1).is_err());
        // Each declared object has to be the one the build passed over.
        let met: std::collections::BTreeSet<_> = [(50, 1), (51, 1)].into();
        assert!(drops.require_left_out(&met).is_ok());
        assert!(drops.require_left_out(&[(50, 1)].into()).is_err());
        assert!(
            drops
                .require_left_out(&[(50, 1), (51, 1), (52, 1)].into())
                .is_err()
        );
        // A left-out row must say what it took; no other kind may.
        assert!(
            DeclaredDrops::from_ledger(&ledger_of(vec![wof_row(60, PlainKind::CloudLeftOut)]))
                .is_err()
        );
        assert!(
            DeclaredDrops::from_ledger(&ledger_of(vec![LedgerRow {
                kind: PlainKind::CloudPlaceholderPlain,
                ..left(61, false, 1, 1)
            }]))
            .is_err()
        );
    }

    #[test]
    fn totals_are_counted_by_kind() {
        let list = PlainList::new(vec![
            entry("\\a", PlainKind::AttributesCleared, TEMPORARY),
            entry("\\b", PlainKind::AttributesCleared, OFFLINE),
        ])
        .unwrap();
        let totals = list.totals();
        assert_eq!(totals.len(), 1);
        assert_eq!(totals[&PlainKind::AttributesCleared].objects, 2);
        assert_eq!(totals[&PlainKind::AttributesCleared].bytes, 6000);
    }

    #[test]
    fn a_ledger_names_each_object_once() {
        let row = |paths: &[&str]| LedgerRow {
            kind: PlainKind::AttributesCleared,
            paths: paths.iter().map(|p| (*p).to_owned()).collect(),
            record_number: 40,
            sequence_number: 1,
            before: LedgerState {
                attributes: 0x120,
                reparse_tag: None,
            },
            after: LedgerState {
                attributes: 0x20,
                reparse_tag: None,
            },
            witness: "raw".into(),
            plain_copy: None,
            efs: None,
            cloud: None,
            left_out: None,
        };
        let mut ledger = PlainLedger {
            kind: LEDGER_KIND.into(),
            agreed_list_sha256: String::new(),
            frozen_list_sha256: String::new(),
            source_inspection_sha256: String::new(),
            rows: vec![row(&["\\a", "\\a2"])],
        };
        assert!(ledger.validate().is_ok());
        assert_eq!(ledger.counts()[&PlainKind::AttributesCleared], 1);
        ledger.rows.push(row(&["\\a2"]));
        assert!(ledger.validate().is_err());
        ledger.rows = vec![row(&[])];
        assert!(ledger.validate().is_err());
        ledger.rows.clear();
        ledger.kind = "other".into();
        assert!(ledger.validate().is_err());
        let text = serde_json::to_string(&PlainLedger {
            kind: LEDGER_KIND.into(),
            agreed_list_sha256: "a".into(),
            frozen_list_sha256: "b".into(),
            source_inspection_sha256: "c".into(),
            rows: vec![row(&["\\a"])],
        })
        .unwrap();
        assert!(text.contains("\"kind\":\"attributes_cleared\""), "{text}");
        let back: PlainLedger = serde_json::from_str(&text).unwrap();
        assert_eq!(back.rows.len(), 1);
    }
}
