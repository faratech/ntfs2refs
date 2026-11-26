//! A plain listing of a mounted volume, and a comparison of two listings.
//!
//! Used to compare an NTFS source before conversion with the same volume once
//! it mounts as ReFS. It deliberately shares nothing with the converter's own
//! verification: directories are enumerated through Windows, every stream is
//! read through whichever file system is mounted, and security is the SDDL
//! text Windows itself produces. Capturing is read only.

use crate::plain_ledger::{
    CLEARABLE_ATTRIBUTES, CLOUD_ATTRIBUTES, ENCRYPTED, LedgerRow, OFFLINE, PlainKind, PlainLedger,
    REPARSE_POINT, SPARSE_FILE,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const SYMLINK_TAG: u32 = 0xa000_000c;
const SYSTEM_VOLUME_INFORMATION: &str = "\\System Volume Information";

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Stream {
    pub name: String,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Path below the volume root, starting with a backslash. The root is "\".
    pub path: String,
    pub directory: bool,
    pub attributes: u32,
    pub created: i64,
    pub written: i64,
    pub changed: i64,
    pub bytes: u64,
    /// The 8.3 name NTFS stores for this entry, if it has one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_name: Option<String>,
    /// SHA-256 of the unnamed data stream. Absent for directories.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Named data streams, sorted by name.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub streams: Vec<Stream>,
    /// Owner, group, DACL and SACL as SDDL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse_tag: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reparse_sha256: Option<String>,
    /// For a relative symbolic link, the name it points at.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relative_link_target: Option<String>,
    /// SHA-256 over the extended attributes other than kernel caches, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<String>,
    /// `$Kernel.Purge.*` attributes (caches the kernel discards whenever a
    /// file changes) and `$Kernel.CFDoNotConvert` (the mark the
    /// configuration manager puts on a hive it loads). Counted, not hashed.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub kernel_cache_attributes: u32,
    /// A directory Windows reports as marked case-sensitive
    /// (FILE_CASE_SENSITIVE_INFO, as `fsutil file queryCaseSensitiveInfo`
    /// shows it). Asked of every directory; a failed query is in `errors`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub case_sensitive: bool,
    /// The object is EFS-encrypted (FILE_ATTRIBUTE_ENCRYPTED, as Windows
    /// reports it). `sha256` is then the plain text the reading account
    /// sees, and `raw_efs_sha256` what is on the disk.
    #[serde(default, skip_serializing_if = "is_false")]
    pub efs: bool,
    /// SHA-256 of an encrypted file's raw EFS export (ReadEncryptedFileRaw):
    /// its ciphertext and EFS metadata, which no key is needed to read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw_efs_sha256: Option<String>,
    /// For a file WOF keeps compressed (compact /exe, CompactOS), WOF's
    /// algorithm as FSCTL_GET_EXTERNAL_BACKING reports it (WOF hides its
    /// reparse point from every other query); [`WOF_WIM_BACKED`] for a file
    /// backed by a WIM image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wof_algorithm: Option<u32>,
    /// For a placeholder (cloud files, ProjFS, Data Deduplication, single
    /// instance storage): SHA-256 of the unnamed stream read as a program
    /// reads it, through the filter that owns the reparse point and with
    /// nothing recalled (FILE_FLAG_OPEN_NO_RECALL). `sha256` is read with
    /// the reparse point opened, as for every other file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_sha256: Option<String>,
    /// Why `plain_sha256` could not be read (a placeholder whose data is
    /// not on the volume). Not an error of the listing: such an object is
    /// refused, or left out with the user's agreement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plain_read_error: Option<String>,
    pub links: u32,
    /// Identifies the file behind several hard links. Only meaningful within
    /// one listing; never compared across listings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_group: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

/// [`Record::wof_algorithm`] of a file backed by a WIM image rather than
/// compressed in place.
pub const WOF_WIM_BACKED: u32 = 0x100;

/// Whether `tag` is that of a placeholder whose contents a program reads
/// through the filter that owns it, and the listing reads as
/// [`Record::plain_sha256`].
pub fn is_placeholder_tag(tag: u32) -> bool {
    is_cloud_tag(tag) || matches!(tag, PROJFS_TAG | DEDUP_TAG | SIS_TAG)
}
/// IO_REPARSE_TAG_CLOUD and its sixteen variants.
pub fn is_cloud_tag(tag: u32) -> bool {
    tag & 0xffff_0fff == 0x9000_001a
}
pub const PROJFS_TAG: u32 = 0x9000_001c;
pub const DEDUP_TAG: u32 = 0x8000_0013;
pub const SIS_TAG: u32 = 0x8000_0007;

fn is_zero(value: &u32) -> bool {
    *value == 0
}
fn is_false(value: &bool) -> bool {
    !*value
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Difference {
    pub path: String,
    /// One of a fixed set of labels, so differences can be counted by kind
    /// whatever names and values `what` goes on to quote.
    #[serde(default)]
    pub kind: String,
    pub what: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Comparison {
    pub before_objects: usize,
    pub after_objects: usize,
    /// 8.3 names that became same-directory links, as intended.
    pub short_names_as_links: usize,
    /// 8.3 names that are gone because the run was asked to leave them
    /// behind (`compare_without_short_names`): never counted otherwise.
    #[serde(default, skip_serializing_if = "none_dropped")]
    pub short_names_dropped: usize,
    /// Directories whose case-sensitive mark is gone because the run said
    /// it does not set the mark on the new volume
    /// (`Declared::case_marks_not_carried`): never counted otherwise.
    #[serde(default, skip_serializing_if = "none_dropped")]
    pub case_marks_not_carried: usize,
    /// Expected differences, counted by kind.
    pub allowed: BTreeMap<String, usize>,
    pub difference_count: usize,
    /// Every difference, counted by its fixed kind.
    pub difference_kinds: BTreeMap<String, usize>,
    /// The first differences, in path order.
    pub differences: Vec<Difference>,
}
impl Comparison {
    pub fn identical(&self) -> bool {
        self.difference_count == 0
    }
}

const DIFFERENCE_LIMIT: usize = 500;
/// Every difference the comparison accepts, by the name it is counted
/// under in `Comparison::allowed`. Anything else is reported. Short names that
/// became same-directory links are counted apart, in `short_names_as_links`.
pub const ALLOWED_DIFFERENCES: &[&str] = &[
    ALLOWED_SYSTEM_VOLUME_INFORMATION,
    ALLOWED_COMPRESSION_FLAG,
    ALLOWED_EMPTY_SYSTEM_ACL,
    ALLOWED_KERNEL_CACHE,
];
const ALLOWED_SYSTEM_VOLUME_INFORMATION: &str = "System Volume Information content";
const ALLOWED_COMPRESSION_FLAG: &str = "NTFS compression flag removed";
const ALLOWED_EMPTY_SYSTEM_ACL: &str = "empty system ACL versus none";
const ALLOWED_KERNEL_CACHE: &str = "kernel cache attributes dropped";
// ReFS reports these on its own files; NTFS never does.
const REFS_ONLY_ATTRIBUTES: u32 = 0x8000 | 0x2_0000;
// NTFS compression is decoded during conversion; ReFS stores the plain data.
const COMPRESSED: u32 = 0x800;
// A file with no attributes is reported as NORMAL.
const NORMAL: u32 = 0x80;

fn parent_and_leaf(path: &str) -> (&str, &str) {
    match path.rfind('\\') {
        Some(0) => ("\\", &path[1..]),
        Some(at) => (&path[..at], &path[at + 1..]),
        None => ("\\", path),
    }
}
fn join(parent: &str, leaf: &str) -> String {
    if parent == "\\" {
        format!("\\{leaf}")
    } else {
        format!("{parent}\\{leaf}")
    }
}
fn inside_system_volume_information(path: &str) -> bool {
    // Compared as bytes. A path is arbitrary UTF-8, so the prefix length need
    // not fall on one of its character boundaries, and slicing the string
    // there would panic.
    let (bytes, prefix) = (path.as_bytes(), SYSTEM_VOLUME_INFORMATION.as_bytes());
    bytes.len() > prefix.len()
        && bytes[..prefix.len()].eq_ignore_ascii_case(prefix)
        && bytes[prefix.len()] == b'\\'
}
fn attributes_for_comparison(attributes: u32) -> u32 {
    attributes & !REFS_ONLY_ATTRIBUTES & !NORMAL
}
/// SDDL with an empty system ACL removed: "no SACL" and "an empty SACL" audit
/// nothing, and ReFS cannot always store the first form.
fn security_for_comparison(sddl: &str) -> (&str, bool) {
    for empty in ["S:NO_ACCESS_CONTROL", "S:"] {
        if let Some(rest) = sddl.strip_suffix(empty) {
            return (rest, true);
        }
    }
    (sddl, false)
}

fn none_dropped(count: &usize) -> bool {
    *count == 0
}

/// What a run said it leaves behind. Each is counted by the comparison made
/// for such a run instead of being a difference; without it, the same thing
/// missing is a difference. Nothing here lets anything else through.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Declared {
    /// The run was asked to leave 8.3 short names behind
    /// (`--short-names drop`).
    pub short_names_dropped: bool,
    /// The run said that it does not set the directories' case-sensitive
    /// marks on the new volume, which it does on every Windows but those of
    /// `windows_build::CASE_MARK_BUILDS`. A directory that gained the mark
    /// is a difference all the same.
    pub case_marks_not_carried: bool,
}

/// Compares the listing taken before conversion with the one taken after.
pub fn compare(before: &[Record], after: &[Record]) -> Comparison {
    compare_declared(before, after, Declared::default())
}

/// The same comparison for a run that was asked to leave 8.3 short names
/// behind (`--short-names drop`): a short name that is simply gone is
/// counted in `short_names_dropped` instead of being a difference. Nothing
/// else is allowed that `compare` does not allow, and a listing after the
/// run that still shows a short name is a difference.
pub fn compare_without_short_names(before: &[Record], after: &[Record]) -> Comparison {
    compare_declared(
        before,
        after,
        Declared {
            short_names_dropped: true,
            ..Declared::default()
        },
    )
}

/// The comparison for a run that declared what it leaves behind.
pub fn compare_declared(before: &[Record], after: &[Record], declared: Declared) -> Comparison {
    let dropped = declared.short_names_dropped;
    let mut result = Comparison {
        before_objects: before.len(),
        after_objects: after.len(),
        ..Comparison::default()
    };
    let mut differences: Vec<Difference> = Vec::new();
    let allow = |kind: &str, allowed: &mut BTreeMap<String, usize>| {
        *allowed.entry(kind.to_owned()).or_default() += 1;
    };
    let after_by_path: BTreeMap<&str, &Record> = after
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect();
    let before_paths: BTreeSet<&str> = before.iter().map(|record| record.path.as_str()).collect();
    let mut explained_after: BTreeSet<String> = BTreeSet::new();

    for record in before {
        let mut differ = |kind: &str, what: String| {
            differences.push(Difference {
                path: record.path.clone(),
                kind: kind.to_owned(),
                what,
            })
        };
        for error in &record.errors {
            differ(
                "unreadable before conversion",
                format!("could not be read before conversion: {error}"),
            );
        }
        // An 8.3 name must survive as a same-directory link to the long name.
        // The converter links every separately stored short name whose text
        // is not exactly the long name, so the same test decides it here.
        if let Some(short) = &record.short_name {
            let (parent, leaf) = parent_and_leaf(&record.path);
            if short != leaf {
                let alias = join(parent, short);
                match after_by_path.get(alias.as_str()) {
                    Some(link)
                        if link.reparse_tag == Some(SYMLINK_TAG)
                            && link.relative_link_target.as_deref() == Some(leaf)
                            && link.directory == record.directory =>
                    {
                        result.short_names_as_links += 1;
                        explained_after.insert(alias);
                    }
                    Some(_) if before_paths.contains(alias.as_str()) => {
                        // A real object of that name exists; it is compared on its own.
                    }
                    Some(_) => differ(
                        "short name is not a link to its long name",
                        format!("short name {short} exists but is not a link to {leaf}"),
                    ),
                    None if dropped => result.short_names_dropped += 1,
                    None => differ("short name lost", format!("short name {short} was lost")),
                }
            }
        }
        let Some(now) = after_by_path.get(record.path.as_str()) else {
            if inside_system_volume_information(&record.path) {
                allow(ALLOWED_SYSTEM_VOLUME_INFORMATION, &mut result.allowed);
            } else {
                differ(
                    "missing after conversion",
                    "missing after conversion".to_owned(),
                );
            }
            continue;
        };
        if inside_system_volume_information(&record.path) {
            allow(ALLOWED_SYSTEM_VOLUME_INFORMATION, &mut result.allowed);
            continue;
        }
        for error in &now.errors {
            differ(
                "unreadable after conversion",
                format!("could not be read after conversion: {error}"),
            );
        }
        if now.directory != record.directory {
            differ(
                "file/directory kind changed",
                "file/directory kind changed".to_owned(),
            );
            continue;
        }
        let (was, is) = (
            attributes_for_comparison(record.attributes),
            attributes_for_comparison(now.attributes),
        );
        if was != is {
            if was & !COMPRESSED == is {
                allow(ALLOWED_COMPRESSION_FLAG, &mut result.allowed);
            } else {
                differ(
                    "attributes changed",
                    format!(
                        "attributes {:#x} became {:#x}",
                        record.attributes, now.attributes
                    ),
                );
            }
        }
        for (name, was, is) in [
            ("creation time", record.created, now.created),
            ("last write time", record.written, now.written),
            ("change time", record.changed, now.changed),
        ] {
            if was != is {
                differ(
                    &format!("{name} changed"),
                    format!("{name} {was} became {is}"),
                );
            }
        }
        if !record.directory && record.bytes != now.bytes {
            differ(
                "size changed",
                format!("size {} became {}", record.bytes, now.bytes),
            );
        }
        if record.sha256 != now.sha256 {
            differ("content differs", "content differs".to_owned());
        }
        if record.streams != now.streams {
            differ("named streams differ", "named streams differ".to_owned());
        }
        match (&record.security, &now.security) {
            (Some(was), Some(is)) if was == is => (),
            (Some(was), Some(is)) => {
                let (was_base, _) = security_for_comparison(was);
                let (is_base, _) = security_for_comparison(is);
                if was_base == is_base {
                    allow(ALLOWED_EMPTY_SYSTEM_ACL, &mut result.allowed);
                } else {
                    differ("security changed", format!("security {was} became {is}"));
                }
            }
            (None, None) => (),
            _ => differ(
                "security unreadable on one side",
                "security could not be read on one side".to_owned(),
            ),
        }
        if record.reparse_tag != now.reparse_tag || record.reparse_sha256 != now.reparse_sha256 {
            differ("reparse point differs", "reparse point differs".to_owned());
        }
        if record.extended_attributes != now.extended_attributes {
            differ(
                "extended attributes differ",
                "extended attributes differ".to_owned(),
            );
        }
        if let Some(what) = feature_view_differs(record, now) {
            differ("feature view differs", what);
        }
        match (record.case_sensitive, now.case_sensitive) {
            (true, false) if declared.case_marks_not_carried => result.case_marks_not_carried += 1,
            (true, false) => differ(
                "case-sensitive mark lost",
                "the directory was marked case-sensitive and is not any more".to_owned(),
            ),
            (false, true) => differ(
                "case-sensitive mark appeared",
                "the directory was not marked case-sensitive and now is".to_owned(),
            ),
            _ => (),
        }
        if now.kernel_cache_attributes > record.kernel_cache_attributes {
            differ(
                "kernel cache attributes appeared",
                "kernel cache attributes appeared".to_owned(),
            );
        } else if now.kernel_cache_attributes < record.kernel_cache_attributes {
            allow(ALLOWED_KERNEL_CACHE, &mut result.allowed);
        }
        if record.links != now.links {
            differ(
                "hard-link count changed",
                format!("hard-link count {} became {}", record.links, now.links),
            );
        }
    }

    // The same names must share one file before and after.
    let groups = |records: &[Record]| -> BTreeSet<BTreeSet<String>> {
        let mut by_group: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for record in records {
            if let Some(group) = &record.link_group {
                if !inside_system_volume_information(&record.path) {
                    by_group
                        .entry(group)
                        .or_default()
                        .insert(record.path.clone());
                }
            }
        }
        by_group
            .into_values()
            .filter(|names| names.len() > 1)
            .collect()
    };
    let (before_groups, after_groups) = (groups(before), groups(after));
    for names in before_groups.difference(&after_groups) {
        differences.push(Difference {
            path: names.iter().next().cloned().unwrap_or_default(),
            kind: "hard-link set not preserved".to_owned(),
            what: format!("hard-link set of {} names is not preserved", names.len()),
        });
    }

    for record in after {
        if before_paths.contains(record.path.as_str()) || explained_after.contains(&record.path) {
            continue;
        }
        if inside_system_volume_information(&record.path) {
            allow(ALLOWED_SYSTEM_VOLUME_INFORMATION, &mut result.allowed);
        } else {
            differences.push(Difference {
                path: record.path.clone(),
                kind: "appeared after conversion".to_owned(),
                what: "appeared after conversion".to_owned(),
            });
        }
    }

    differences.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.what.cmp(&b.what)));
    result.difference_count = differences.len();
    for difference in &differences {
        *result
            .difference_kinds
            .entry(difference.kind.clone())
            .or_default() += 1;
    }
    differences.truncate(DIFFERENCE_LIMIT);
    result.differences = differences;
    result
}

/// What the listing records of a feature ReFS does not have (EFS, WOF, a
/// placeholder's plain view), compared as every other field is: equal, or
/// a difference. Only the content verdict of a plain conversion
/// ([`compare_with_plain`]) expects one to change, and only for an object
/// the run's ledger names.
fn feature_view_differs(was: &Record, is: &Record) -> Option<String> {
    if was.efs != is.efs || was.raw_efs_sha256 != is.raw_efs_sha256 {
        return Some(format!("EFS encryption {} became {}", was.efs, is.efs));
    }
    if was.wof_algorithm != is.wof_algorithm {
        return Some(format!(
            "WOF compression {:?} became {:?}",
            was.wof_algorithm, is.wof_algorithm
        ));
    }
    if was.plain_sha256 != is.plain_sha256 || was.plain_read_error != is.plain_read_error {
        return Some("the contents a program reads through the placeholder differ".to_owned());
    }
    None
}

/// Compares two listings of a volume that must not have changed at all: the
/// NTFS source before and after a diagnose run, or before a conversion and
/// after its rollback. Every recorded field of every object must be equal,
/// short names included, and nothing is accepted as an expected difference.
pub fn compare_exact(before: &[Record], after: &[Record]) -> Comparison {
    let mut result = Comparison {
        before_objects: before.len(),
        after_objects: after.len(),
        ..Comparison::default()
    };
    let mut differences: Vec<Difference> = Vec::new();
    let after_by_path: BTreeMap<&str, &Record> = after
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect();
    let before_paths: BTreeSet<&str> = before.iter().map(|record| record.path.as_str()).collect();

    for record in before {
        let mut differ = |kind: &str, what: String| {
            differences.push(Difference {
                path: record.path.clone(),
                kind: kind.to_owned(),
                what,
            })
        };
        for error in &record.errors {
            differ(
                "unreadable before",
                format!("could not be read before: {error}"),
            );
        }
        let Some(now) = after_by_path.get(record.path.as_str()) else {
            differ("missing afterwards", "missing afterwards".to_owned());
            continue;
        };
        for error in &now.errors {
            differ(
                "unreadable afterwards",
                format!("could not be read afterwards: {error}"),
            );
        }
        if now.directory != record.directory {
            differ(
                "file/directory kind changed",
                "file/directory kind changed".to_owned(),
            );
            continue;
        }
        if record.attributes != now.attributes {
            differ(
                "attributes changed",
                format!(
                    "attributes {:#x} became {:#x}",
                    record.attributes, now.attributes
                ),
            );
        }
        for (name, was, is) in [
            ("creation time", record.created, now.created),
            ("last write time", record.written, now.written),
            ("change time", record.changed, now.changed),
        ] {
            if was != is {
                differ(
                    &format!("{name} changed"),
                    format!("{name} {was} became {is}"),
                );
            }
        }
        if record.bytes != now.bytes {
            differ(
                "size changed",
                format!("size {} became {}", record.bytes, now.bytes),
            );
        }
        if record.short_name != now.short_name {
            differ(
                "short name changed",
                format!(
                    "short name {:?} became {:?}",
                    record.short_name, now.short_name
                ),
            );
        }
        if record.sha256 != now.sha256 {
            differ("content differs", "content differs".to_owned());
        }
        if record.streams != now.streams {
            differ("named streams differ", "named streams differ".to_owned());
        }
        if record.security != now.security {
            differ(
                "security changed",
                format!("security {:?} became {:?}", record.security, now.security),
            );
        }
        if record.reparse_tag != now.reparse_tag
            || record.reparse_sha256 != now.reparse_sha256
            || record.relative_link_target != now.relative_link_target
        {
            differ("reparse point differs", "reparse point differs".to_owned());
        }
        if record.extended_attributes != now.extended_attributes {
            differ(
                "extended attributes differ",
                "extended attributes differ".to_owned(),
            );
        }
        if let Some(what) = feature_view_differs(record, now) {
            differ("feature view differs", what);
        }
        if record.case_sensitive != now.case_sensitive {
            differ(
                "case-sensitive mark changed",
                format!(
                    "case-sensitive mark {} became {}",
                    record.case_sensitive, now.case_sensitive
                ),
            );
        }
        if record.kernel_cache_attributes != now.kernel_cache_attributes {
            differ(
                "kernel cache attributes changed",
                format!(
                    "kernel cache attributes {} became {}",
                    record.kernel_cache_attributes, now.kernel_cache_attributes
                ),
            );
        }
        if record.links != now.links {
            differ(
                "hard-link count changed",
                format!("hard-link count {} became {}", record.links, now.links),
            );
        }
    }

    // The same names must share one file before and afterwards. A group's
    // identifier means something only within its own listing.
    let groups = |records: &[Record]| -> BTreeSet<BTreeSet<String>> {
        let mut by_group: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for record in records {
            if let Some(group) = &record.link_group {
                by_group
                    .entry(group)
                    .or_default()
                    .insert(record.path.clone());
            }
        }
        by_group
            .into_values()
            .filter(|names| names.len() > 1)
            .collect()
    };
    let (before_groups, after_groups) = (groups(before), groups(after));
    for names in before_groups.symmetric_difference(&after_groups) {
        differences.push(Difference {
            path: names.iter().next().cloned().unwrap_or_default(),
            kind: "hard-link set changed".to_owned(),
            what: format!("hard-link set of {} names is not the same", names.len()),
        });
    }

    for record in after {
        if !before_paths.contains(record.path.as_str()) {
            differences.push(Difference {
                path: record.path.clone(),
                kind: "appeared afterwards".to_owned(),
                what: "appeared afterwards".to_owned(),
            });
        }
    }

    differences.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.what.cmp(&b.what)));
    result.difference_count = differences.len();
    for difference in &differences {
        *result
            .difference_kinds
            .entry(difference.kind.clone())
            .or_default() += 1;
    }
    differences.truncate(DIFFERENCE_LIMIT);
    result.differences = differences;
    result
}

/// What the content verdict found for the objects a run converted to plain
/// files (`plain_ledger`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlainVerdict {
    /// Ledger rows of which every name passed, by kind.
    pub conversions: BTreeMap<String, usize>,
    pub failure_count: usize,
    /// Every failure, counted by its fixed kind.
    pub failure_kinds: BTreeMap<String, usize>,
    /// The first failures, in path order.
    pub failures: Vec<Difference>,
}

/// The verdict on a run that converted objects to plain files: the listing
/// comparison and the content verdict, reported apart.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Verdict {
    /// [`compare_declared`] of every object the ledger does not name,
    /// exactly as for a run without plain conversions.
    pub listing: Comparison,
    pub plain: PlainVerdict,
}

impl Verdict {
    /// Both: no difference in the listing, and no failed plain conversion.
    pub fn identical(&self) -> bool {
        self.listing.identical() && self.plain.failure_count == 0
    }
}

/// The record an object should have after the conversion its ledger row
/// declares: `before` with the declared feature taken off and nothing else.
/// An error when `before` does not show that feature, or when the row
/// declares more than its kind may take off.
fn declared_after(row: &LedgerRow, before: &Record) -> Result<Record, String> {
    let mut after = before.clone();
    // A placeholder of any kind becomes the bytes a program read through it.
    // (Not converted by this build: see `PlainKind::implemented`.)
    let placeholder = |after: &mut Record, shown: bool, what: &str| -> Result<(), String> {
        if !shown {
            return Err(format!(
                "the listing before shows no {what} (reparse tag {:?})",
                before.reparse_tag
            ));
        }
        let Some(plain) = before.plain_sha256.clone() else {
            return Err(format!(
                "the listing before could not read the {what} as a program does: {}",
                before.plain_read_error.as_deref().unwrap_or("not read")
            ));
        };
        after.sha256 = Some(plain);
        after.plain_sha256 = None;
        after.plain_read_error = None;
        after.reparse_tag = None;
        after.reparse_sha256 = None;
        after.relative_link_target = None;
        after.attributes &= !(REPARSE_POINT | CLOUD_ATTRIBUTES | OFFLINE | SPARSE_FILE);
        Ok(())
    };
    let tag = before.reparse_tag.unwrap_or(0);
    match row.kind {
        PlainKind::AttributesCleared => {
            let cleared = row.before.attributes & !row.after.attributes;
            if cleared == 0
                || cleared & !CLEARABLE_ATTRIBUTES != 0
                || row.after.attributes & !row.before.attributes != 0
            {
                return Err(format!(
                    "the ledger declares attributes {:#x} becoming {:#x}, which is not TEMPORARY or OFFLINE taken off and nothing else",
                    row.before.attributes, row.after.attributes
                ));
            }
            if before.attributes & cleared != cleared {
                return Err(format!(
                    "the listing before shows attributes {:#x}, without the {cleared:#x} the ledger declares taken off",
                    before.attributes
                ));
            }
            if before.reparse_tag.is_some() || before.attributes & REPARSE_POINT != 0 {
                return Err(
                    "it has a reparse point, which clearing attributes does not cover".into(),
                );
            }
            after.attributes &= !cleared;
        }
        PlainKind::EfsDecrypted => {
            if !before.efs || before.attributes & ENCRYPTED == 0 || before.raw_efs_sha256.is_none()
            {
                return Err(
                    "the listing before does not show it EFS-encrypted, with its raw export read"
                        .into(),
                );
            }
            after.efs = false;
            after.raw_efs_sha256 = None;
            after.attributes &= !ENCRYPTED;
        }
        PlainKind::WofExpanded => {
            if before.wof_algorithm.is_none() {
                return Err("the listing before does not show it WOF-compressed".into());
            }
            after.wof_algorithm = None;
        }
        PlainKind::DedupRehydrated => {
            placeholder(&mut after, tag == DEDUP_TAG, "deduplicated file")?
        }
        PlainKind::SisExpanded => placeholder(&mut after, tag == SIS_TAG, "single-instance link")?,
        PlainKind::CloudPlaceholderPlain => {
            placeholder(&mut after, is_cloud_tag(tag), "cloud placeholder")?
        }
        PlainKind::ProjfsPlaceholderPlain => {
            placeholder(&mut after, tag == PROJFS_TAG, "ProjFS placeholder")?
        }
        PlainKind::CloudLeftOut => {
            return Err("an object left out has no record afterwards".into());
        }
    }
    Ok(after)
}

/// The verdict on a run whose ledger says which objects it converted to
/// plain files.
///
/// Why this is as strict as the listing comparison, and no wider:
///
/// - Every object the ledger does not name is compared by
///   [`compare_declared`] itself, unchanged, and its result is reported as
///   `listing`. Nothing about those objects is accepted that a run without
///   plain conversions would not accept, and the comparison gains no
///   per-object exception.
/// - An object leaves that comparison only by being named in the ledger,
///   which the run wrote from the frozen source and which the list the user
///   agreed to bounds. Each such object is then held by the very same
///   [`compare_declared`] to its record before with exactly the feature its
///   row declares taken off (`declared_after`). Its contents (every
///   stream), times, security, names, links, extended attributes and every
///   other attribute must be equal, as in the listing.
/// - A row whose object the listing before does not show with the declared
///   feature is a failure, so the ledger cannot excuse a difference the
///   feature does not explain. So is a name in the ledger that the listing
///   before does not have, a hard-link set split between the ledger and the
///   rest, and an object left out (`cloud_left_out`) that is on the volume
///   afterwards.
/// - The two results are reported apart (`differences`, and
///   `plain_conversions` with `plain_failures`), and [`Verdict::identical`]
///   needs both clean.
pub fn compare_with_plain(
    before: &[Record],
    after: &[Record],
    declared: Declared,
    ledger: &PlainLedger,
) -> Verdict {
    let mut failures: Vec<Difference> = Vec::new();
    let mut fail = |path: &str, kind: &str, what: String| {
        failures.push(Difference {
            path: path.to_owned(),
            kind: kind.to_owned(),
            what,
        })
    };
    if let Err(why) = ledger.validate() {
        fail("\\", "ledger not valid", why);
    }
    let before_by_path: BTreeMap<&str, &Record> = before
        .iter()
        .map(|record| (record.path.as_str(), record))
        .collect();
    let after_paths: BTreeSet<&str> = after.iter().map(|record| record.path.as_str()).collect();
    // The names the ledger takes out of the listing comparison, and the
    // short-name links of those names, which belong with them.
    let mut taken: BTreeSet<&str> = BTreeSet::new();
    for row in &ledger.rows {
        taken.extend(row.paths.iter().map(String::as_str));
    }
    let mut links: BTreeSet<String> = BTreeSet::new();
    for path in &taken {
        if let Some(short) = before_by_path
            .get(path)
            .and_then(|record| record.short_name.as_ref())
        {
            let (parent, leaf) = parent_and_leaf(path);
            let alias = join(parent, short);
            if short != leaf && !before_by_path.contains_key(alias.as_str()) {
                links.insert(alias);
            }
        }
    }
    let rest_before: Vec<Record> = before
        .iter()
        .filter(|record| !taken.contains(record.path.as_str()))
        .cloned()
        .collect();
    let rest_after: Vec<Record> = after
        .iter()
        .filter(|record| !taken.contains(record.path.as_str()) && !links.contains(&record.path))
        .cloned()
        .collect();
    let listing = compare_declared(&rest_before, &rest_after, declared);

    // A hard-link set is either wholly in the ledger or wholly outside it.
    for (side, records) in [("before", before), ("afterwards", after)] {
        let mut groups: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
        for record in records {
            if let Some(group) = &record.link_group {
                let counts = groups.entry(group).or_default();
                counts.0 += 1;
                counts.1 += usize::from(taken.contains(record.path.as_str()));
            }
        }
        for record in records {
            if let Some((all, in_ledger)) = record
                .link_group
                .as_deref()
                .and_then(|group| groups.get(group))
                && in_ledger != all
                && taken.contains(record.path.as_str())
            {
                fail(
                    &record.path,
                    "hard-link set split by the ledger",
                    format!(
                        "{in_ledger} of the {all} names of this file {side} are in the plain-conversions ledger"
                    ),
                );
            }
        }
    }

    // Each row: the feature it declares, shown before; then the records
    // that makes, held to what is there afterwards.
    let mut expected: Vec<Record> = Vec::new();
    let mut compared: BTreeSet<&str> = BTreeSet::new();
    for row in &ledger.rows {
        for path in &row.paths {
            let Some(was) = before_by_path.get(path.as_str()) else {
                fail(
                    path,
                    "ledger names what was not there before",
                    format!(
                        "the ledger names it as {}, and the listing before has no such object",
                        row.kind
                    ),
                );
                continue;
            };
            if row.kind == PlainKind::CloudLeftOut {
                if !was.reparse_tag.is_some_and(is_cloud_tag) {
                    fail(
                        path,
                        "declared feature not shown before",
                        format!(
                            "left out as a cloud placeholder, and the listing before shows reparse tag {:?}",
                            was.reparse_tag
                        ),
                    );
                }
                if after_paths.contains(path.as_str()) {
                    fail(
                        path,
                        "left out, and there afterwards",
                        "the ledger says it was left out, and it is on the volume afterwards"
                            .into(),
                    );
                }
                continue;
            }
            match declared_after(row, was) {
                Ok(record) => {
                    expected.push(record);
                    compared.insert(path.as_str());
                }
                Err(why) => fail(path, "declared feature not shown before", why),
            }
        }
    }
    let plain_after: Vec<Record> = after
        .iter()
        .filter(|record| compared.contains(record.path.as_str()) || links.contains(&record.path))
        .cloned()
        .collect();
    // The listing comparison itself, on what the declared transforms make.
    let held = compare_declared(&expected, &plain_after, declared);

    let mut verdict = PlainVerdict {
        failure_count: failures.len() + held.difference_count,
        ..PlainVerdict::default()
    };
    for failure in &failures {
        *verdict
            .failure_kinds
            .entry(failure.kind.clone())
            .or_default() += 1;
    }
    for (kind, count) in &held.difference_kinds {
        *verdict.failure_kinds.entry(kind.clone()).or_default() += count;
    }
    // Rows are counted as converted only while every failure is known by
    // its path: the held comparison keeps its first differences only.
    let complete = held.differences.len() == held.difference_count;
    failures.extend(held.differences);
    let failing: BTreeSet<&str> = failures.iter().map(|f| f.path.as_str()).collect();
    if complete {
        for row in &ledger.rows {
            if row
                .paths
                .iter()
                .all(|path| !failing.contains(path.as_str()))
            {
                *verdict
                    .conversions
                    .entry(row.kind.name().to_owned())
                    .or_default() += 1;
            }
        }
    }
    failures.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.what.cmp(&b.what)));
    failures.truncate(DIFFERENCE_LIMIT);
    verdict.failures = failures;
    Verdict {
        listing,
        plain: verdict,
    }
}

/// Runs `work` over every item on up to `threads` threads, each with its own
/// `state`, and returns one output per item in no particular order.
///
/// A panic in `work` fails the whole run and names the item. Dropping what a
/// panicked thread had finished would leave a listing that looks complete and
/// later compares as if objects had gone missing or appeared.
#[cfg(any(windows, test))]
fn run_all<T: Send, S, R: Send>(
    items: Vec<T>,
    threads: usize,
    state: impl Fn() -> S + Sync,
    label: impl Fn(&T) -> String + Sync,
    work: impl Fn(&mut S, T) -> R + Sync,
) -> std::io::Result<Vec<R>> {
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let total = items.len();
    let slots: Vec<Mutex<Option<T>>> = items
        .into_iter()
        .map(|item| Mutex::new(Some(item)))
        .collect();
    let cursor = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let finished: Vec<Result<Vec<R>, String>> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..threads.clamp(1, 64).min(total.max(1)))
            .map(|_| {
                scope.spawn(|| {
                    let mut own = state();
                    let mut done = Vec::new();
                    while !stop.load(Ordering::Acquire) {
                        let index = cursor.fetch_add(1, Ordering::Relaxed);
                        let Some(slot) = slots.get(index) else {
                            break;
                        };
                        let item = slot
                            .lock()
                            .unwrap_or_else(|poisoned| poisoned.into_inner())
                            .take();
                        let Some(item) = item else {
                            continue;
                        };
                        let name = label(&item);
                        let observed =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                work(&mut own, item)
                            }));
                        match observed {
                            Ok(output) => done.push(output),
                            Err(payload) => {
                                stop.store(true, Ordering::Release);
                                let message = payload
                                    .downcast_ref::<&str>()
                                    .map(|text| (*text).to_owned())
                                    .or_else(|| payload.downcast_ref::<String>().cloned())
                                    .unwrap_or_else(|| "no message".to_owned());
                                return Err(format!(
                                    "capture worker panicked while observing {name}: {message}"
                                ));
                            }
                        }
                    }
                    Ok(done)
                })
            })
            .collect();
        workers
            .into_iter()
            .map(|worker| {
                worker.join().unwrap_or_else(|_| {
                    Err("capture worker panicked outside an observation".to_owned())
                })
            })
            .collect()
    });
    let mut outputs = Vec::with_capacity(total);
    for result in finished {
        outputs.extend(result.map_err(std::io::Error::other)?);
    }
    if outputs.len() != total {
        return Err(std::io::Error::other(format!(
            "capture observed {} of {total} listed objects",
            outputs.len()
        )));
    }
    Ok(outputs)
}

/// Calls `query` with `buffer`, doubling the buffer while Windows reports that
/// the answer needs more room, up to `limit_bytes`.
#[cfg(any(windows, test))]
fn query_growing(
    buffer: &mut Vec<u64>,
    limit_bytes: usize,
    what: &str,
    mut query: impl FnMut(&mut [u64]) -> std::io::Result<()>,
) -> std::io::Result<()> {
    loop {
        match query(buffer) {
            // ERROR_MORE_DATA, ERROR_BAD_LENGTH: the answer did not fit.
            Err(error) if matches!(error.raw_os_error(), Some(234 | 24)) => {
                let bytes = buffer.len() * 8;
                if bytes >= limit_bytes {
                    return Err(std::io::Error::other(format!(
                        "{what} does not fit in {limit_bytes} bytes: {error}"
                    )));
                }
                buffer.resize((bytes * 2).clamp(8, limit_bytes).div_ceil(8), 0);
            }
            other => return other,
        }
    }
}

#[cfg(windows)]
pub use capture::capture;

#[cfg(windows)]
mod capture {
    use super::{Record, SYMLINK_TAG, Stream};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        io::{self, Read, Seek, SeekFrom},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{
            Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW,
            GetKernelObjectSecurity,
        },
        Storage::FileSystem::{
            CloseEncryptedFileRaw, GetFileInformationByHandleEx, OpenEncryptedFileRawW,
            ReadEncryptedFileRaw,
        },
        System::IO::DeviceIoControl,
    };

    // FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | ACCESS_SYSTEM_SECURITY
    const READ_EVERYTHING: u32 = 0x0102_0089;
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN
    const OPEN_FLAGS: u32 = 0x0a20_0000;
    const REPARSE: u32 = 0x400;
    const DIRECTORY: u32 = 0x10;
    const ENCRYPTED: u32 = 0x4000;
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_SEQUENTIAL_SCAN |
    // FILE_FLAG_OPEN_NO_RECALL: read through the filter that owns a
    // placeholder, as a program does, and never have it recall anything.
    const PLAIN_FLAGS: u32 = 0x0a10_0000;
    const FSCTL_GET_EXTERNAL_BACKING: u32 = 0x0009_0310;

    /// WOF's algorithm for a file it backs: FSCTL_GET_EXTERNAL_BACKING
    /// answers WOF_EXTERNAL_INFO (version, provider) and, for the file
    /// provider, FILE_PROVIDER_EXTERNAL_INFO_V1 (version, algorithm, flags).
    fn wof_algorithm(file: &File) -> io::Result<Option<u32>> {
        let mut answer = [0u32; 16];
        let mut returned = 0u32;
        // SAFETY: a live handle, no input, and aligned output of the stated size.
        let ok = unsafe {
            DeviceIoControl(
                file.as_raw_handle(),
                FSCTL_GET_EXTERNAL_BACKING,
                ptr::null(),
                0,
                answer.as_mut_ptr().cast(),
                std::mem::size_of_val(&answer) as u32,
                &mut returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            let error = io::Error::last_os_error();
            // ERROR_OBJECT_NOT_EXTERNALLY_BACKED, and a file system or a
            // file that WOF does not attach to: not backed.
            return match error.raw_os_error() {
                Some(342 | 1 | 50 | 87) => Ok(None),
                _ => Err(error),
            };
        }
        Ok(Some(match answer[1] {
            // WOF_PROVIDER_FILE
            2 if returned >= 20 => answer[3],
            // WOF_PROVIDER_WIM
            1 => super::WOF_WIM_BACKED,
            provider => {
                return Err(io::Error::other(format!(
                    "WOF provider {provider} answered in {returned} bytes"
                )));
            }
        }))
    }

    /// SHA-256 of an encrypted file's raw EFS export: what is on the disk,
    /// read without its key.
    fn raw_efs_sha256(prefix: &str, path: &str) -> io::Result<String> {
        unsafe extern "system" fn export(
            data: *const u8,
            context: *const std::ffi::c_void,
            length: u32,
        ) -> u32 {
            // SAFETY: the context is the hasher passed below, and Windows
            // hands `length` readable bytes at `data`.
            unsafe {
                let hasher = &mut *(context as *mut Sha256);
                hasher.update(std::slice::from_raw_parts(data, length as usize));
            }
            0
        }
        let name: Vec<u16> = format!("{prefix}{path}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let mut context = ptr::null_mut();
        // SAFETY: a terminated name; flags 0 open the file for export.
        let opened = unsafe { OpenEncryptedFileRawW(name.as_ptr(), 0, &mut context) };
        if opened != 0 {
            return Err(io::Error::from_raw_os_error(opened as i32));
        }
        let mut hasher = Sha256::new();
        // SAFETY: the context Windows just opened, and a hasher that lives
        // across the call.
        let read = unsafe {
            ReadEncryptedFileRaw(Some(export), (&mut hasher as *mut Sha256).cast(), context)
        };
        // SAFETY: closes the context opened above, once.
        unsafe { CloseEncryptedFileRaw(context) };
        if read != 0 {
            return Err(io::Error::from_raw_os_error(read as i32));
        }
        Ok(hex::encode(hasher.finalize()))
    }

    /// SHA-256 of a placeholder's unnamed stream, read as a program reads it.
    fn plain_sha256(prefix: &str, path: &str, buffer: &mut [u8]) -> io::Result<String> {
        let mut file = File::options()
            .access_mode(0x0000_0081)
            .share_mode(7)
            .custom_flags(PLAIN_FLAGS)
            .open(format!("{prefix}{path}"))?;
        hash(&mut file, buffer).map(|(_, sha256)| sha256)
    }

    struct Pending {
        path: String,
        attributes: u32,
        created: i64,
        written: i64,
        changed: i64,
        bytes: u64,
        short_name: Option<String>,
    }

    fn open(prefix: &str, path: &str) -> io::Result<File> {
        File::options()
            .access_mode(READ_EVERYTHING)
            .share_mode(7)
            .custom_flags(OPEN_FLAGS)
            .open(format!("{prefix}{path}"))
    }
    fn information(file: &File, class: i32, buffer: &mut [u64]) -> io::Result<()> {
        // SAFETY: a live handle and aligned, initialized storage of the stated size.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                class,
                buffer.as_mut_ptr().cast(),
                (buffer.len() * 8) as u32,
            )
        };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
    fn bytes_of(buffer: &[u64]) -> &[u8] {
        // SAFETY: reinterpreting initialized u64 storage as bytes.
        unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast(), buffer.len() * 8) }
    }
    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes"))
    }
    fn i64_at(bytes: &[u8], at: usize) -> i64 {
        i64::from_le_bytes(bytes[at..at + 8].try_into().expect("eight bytes"))
    }
    /// The text of little-endian UTF-16 bytes, or their code units when they
    /// are not valid UTF-16. NTFS permits unpaired surrogates in names; a
    /// lossy conversion would record a different name.
    pub(super) fn utf16(bytes: &[u8]) -> Result<String, Vec<u16>> {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).map_err(|_| units)
    }

    /// A name the listing cannot hold exactly. Its object could not be
    /// reopened by the recorded path, and two such names could share one.
    #[derive(Debug)]
    struct InvalidName(String);
    impl std::fmt::Display for InvalidName {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(&self.0)
        }
    }
    impl std::error::Error for InvalidName {}
    fn invalid_name(directory: &str, what: &str, units: &[u16]) -> io::Error {
        io::Error::other(InvalidName(format!(
            "directory {directory} holds a {what} that is not valid UTF-16 and cannot be listed exactly: {units:04x?}"
        )))
    }

    /// One directory's entries, with the short names NTFS keeps beside them.
    fn list(
        prefix: &str,
        path: &str,
        buffer: &mut [u64],
        out: &mut Vec<Pending>,
    ) -> io::Result<()> {
        let directory = open(prefix, path)?;
        loop {
            // FileIdBothDirectoryInfo
            match information(&directory, 10, buffer) {
                Ok(()) => (),
                // ERROR_NO_MORE_FILES
                Err(error) if error.raw_os_error() == Some(18) => return Ok(()),
                Err(error) => return Err(error),
            }
            let bytes = bytes_of(buffer);
            let mut at = 0usize;
            loop {
                let entry = &bytes[at..];
                let next = u32_at(entry, 0) as usize;
                let name_bytes = u32_at(entry, 60) as usize;
                let name = utf16(&entry[104..104 + name_bytes])
                    .map_err(|units| invalid_name(path, "name", &units))?;
                if name != "." && name != ".." {
                    let short_bytes = entry[68] as usize;
                    let short = utf16(&entry[70..70 + short_bytes])
                        .map_err(|units| invalid_name(path, "short name", &units))?;
                    out.push(Pending {
                        path: if path == "\\" {
                            format!("\\{name}")
                        } else {
                            format!("{path}\\{name}")
                        },
                        attributes: u32_at(entry, 56),
                        created: i64_at(entry, 8),
                        written: i64_at(entry, 24),
                        changed: i64_at(entry, 32),
                        bytes: i64_at(entry, 40) as u64,
                        short_name: (!short.is_empty()).then_some(short),
                    });
                }
                if next == 0 {
                    break;
                }
                at += next;
            }
        }
    }

    fn kernel_security(file: &File, requested: u32) -> io::Result<Vec<u64>> {
        let mut descriptor = vec![0u64; 512];
        loop {
            let mut needed = 0u32;
            // SAFETY: a live handle and aligned storage of the stated size.
            let ok = unsafe {
                GetKernelObjectSecurity(
                    file.as_raw_handle(),
                    requested,
                    descriptor.as_mut_ptr().cast(),
                    (descriptor.len() * 8) as u32,
                    &mut needed,
                )
            };
            if ok != 0 {
                return Ok(descriptor);
            }
            let error = io::Error::last_os_error();
            // ERROR_INSUFFICIENT_BUFFER: retry once with the size the system asked for.
            if error.raw_os_error() != Some(122) || needed as usize <= descriptor.len() * 8 {
                return Err(error);
            }
            descriptor = vec![0u64; (needed as usize).div_ceil(8)];
        }
    }

    fn sddl(file: &File) -> io::Result<String> {
        // Owner, group, DACL, SACL, then the label, attribute, scope and
        // process-trust parts of the SACL where the system reports them.
        let mut last = None;
        for requested in [0xffu32, 0x1f, 0x0f] {
            let mut descriptor = match kernel_security(file, requested) {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    last = Some(error);
                    continue;
                }
            };
            let mut text: *mut u16 = ptr::null_mut();
            let mut length = 0u32;
            // SAFETY: a descriptor the system just returned; the output string
            // is released with LocalFree below.
            let ok = unsafe {
                ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor.as_mut_ptr().cast(),
                    1,
                    requested,
                    &mut text,
                    &mut length,
                )
            };
            if ok == 0 || text.is_null() {
                last = Some(io::Error::last_os_error());
                continue;
            }
            // SAFETY: `length` UTF-16 units including the terminator, owned until LocalFree.
            let units = unsafe { std::slice::from_raw_parts(text, length as usize) };
            let end = units
                .iter()
                .position(|unit| *unit == 0)
                .unwrap_or(units.len());
            let value = String::from_utf16(&units[..end]);
            // SAFETY: allocated by the conversion call above.
            unsafe { LocalFree(text.cast()) };
            return value
                .map_err(|_| io::Error::other("security descriptor text is not valid UTF-16"));
        }
        Err(last.unwrap_or_else(|| io::Error::other("security descriptor unavailable")))
    }

    fn hash(file: &mut File, buffer: &mut [u8]) -> io::Result<(u64, String)> {
        file.seek(SeekFrom::Start(0))?;
        let mut hasher = Sha256::new();
        let mut total = 0u64;
        loop {
            let count = file.read(buffer)?;
            if count == 0 {
                return Ok((total, hex::encode(hasher.finalize())));
            }
            hasher.update(&buffer[..count]);
            total += count as u64;
        }
    }

    /// One worker's reusable buffers: the file content being hashed, and the
    /// stream list of the object being observed.
    struct Workspace {
        content: Vec<u8>,
        streams: Vec<u64>,
    }
    impl Workspace {
        fn new() -> Self {
            Self {
                content: vec![0u8; 1024 * 1024],
                streams: vec![0u64; 8192],
            }
        }
    }
    // A stream list larger than this is not one this tool holds in memory.
    const STREAM_LIST_LIMIT: usize = 64 * 1024 * 1024;

    fn named_streams(
        prefix: &str,
        path: &str,
        file: &File,
        buffer: &mut [u8],
        listing: &mut Vec<u64>,
    ) -> io::Result<Vec<Stream>> {
        // FileStreamInfo. Many or long-named streams need more than the
        // starting 64 KiB, so the list grows until the answer fits.
        let listed = super::query_growing(listing, STREAM_LIST_LIMIT, "the stream list", |room| {
            information(file, 7, room)
        });
        match listed {
            Ok(()) => (),
            // ERROR_HANDLE_EOF: no streams at all (a directory without any).
            Err(error) if error.raw_os_error() == Some(38) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        }
        let bytes = bytes_of(listing);
        let mut streams = Vec::new();
        let mut at = 0usize;
        loop {
            let entry = &bytes[at..];
            let next = u32_at(entry, 0) as usize;
            let name_bytes = u32_at(entry, 4) as usize;
            let name = utf16(&entry[24..24 + name_bytes]).map_err(|units| {
                io::Error::other(format!("a stream name is not valid UTF-16: {units:04x?}"))
            })?;
            if name != "::$DATA" {
                let stream_name = name.strip_suffix(":$DATA").unwrap_or(&name);
                let mut stream = File::options()
                    .access_mode(0x0000_0081)
                    .share_mode(7)
                    .custom_flags(OPEN_FLAGS)
                    .open(format!("{prefix}{path}{stream_name}"))?;
                let (bytes, sha256) = hash(&mut stream, buffer)?;
                streams.push(Stream {
                    name,
                    bytes,
                    sha256,
                });
            }
            if next == 0 {
                break;
            }
            at += next;
        }
        streams.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(streams)
    }

    /// The name a relative symbolic link points at.
    fn relative_target(buffer: &[u8]) -> Option<String> {
        if buffer.len() < 20 || u32_at(buffer, 0) != SYMLINK_TAG || u32_at(buffer, 16) & 1 == 0 {
            return None;
        }
        let offset = u16::from_le_bytes([buffer[8], buffer[9]]) as usize;
        let length = u16::from_le_bytes([buffer[10], buffer[11]]) as usize;
        buffer
            .get(20 + offset..20 + offset + length)
            .and_then(|name| utf16(name).ok())
    }

    fn observe(prefix: &str, pending: Pending, workspace: &mut Workspace) -> Record {
        let Workspace {
            content: buffer,
            streams,
        } = workspace;
        let directory = pending.attributes & DIRECTORY != 0;
        let mut record = Record {
            path: pending.path,
            directory,
            attributes: pending.attributes,
            created: pending.created,
            written: pending.written,
            changed: pending.changed,
            bytes: if directory { 0 } else { pending.bytes },
            short_name: pending.short_name,
            links: 1,
            ..Record::default()
        };
        let mut file = match open(prefix, &record.path) {
            Ok(file) => file,
            Err(error) => {
                record.errors.push(format!("open: {error}"));
                return record;
            }
        };
        let note = |record: &mut Record, what: &str, error: &dyn std::fmt::Display| {
            record.errors.push(format!("{what}: {error}"))
        };
        match sddl(&file) {
            Ok(text) => record.security = Some(text),
            Err(error) => note(&mut record, "security", &error),
        }
        // A directory entry carries a copy of these that NTFS refreshes
        // lazily, per name. The values held by the object are the true ones.
        let mut basic = [0u64; 5];
        // FileBasicInfo
        match information(&file, 0, &mut basic) {
            Ok(()) => {
                let basic = bytes_of(&basic);
                record.created = i64_at(basic, 0);
                record.written = i64_at(basic, 16);
                record.changed = i64_at(basic, 24);
                record.attributes = u32_at(basic, 32);
            }
            Err(error) => note(&mut record, "times and attributes", &error),
        }
        let mut standard = [0u64; 3];
        // FileStandardInfo
        match information(&file, 1, &mut standard) {
            Ok(()) => {
                let standard = bytes_of(&standard);
                record.links = u32_at(standard, 16);
                if !directory {
                    record.bytes = i64_at(standard, 8) as u64;
                }
            }
            Err(error) => note(&mut record, "size and link count", &error),
        }
        if record.links > 1 && !directory {
            let mut identity = [0u64; 3];
            // FileIdInfo
            match information(&file, 18, &mut identity) {
                Ok(()) => record.link_group = Some(hex::encode(&bytes_of(&identity)[8..24])),
                Err(error) => note(&mut record, "file identity", &error),
            }
        }
        // Extended attributes are read of an object without a reparse
        // point, as always, and of a placeholder (cloud files, ProjFS, Data
        // Deduplication, single instance storage), which a conversion to
        // plain carries over as a plain file: its record before has to hold
        // them for the content verdict. Other reparse points (links,
        // junctions, WSL files) are listed as they always were.
        let mut read_extended_attributes = record.attributes & REPARSE == 0;
        if record.attributes & REPARSE != 0 {
            match crate::reparse_native::capture(&file) {
                Ok(Some(point)) => {
                    read_extended_attributes = super::is_placeholder_tag(point.tag());
                    record.reparse_tag = Some(point.tag());
                    record.reparse_sha256 = Some(hex::encode(Sha256::digest(&point.buffer)));
                    record.relative_link_target = relative_target(&point.buffer);
                    if !directory && super::is_placeholder_tag(point.tag()) {
                        match plain_sha256(prefix, &record.path, buffer) {
                            Ok(sha256) => record.plain_sha256 = Some(sha256),
                            Err(error) => record.plain_read_error = Some(error.to_string()),
                        }
                    }
                }
                Ok(None) => note(
                    &mut record,
                    "reparse point",
                    &"attribute set but no reparse data",
                ),
                Err(error) => note(&mut record, "reparse point", &error),
            }
        }
        if read_extended_attributes {
            // Asked of the object itself: the size a directory entry reports
            // for extended attributes can be stale.
            match crate::extended_attributes_native::capture(&file) {
                Ok(set) if !set.is_empty() => {
                    let mut hasher = Sha256::new();
                    let mut ordinary = 0usize;
                    for entry in &set.entries {
                        let name = entry.name.to_ascii_uppercase();
                        if name.starts_with(b"$KERNEL.PURGE.") || name == b"$KERNEL.CFDONOTCONVERT"
                        {
                            record.kernel_cache_attributes += 1;
                            continue;
                        }
                        ordinary += 1;
                        hasher.update([entry.flags]);
                        hasher.update((name.len() as u32).to_le_bytes());
                        hasher.update(&name);
                        hasher.update((entry.value.len() as u32).to_le_bytes());
                        hasher.update(&entry.value);
                    }
                    if ordinary != 0 {
                        record.extended_attributes = Some(hex::encode(hasher.finalize()));
                    }
                }
                Ok(_) => (),
                Err(error) => note(&mut record, "extended attributes", &format!("{error:?}")),
            }
        }
        if directory {
            // Asked of every directory, on either file system. Flags other
            // than the one Windows documents are reported, not read as a
            // mark or as none.
            match crate::directory_case::flags(&file) {
                Ok(0) => (),
                Ok(1) => record.case_sensitive = true,
                Ok(flags) => note(
                    &mut record,
                    "case-sensitive mark",
                    &format!("unknown flags {flags:#x}"),
                ),
                Err(error) => note(&mut record, "case-sensitive mark", &error),
            }
        }
        if record.attributes & ENCRYPTED != 0 {
            record.efs = true;
            if !directory {
                match raw_efs_sha256(prefix, &record.path) {
                    Ok(sha256) => record.raw_efs_sha256 = Some(sha256),
                    Err(error) => note(&mut record, "raw EFS export", &error),
                }
            }
        }
        if !directory {
            match wof_algorithm(&file) {
                Ok(algorithm) => record.wof_algorithm = algorithm,
                Err(error) => note(&mut record, "WOF backing", &error),
            }
        }
        match named_streams(prefix, &record.path, &file, buffer, streams) {
            Ok(streams) => record.streams = streams,
            Err(error) => note(&mut record, "named streams", &error),
        }
        if !directory {
            match hash(&mut file, buffer) {
                Ok((_, sha256)) => record.sha256 = Some(sha256),
                Err(error) => note(&mut record, "content", &error),
            }
        }
        record
    }

    /// Lists every object on the volume mounted at `root` (for example `D:\`).
    pub fn capture(root: &Path, threads: usize) -> io::Result<Vec<Record>> {
        let text: Vec<u16> = root.as_os_str().encode_wide().collect();
        let text = String::from_utf16(&text)
            .map_err(|_| io::Error::other("volume root is not Unicode"))?;
        let drive = text.trim_end_matches('\\');
        if drive.len() != 2
            || !drive.as_bytes()[0].is_ascii_alphabetic()
            || drive.as_bytes()[1] != b':'
        {
            return Err(io::Error::other("volume root must be a drive such as D:\\"));
        }
        let prefix = format!("\\\\?\\{drive}");
        let _privileges = crate::attestation_native::Privileges::enable_for(&[
            "SeBackupPrivilege",
            "SeSecurityPrivilege",
        ])?;

        // The root has no directory entry of its own.
        let root_file = open(&prefix, "\\")?;
        let mut basic = [0u64; 5];
        // FileBasicInfo
        information(&root_file, 0, &mut basic)?;
        let basic = bytes_of(&basic);
        drop(root_file);
        let mut pending = vec![Pending {
            path: "\\".to_owned(),
            attributes: u32_at(basic, 32),
            created: i64_at(basic, 0),
            written: i64_at(basic, 16),
            changed: i64_at(basic, 24),
            bytes: 0,
            short_name: None,
        }];
        let mut listing_errors = Vec::new();
        let mut entries = vec![0u64; 32 * 1024];
        let mut next = 0usize;
        while next < pending.len() {
            let entry = &pending[next];
            next += 1;
            // Links and junctions are recorded, never followed.
            if entry.attributes & DIRECTORY == 0 || entry.attributes & REPARSE != 0 {
                continue;
            }
            let path = entry.path.clone();
            if let Err(error) = list(&prefix, &path, &mut entries, &mut pending) {
                // Not an unreadable object to note and carry on from: the
                // listing itself would misname what the volume holds.
                if error
                    .get_ref()
                    .is_some_and(|inner| inner.is::<InvalidName>())
                {
                    return Err(error);
                }
                listing_errors.push((path, error.to_string()));
            }
        }

        let mut records: Vec<Record> = super::run_all(
            pending,
            threads,
            Workspace::new,
            |entry: &Pending| entry.path.clone(),
            |workspace, entry| observe(&prefix, entry, workspace),
        )?;
        for (path, error) in listing_errors {
            if let Some(record) = records.iter_mut().find(|record| record.path == path) {
                record.errors.push(format!("directory listing: {error}"));
            }
        }
        records.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(records)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(path: &str, sha: &str) -> Record {
        Record {
            path: path.to_owned(),
            attributes: 0x20,
            created: 1,
            written: 2,
            changed: 3,
            bytes: 5,
            sha256: Some(sha.to_owned()),
            security: Some("O:SYG:SYD:(A;;FA;;;SY)".to_owned()),
            links: 1,
            ..Record::default()
        }
    }
    fn directory(path: &str) -> Record {
        Record {
            path: path.to_owned(),
            directory: true,
            attributes: 0x10,
            security: Some("O:SYG:SYD:(A;;FA;;;SY)".to_owned()),
            links: 1,
            ..Record::default()
        }
    }

    fn ledger(rows: Vec<LedgerRow>) -> PlainLedger {
        PlainLedger {
            kind: crate::plain_ledger::LEDGER_KIND.to_owned(),
            agreed_list_sha256: "a".repeat(64),
            frozen_list_sha256: "b".repeat(64),
            source_inspection_sha256: "c".repeat(64),
            rows,
        }
    }
    fn cleared_row(paths: &[&str], before: u32, after: u32) -> LedgerRow {
        LedgerRow {
            kind: PlainKind::AttributesCleared,
            paths: paths.iter().map(|path| (*path).to_owned()).collect(),
            record_number: 40,
            sequence_number: 1,
            before: crate::plain_ledger::LedgerState {
                attributes: before,
                reparse_tag: None,
            },
            after: crate::plain_ledger::LedgerState {
                attributes: after,
                reparse_tag: None,
            },
            witness: "test".into(),
            plain_copy: None,
        }
    }
    /// A volume with an ordinary file and a TEMPORARY one, before and after
    /// a run that cleared the attribute.
    fn temporary_volume() -> (Vec<Record>, Vec<Record>) {
        let mut temporary = file("\\t.tmp", "tt");
        temporary.attributes = 0x120;
        let before = vec![directory("\\"), file("\\a.txt", "aa"), temporary.clone()];
        let mut cleared = temporary;
        cleared.attributes = 0x20;
        let after = vec![directory("\\"), file("\\a.txt", "aa"), cleared];
        (before, after)
    }

    #[test]
    fn the_listing_alone_reports_a_cleared_attribute_as_a_difference() {
        // Without a ledger nothing changes: the attribute is a difference.
        let (before, after) = temporary_volume();
        let plain = compare(&before, &after);
        assert_eq!(plain.difference_count, 1, "{plain:?}");
        assert_eq!(plain.differences[0].kind, "attributes changed");
    }

    #[test]
    fn a_plain_conversion_is_verified_apart_and_the_listing_stays_as_strict() {
        let (before, after) = temporary_volume();
        let verdict = compare_with_plain(
            &before,
            &after,
            Declared::default(),
            &ledger(vec![cleared_row(&["\\t.tmp"], 0x120, 0x20)]),
        );
        assert!(verdict.identical(), "{verdict:?}");
        // The listing compared the two objects the ledger does not name.
        assert_eq!(verdict.listing.before_objects, 2);
        assert_eq!(verdict.listing.difference_count, 0);
        assert_eq!(verdict.plain.conversions["attributes_cleared"], 1);
        assert_eq!(verdict.plain.failure_count, 0);

        // A difference outside the ledger is still the listing's.
        let mut changed = after.clone();
        changed[1].sha256 = Some("zz".into());
        let verdict = compare_with_plain(
            &before,
            &changed,
            Declared::default(),
            &ledger(vec![cleared_row(&["\\t.tmp"], 0x120, 0x20)]),
        );
        assert!(!verdict.identical());
        assert_eq!(verdict.listing.difference_count, 1);
        assert_eq!(verdict.plain.failure_count, 0);
    }

    #[test]
    fn a_plain_object_is_held_to_everything_but_its_declared_feature() {
        let (before, after) = temporary_volume();
        let row = || ledger(vec![cleared_row(&["\\t.tmp"], 0x120, 0x20)]);
        // Its contents, times, security and other attributes, each.
        type Change = (&'static str, fn(&mut Record));
        let changes: [Change; 6] = [
            ("content differs", |r| r.sha256 = Some("xx".into())),
            ("last write time changed", |r| r.written += 1),
            ("security changed", |r| r.security = Some("O:BA".into())),
            ("attributes changed", |r| r.attributes |= 0x1),
            ("named streams differ", |r| {
                r.streams = vec![Stream {
                    name: ":s:$DATA".into(),
                    bytes: 1,
                    sha256: "s".into(),
                }]
            }),
            ("extended attributes differ", |r| {
                r.extended_attributes = Some("e".into())
            }),
        ];
        for (kind, change) in changes {
            let mut after = after.clone();
            change(&mut after[2]);
            let verdict = compare_with_plain(&before, &after, Declared::default(), &row());
            assert!(!verdict.identical(), "{kind}");
            assert!(verdict.listing.identical(), "{kind}: {verdict:?}");
            assert_eq!(verdict.plain.failure_count, 1, "{kind}: {verdict:?}");
            assert_eq!(verdict.plain.failure_kinds[kind], 1, "{verdict:?}");
            assert!(verdict.plain.conversions.is_empty(), "{kind}");
        }
        // Still TEMPORARY afterwards: not converted.
        let mut kept = after.clone();
        kept[2].attributes = 0x120;
        let verdict = compare_with_plain(&before, &kept, Declared::default(), &row());
        assert_eq!(verdict.plain.failure_kinds["attributes changed"], 1);
        // Gone afterwards.
        let verdict = compare_with_plain(&before, &after[..2], Declared::default(), &row());
        assert_eq!(verdict.plain.failure_kinds["missing after conversion"], 1);
    }

    #[test]
    fn a_ledger_row_must_show_its_feature_before_and_declare_nothing_more() {
        let (before, after) = temporary_volume();
        for (row, why) in [
            // The listing shows no OFFLINE on the object.
            (
                cleared_row(&["\\t.tmp"], 0x1020, 0x20),
                "without the 0x1000",
            ),
            // Anything but TEMPORARY and OFFLINE.
            (
                cleared_row(&["\\t.tmp"], 0x121, 0x20),
                "not TEMPORARY or OFFLINE",
            ),
            // Nothing cleared at all.
            (
                cleared_row(&["\\t.tmp"], 0x20, 0x20),
                "not TEMPORARY or OFFLINE",
            ),
            // Something added.
            (
                cleared_row(&["\\t.tmp"], 0x120, 0x22),
                "not TEMPORARY or OFFLINE",
            ),
        ] {
            let verdict =
                compare_with_plain(&before, &after, Declared::default(), &ledger(vec![row]));
            assert!(!verdict.identical());
            assert!(
                verdict.plain.failures.iter().any(|f| f.what.contains(why)),
                "{why}: {verdict:?}"
            );
        }
        // An object the ledger names that is not in the listing; one that
        // has no such feature; one hiding a difference of the listing.
        let verdict = compare_with_plain(
            &before,
            &after,
            Declared::default(),
            &ledger(vec![cleared_row(&["\\nowhere"], 0x120, 0x20)]),
        );
        assert_eq!(
            verdict.plain.failure_kinds["ledger names what was not there before"],
            1
        );
        let mut changed = after.clone();
        changed[1].sha256 = Some("zz".into());
        let verdict = compare_with_plain(
            &before,
            &changed,
            Declared::default(),
            &ledger(vec![cleared_row(&["\\a.txt"], 0x120, 0x20)]),
        );
        assert!(!verdict.identical());
        assert_eq!(
            verdict.plain.failure_kinds["declared feature not shown before"], 1,
            "{verdict:?}"
        );
        // A ledger that names one object twice is not valid.
        let verdict = compare_with_plain(
            &before,
            &after,
            Declared::default(),
            &ledger(vec![
                cleared_row(&["\\t.tmp"], 0x120, 0x20),
                cleared_row(&["\\t.tmp"], 0x120, 0x20),
            ]),
        );
        assert_eq!(verdict.plain.failure_kinds["ledger not valid"], 1);
    }

    #[test]
    fn a_hard_link_set_is_wholly_in_the_ledger_or_wholly_outside() {
        let linked = |path: &str, attributes: u32| Record {
            attributes,
            links: 2,
            link_group: Some("g".into()),
            ..file(path, "ll")
        };
        let before = vec![directory("\\"), linked("\\a", 0x120), linked("\\b", 0x120)];
        let after = vec![directory("\\"), linked("\\a", 0x20), linked("\\b", 0x20)];
        let both = compare_with_plain(
            &before,
            &after,
            Declared::default(),
            &ledger(vec![cleared_row(&["\\a", "\\b"], 0x120, 0x20)]),
        );
        assert!(both.identical(), "{both:?}");
        assert_eq!(both.plain.conversions["attributes_cleared"], 1);
        let one = compare_with_plain(
            &before,
            &after,
            Declared::default(),
            &ledger(vec![cleared_row(&["\\a"], 0x120, 0x20)]),
        );
        assert!(!one.identical());
        assert!(
            one.plain.failure_kinds["hard-link set split by the ledger"] >= 1,
            "{one:?}"
        );
    }

    #[test]
    fn each_modelled_kind_takes_off_its_own_feature_only() {
        let row = |kind| LedgerRow {
            kind,
            ..cleared_row(&["\\f"], 0, 0)
        };
        // EFS: the plain text stays, the raw export and the bit go.
        let mut efs = file("\\f", "plain-text");
        efs.attributes = 0x4020;
        efs.efs = true;
        efs.raw_efs_sha256 = Some("cipher".into());
        let mut decrypted = file("\\f", "plain-text");
        decrypted.attributes = 0x20;
        let verdict = compare_with_plain(
            &[efs.clone()],
            &[decrypted.clone()],
            Declared::default(),
            &ledger(vec![row(PlainKind::EfsDecrypted)]),
        );
        assert!(verdict.identical(), "{verdict:?}");
        // Without its raw export read, it was not shown encrypted.
        let mut unread = efs;
        unread.raw_efs_sha256 = None;
        assert!(
            !compare_with_plain(
                &[unread],
                &[decrypted],
                Declared::default(),
                &ledger(vec![row(PlainKind::EfsDecrypted)])
            )
            .identical()
        );

        // WOF: the algorithm goes, the bytes stay.
        let mut wof = file("\\f", "bytes");
        wof.wof_algorithm = Some(1);
        let verdict = compare_with_plain(
            &[wof],
            &[file("\\f", "bytes")],
            Declared::default(),
            &ledger(vec![row(PlainKind::WofExpanded)]),
        );
        assert!(verdict.identical(), "{verdict:?}");

        // A cloud placeholder: the plain read becomes the contents.
        let mut cloud = file("\\f", "stub");
        cloud.attributes = 0x20 | 0x400 | 0x200 | 0x40_0000;
        cloud.reparse_tag = Some(0x9000_301a);
        cloud.reparse_sha256 = Some("r".into());
        cloud.plain_sha256 = Some("bytes".into());
        let verdict = compare_with_plain(
            &[cloud.clone()],
            &[file("\\f", "bytes")],
            Declared::default(),
            &ledger(vec![row(PlainKind::CloudPlaceholderPlain)]),
        );
        assert!(verdict.identical(), "{verdict:?}");
        // The same declared as ProjFS's is not what the listing shows.
        assert!(
            !compare_with_plain(
                &[cloud.clone()],
                &[file("\\f", "bytes")],
                Declared::default(),
                &ledger(vec![row(PlainKind::ProjfsPlaceholderPlain)])
            )
            .identical()
        );
        // Left out: absent afterwards, and nowhere in the listing comparison.
        let verdict = compare_with_plain(
            &[directory("\\"), cloud.clone()],
            &[directory("\\")],
            Declared::default(),
            &ledger(vec![row(PlainKind::CloudLeftOut)]),
        );
        assert!(verdict.identical(), "{verdict:?}");
        assert_eq!(verdict.plain.conversions["cloud_left_out"], 1);
        let there = compare_with_plain(
            &[directory("\\"), cloud.clone()],
            &[directory("\\"), file("\\f", "bytes")],
            Declared::default(),
            &ledger(vec![row(PlainKind::CloudLeftOut)]),
        );
        assert_eq!(
            there.plain.failure_kinds["left out, and there afterwards"],
            1
        );
    }

    #[test]
    fn the_feature_views_are_compared_by_the_listing_too() {
        let mut wof = file("\\f", "bytes");
        wof.wof_algorithm = Some(1);
        let lost = compare(&[wof.clone()], &[file("\\f", "bytes")]);
        assert_eq!(lost.difference_kinds["feature view differs"], 1);
        let exact = compare_exact(&[wof], &[file("\\f", "bytes")]);
        assert_eq!(exact.difference_kinds["feature view differs"], 1);
        assert!(is_cloud_tag(0x9000_001a) && is_cloud_tag(0x9000_f01a));
        assert!(!is_cloud_tag(0x9000_001c) && is_placeholder_tag(0x9000_001c));
        assert!(is_placeholder_tag(DEDUP_TAG) && is_placeholder_tag(SIS_TAG));
        assert!(!is_placeholder_tag(SYMLINK_TAG));
    }

    #[test]
    fn identical_listings_have_no_differences() {
        let listing = vec![
            directory("\\"),
            directory("\\Windows"),
            file("\\Windows\\a.txt", "aa"),
        ];
        let comparison = compare(&listing, &listing);
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.before_objects, 3);
    }

    #[test]
    fn a_short_name_must_become_a_link_to_the_long_name() {
        let mut long = directory("\\Program Files");
        long.short_name = Some("PROGRA~1".to_owned());
        let before = vec![directory("\\"), long.clone()];
        let mut link = directory("\\PROGRA~1");
        link.attributes = 0x410;
        link.reparse_tag = Some(SYMLINK_TAG);
        link.relative_link_target = Some("Program Files".to_owned());
        let mut converted = long.clone();
        converted.short_name = None;
        let after = vec![directory("\\"), link, converted.clone()];
        let comparison = compare(&before, &after);
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.short_names_as_links, 1);

        let lost = compare(&before, &[directory("\\"), converted]);
        assert_eq!(lost.difference_count, 1);
        assert_eq!(lost.differences[0].what, "short name PROGRA~1 was lost");
    }

    #[test]
    fn a_case_mark_that_is_gone_is_a_difference_unless_the_run_declared_it() {
        let mut marked = directory("\\src");
        marked.case_sensitive = true;
        let before = vec![directory("\\"), marked.clone(), directory("\\docs")];
        let carried = before.clone();
        let mut unmarked = marked.clone();
        unmarked.case_sensitive = false;
        let left = vec![directory("\\"), unmarked, directory("\\docs")];
        let not_carried = Declared {
            case_marks_not_carried: true,
            ..Declared::default()
        };

        // Carried over: identical, whatever was declared, and nothing counted.
        for declared in [Declared::default(), not_carried] {
            let same = compare_declared(&before, &carried, declared);
            assert!(same.identical(), "{same:?}");
            assert_eq!(same.case_marks_not_carried, 0);
        }
        // Gone: a difference for a run that carries the mark, and for the
        // exact comparison of a volume that must not have changed.
        let lost = compare(&before, &left);
        assert_eq!(lost.difference_count, 1);
        assert_eq!(lost.difference_kinds["case-sensitive mark lost"], 1);
        assert_eq!(lost.differences[0].path, "\\src");
        assert_eq!(lost.case_marks_not_carried, 0);
        let exact = compare_exact(&before, &left);
        assert_eq!(exact.difference_kinds["case-sensitive mark changed"], 1);
        assert!(compare_exact(&before, &carried).identical());
        // Counted for a run that said it leaves the mark behind.
        let declared = compare_declared(&before, &left, not_carried);
        assert!(declared.identical(), "{declared:?}");
        assert_eq!(declared.case_marks_not_carried, 1);
        assert!(declared.allowed.is_empty());
        // A directory that gained the mark is a difference either way.
        for declaration in [Declared::default(), not_carried] {
            let gained = compare_declared(&left, &before, declaration);
            assert_eq!(
                gained.difference_kinds["case-sensitive mark appeared"], 1,
                "{gained:?}"
            );
        }
        // The mark and its count are written only where there is one.
        let plain = serde_json::to_string(&directory("\\docs")).unwrap();
        assert!(!plain.contains("case_sensitive"), "{plain}");
        assert!(
            serde_json::to_string(&marked)
                .unwrap()
                .contains("\"case_sensitive\":true")
        );
        assert!(
            !serde_json::to_string(&lost)
                .unwrap()
                .contains("case_marks_not_carried")
        );
        assert!(
            serde_json::to_string(&declared)
                .unwrap()
                .contains("\"case_marks_not_carried\":1")
        );
        // A listing written before the field existed reads as unmarked.
        let old: Record = serde_json::from_str(&plain).unwrap();
        assert!(!old.case_sensitive);
    }

    #[test]
    fn a_dropped_short_name_is_counted_only_by_the_comparison_made_for_it() {
        let mut long = file("\\Annual Report.docx", "aa");
        long.short_name = Some("ANNUAL~1.DOC".to_owned());
        let before = vec![long.clone()];
        let mut converted = long.clone();
        converted.short_name = None;
        let after = vec![converted];
        // The ordinary comparison calls it lost.
        let ordinary = compare(&before, &after);
        assert!(!ordinary.identical());
        assert_eq!(ordinary.difference_kinds["short name lost"], 1);
        assert_eq!(ordinary.short_names_dropped, 0);
        // The one for a run that was asked to drop them counts it.
        let asked = compare_without_short_names(&before, &after);
        assert!(asked.identical(), "{asked:?}");
        assert_eq!(asked.short_names_dropped, 1);
        assert!(asked.allowed.is_empty());
        // Nothing else is let through: changed contents are a difference still.
        let changed = vec![file("\\Annual Report.docx", "bb")];
        assert!(!compare_without_short_names(&before, &changed).identical());
        // And the count is only written where there is one.
        let text = serde_json::to_string(&ordinary).unwrap();
        assert!(!text.contains("short_names_dropped"), "{text}");
        assert!(
            serde_json::to_string(&asked)
                .unwrap()
                .contains("\"short_names_dropped\":1")
        );
    }

    #[test]
    fn a_short_name_differing_only_by_case_still_needs_its_link() {
        let mut long = file("\\readme.txt", "11");
        long.short_name = Some("README.TXT".to_owned());
        let mut converted = long.clone();
        converted.short_name = None;
        let comparison = compare(&[directory("\\"), long], &[directory("\\"), converted]);
        assert_eq!(comparison.difference_count, 1, "{comparison:?}");
        assert_eq!(comparison.difference_kinds["short name lost"], 1);

        // A short name with exactly the long name's text is not a second name.
        let mut same = file("\\README.TXT", "11");
        same.short_name = Some("README.TXT".to_owned());
        let mut after = same.clone();
        after.short_name = None;
        let comparison = compare(&[directory("\\"), same], &[directory("\\"), after]);
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.short_names_as_links, 0);
    }

    #[test]
    fn changed_content_missing_and_extra_objects_are_reported() {
        let before = vec![directory("\\"), file("\\a", "11"), file("\\b", "22")];
        let after = vec![directory("\\"), file("\\a", "ff"), file("\\c", "33")];
        let comparison = compare(&before, &after);
        let found: Vec<_> = comparison
            .differences
            .iter()
            .map(|difference| (difference.path.as_str(), difference.what.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("\\a", "content differs"),
                ("\\b", "missing after conversion"),
                ("\\c", "appeared after conversion")
            ]
        );
    }

    #[test]
    fn only_the_documented_differences_are_allowed() {
        let mut compressed = file("\\z", "11");
        compressed.attributes = 0x820;
        let mut audited = file("\\s", "22");
        audited.security = Some("O:SYG:SYD:(A;;FA;;;SY)".to_owned());
        let before = vec![
            directory("\\"),
            compressed,
            audited,
            file("\\System Volume Information\\x", "33"),
        ];
        let mut plain = file("\\z", "11");
        plain.attributes = 0x20 | 0x8000;
        let mut empty_sacl = file("\\s", "22");
        empty_sacl.security = Some("O:SYG:SYD:(A;;FA;;;SY)S:".to_owned());
        let after = vec![
            directory("\\"),
            plain,
            empty_sacl,
            file("\\System Volume Information\\y", "44"),
        ];
        let comparison = compare(&before, &after);
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.allowed["NTFS compression flag removed"], 1);
        assert_eq!(comparison.allowed["empty system ACL versus none"], 1);
        assert_eq!(comparison.allowed["System Volume Information content"], 2);

        let mut real_sacl = file("\\s", "22");
        real_sacl.security = Some("O:SYG:SYD:(A;;FA;;;SY)S:(AU;SA;FA;;;WD)".to_owned());
        let stricter = compare(
            &[directory("\\"), file("\\s", "22")],
            &[directory("\\"), real_sacl],
        );
        assert_eq!(stricter.difference_count, 1);
    }

    #[test]
    fn an_exact_comparison_accepts_nothing_a_conversion_comparison_accepts() {
        let mut compressed = file("\\z", "11");
        compressed.attributes = 0x820;
        let mut cached = file("\\k", "22");
        cached.kernel_cache_attributes = 2;
        let mut named = file("\\Program Files", "33");
        named.short_name = Some("PROGRA~1".to_owned());
        let before = vec![
            directory("\\"),
            compressed,
            cached,
            named,
            file("\\System Volume Information\\x", "44"),
        ];
        // An unchanged NTFS volume, short names and all, is identical.
        let unchanged = compare_exact(&before, &before);
        assert!(unchanged.identical(), "{unchanged:?}");
        assert!(unchanged.allowed.is_empty());
        assert_eq!(unchanged.short_names_as_links, 0);

        // Each of the things a conversion may leave is a difference here.
        let mut after = before.clone();
        after[1].attributes = 0x20;
        after[2].kernel_cache_attributes = 0;
        after[3].short_name = None;
        after[4].sha256 = Some("55".to_owned());
        let comparison = compare_exact(&before, &after);
        assert_eq!(comparison.difference_count, 4, "{comparison:?}");
        assert!(comparison.allowed.is_empty());
        for kind in [
            "attributes changed",
            "kernel cache attributes changed",
            "short name changed",
            "content differs",
        ] {
            assert_eq!(comparison.difference_kinds[kind], 1, "{kind}");
        }
    }

    #[test]
    fn an_exact_comparison_reports_missing_added_and_relinked_objects() {
        let linked = |path: &str, group: &str| {
            let mut record = file(path, "11");
            record.links = 2;
            record.link_group = Some(group.to_owned());
            record
        };
        let before = vec![
            directory("\\"),
            linked("\\a", "x"),
            linked("\\b", "x"),
            file("\\c", "33"),
        ];
        // Group identifiers differ between listings; the sets of names do not.
        let same = vec![
            directory("\\"),
            linked("\\a", "q"),
            linked("\\b", "q"),
            file("\\c", "33"),
        ];
        assert!(compare_exact(&before, &same).identical());

        let changed = vec![
            directory("\\"),
            linked("\\a", "q"),
            linked("\\b", "r"),
            file("\\d", "33"),
        ];
        let comparison = compare_exact(&before, &changed);
        assert_eq!(comparison.difference_count, 3, "{comparison:?}");
        for kind in [
            "hard-link set changed",
            "missing afterwards",
            "appeared afterwards",
        ] {
            assert_eq!(comparison.difference_kinds[kind], 1, "{kind}");
        }
    }

    #[test]
    fn the_accepted_differences_are_exactly_the_four_documented_ones() {
        // Widening this list is a decision about what a conversion may
        // change, not a way to make a comparison pass.
        assert_eq!(
            ALLOWED_DIFFERENCES,
            [
                "System Volume Information content",
                "NTFS compression flag removed",
                "empty system ACL versus none",
                "kernel cache attributes dropped",
            ]
        );
    }

    #[test]
    fn only_kernel_cache_attributes_may_disappear() {
        let mut cached = file("\\a", "11");
        cached.kernel_cache_attributes = 2;
        cached.extended_attributes = Some("ee".to_owned());
        let mut kept = file("\\a", "11");
        kept.extended_attributes = Some("ee".to_owned());
        let comparison = compare(
            &[directory("\\"), cached.clone()],
            &[directory("\\"), kept.clone()],
        );
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.allowed["kernel cache attributes dropped"], 1);

        let mut lost = kept.clone();
        lost.extended_attributes = None;
        let comparison = compare(&[directory("\\"), cached], &[directory("\\"), lost]);
        assert_eq!(comparison.difference_count, 1);
        assert_eq!(comparison.difference_kinds["extended attributes differ"], 1);
    }

    #[test]
    fn differences_are_counted_by_kind() {
        let before = vec![directory("\\"), file("\\a", "11"), file("\\b", "22")];
        let mut a = file("\\a", "11");
        a.changed = 99;
        let mut b = file("\\b", "22");
        b.changed = 77;
        let comparison = compare(&before, &[directory("\\"), a, b]);
        assert_eq!(comparison.difference_kinds["change time changed"], 2);
    }

    #[test]
    fn kinds_do_not_depend_on_the_names_and_values_a_difference_quotes() {
        let named = |path: &str, short: &str, sddl: &str| {
            let mut record = file(path, "11");
            record.short_name = Some(short.to_owned());
            record.security = Some(sddl.to_owned());
            record
        };
        let before = vec![
            directory("\\"),
            named("\\Program Files", "PROGRA~1", "O:SYG:SYD:(A;;FA;;;SY)"),
            named("\\Common Files", "COMMON~1", "O:BAG:BAD:(A;;FA;;;BA)"),
        ];
        let mut after = before.clone();
        for record in &mut after[1..] {
            record.short_name = None;
            record.security = Some("O:WDG:WDD:(A;;FA;;;WD)".to_owned());
        }
        let comparison = compare(&before, &after);
        assert_eq!(comparison.difference_count, 4, "{comparison:?}");
        assert_eq!(comparison.difference_kinds.len(), 2, "{comparison:?}");
        assert_eq!(comparison.difference_kinds["short name lost"], 2);
        assert_eq!(comparison.difference_kinds["security changed"], 2);
        // The detail still names what differed.
        assert!(
            comparison
                .differences
                .iter()
                .any(|difference| difference.what == "short name PROGRA~1 was lost")
        );
    }

    #[test]
    fn hard_link_sets_must_be_preserved() {
        let linked = |path: &str, group: &str| {
            let mut record = file(path, "11");
            record.links = 2;
            record.link_group = Some(group.to_owned());
            record
        };
        let before = vec![directory("\\"), linked("\\a", "x"), linked("\\b", "x")];
        let same = vec![directory("\\"), linked("\\a", "q"), linked("\\b", "q")];
        assert!(compare(&before, &same).identical());
        let split = vec![directory("\\"), linked("\\a", "q"), linked("\\b", "r")];
        let comparison = compare(&before, &split);
        assert_eq!(comparison.difference_count, 1);
        assert!(comparison.differences[0].what.contains("hard-link set"));
    }

    #[test]
    fn a_query_buffer_grows_until_the_answer_fits_or_the_limit_is_reached() {
        let more_data = || std::io::Error::from_raw_os_error(234);
        let mut buffer = vec![0u64; 4];
        let mut calls = 0;
        query_growing(&mut buffer, 1024, "test", |room| {
            calls += 1;
            if room.len() < 32 {
                Err(more_data())
            } else {
                Ok(())
            }
        })
        .unwrap();
        assert_eq!((buffer.len(), calls), (32, 4));

        // 256 bytes held; one doubling reaches the 512-byte limit, then it stops.
        let error =
            query_growing(&mut buffer, 512, "the stream list", |_| Err(more_data())).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("the stream list does not fit in 512 bytes"),
            "{error}"
        );
        assert_eq!(buffer.len(), 64);

        // Any other failure is returned as it is, without growing.
        let denied = query_growing(&mut buffer, 4096, "test", |_| {
            Err(std::io::Error::from_raw_os_error(5))
        })
        .unwrap_err();
        assert_eq!(denied.raw_os_error(), Some(5));
        assert_eq!(buffer.len(), 64);
    }

    #[cfg(windows)]
    #[test]
    fn names_that_are_not_valid_utf16_are_rejected_not_altered() {
        let bytes = |units: &[u16]| -> Vec<u8> {
            units.iter().flat_map(|unit| unit.to_le_bytes()).collect()
        };
        assert_eq!(
            capture::utf16(&bytes(&[0x41, 0x65e5])).unwrap(),
            "A\u{65e5}"
        );
        // A surrogate pair is one character; a lone surrogate is not text.
        assert_eq!(
            capture::utf16(&bytes(&[0xd83d, 0xde00])).unwrap(),
            "\u{1f600}"
        );
        assert_eq!(
            capture::utf16(&bytes(&[0xd800, 0x41])).unwrap_err(),
            [0xd800, 0x41]
        );
    }

    #[test]
    fn every_item_is_observed_once_and_a_panic_fails_the_run_naming_the_item() {
        let mut outputs = run_all(
            (0..1000u32).collect(),
            8,
            || 0u32,
            |number| number.to_string(),
            |seen, number| {
                *seen += 1;
                number * 2
            },
        )
        .unwrap();
        outputs.sort_unstable();
        assert_eq!(outputs, (0..1000u32).map(|n| n * 2).collect::<Vec<_>>());

        let error = run_all(
            (0..1000u32).collect(),
            8,
            || (),
            |number| format!("\\object-{number}"),
            |(), number| {
                assert_ne!(number, 617, "boom");
                number
            },
        )
        .unwrap_err();
        let text = error.to_string();
        assert!(
            text.contains("\\object-617") && text.contains("boom"),
            "{text}"
        );

        let none = run_all(Vec::<u32>::new(), 8, || (), |n| n.to_string(), |(), n| n).unwrap();
        assert!(none.is_empty());
    }

    /// A backslash and nine three-byte characters (U+65E5): 28 bytes, in which
    /// byte 26, the length of "\System Volume Information", is not a
    /// character boundary.
    fn boundary_path() -> String {
        format!("\\{}", "\u{65e5}".repeat(9))
    }

    #[test]
    fn a_path_that_the_exempt_prefix_length_splits_mid_character_is_compared() {
        let path = boundary_path();
        assert_eq!(path.len(), 28);
        assert!(!path.is_char_boundary(SYSTEM_VOLUME_INFORMATION.len()));
        assert!(!inside_system_volume_information(&path));

        let listing = vec![directory("\\"), file(&path, "aa")];
        let comparison = compare(&listing, &listing);
        assert!(comparison.identical(), "{comparison:?}");

        let missing = compare(&listing, &[directory("\\")]);
        assert_eq!(missing.difference_count, 1, "{missing:?}");
        assert_eq!(missing.differences[0].path, path);
        assert_eq!(missing.differences[0].what, "missing after conversion");

        let appeared = compare(&[directory("\\")], &listing);
        assert_eq!(appeared.difference_count, 1, "{appeared:?}");
        assert_eq!(appeared.differences[0].what, "appeared after conversion");
    }

    #[test]
    fn supplementary_plane_and_long_mixed_script_paths_are_compared() {
        // U+1D4B3 and U+1F600 take four bytes each in UTF-8 and two units in UTF-16.
        let astral = "\\\u{1d4b3}\u{1f600}\\a\u{1f600}b.txt";
        // Han, Cyrillic, an emoji and ASCII in every component.
        let component =
            "\u{6570}\u{636e}-\u{434}\u{430}\u{43d}\u{43d}\u{44b}\u{435}-\u{1f600}-data";
        let long = format!("\\{}", vec![component; 24].join("\\"));
        assert!(long.chars().count() > 400);
        let inside = format!("{SYSTEM_VOLUME_INFORMATION}{long}");
        let listing = vec![
            directory("\\"),
            file(astral, "11"),
            file(&long, "22"),
            file(&inside, "33"),
        ];
        let comparison = compare(&listing, &listing);
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.allowed["System Volume Information content"], 1);

        let mut changed = listing.clone();
        changed[1].sha256 = Some("ee".to_owned());
        changed[2].sha256 = Some("ff".to_owned());
        let comparison = compare(&listing, &changed);
        assert_eq!(comparison.difference_count, 2, "{comparison:?}");
        assert!(
            comparison
                .differences
                .iter()
                .all(|difference| difference.what == "content differs")
        );
    }

    #[test]
    fn only_the_system_volume_information_directory_itself_is_exempt() {
        assert!(inside_system_volume_information(
            "\\System Volume Information\\x"
        ));
        assert!(inside_system_volume_information(
            "\\SYSTEM VOLUME INFORMATION\\x"
        ));
        // The directory's own entry, and names that merely begin the same way.
        assert!(!inside_system_volume_information(SYSTEM_VOLUME_INFORMATION));
        assert!(!inside_system_volume_information(
            "\\System Volume Informationx\\y"
        ));
        let lookalike = "\\System Volume Information\u{65e5}\\x";
        assert!(!inside_system_volume_information(lookalike));

        let comparison = compare(
            &[directory("\\"), file(lookalike, "11")],
            &[directory("\\")],
        );
        assert_eq!(comparison.difference_count, 1, "{comparison:?}");
        assert!(comparison.allowed.is_empty(), "{comparison:?}");
    }
}
