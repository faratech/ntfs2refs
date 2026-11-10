//! A plain listing of a mounted volume, and a comparison of two listings.
//!
//! Used to compare an NTFS source before conversion with the same volume once
//! it mounts as ReFS. It deliberately shares nothing with the converter's own
//! verification: directories are enumerated through Windows, every stream is
//! read through whichever file system is mounted, and security is the SDDL
//! text Windows itself produces. Capturing is read only.

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
    /// SHA-256 over the extended attributes, if there are any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extended_attributes: Option<String>,
    pub links: u32,
    /// Identifies the file behind several hard links. Only meaningful within
    /// one listing; never compared across listings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link_group: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Difference {
    pub path: String,
    pub what: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Comparison {
    pub before_objects: usize,
    pub after_objects: usize,
    /// 8.3 names that became same-directory links, as intended.
    pub short_names_as_links: usize,
    /// Expected differences, counted by kind.
    pub allowed: BTreeMap<String, usize>,
    pub difference_count: usize,
    /// The first differences, in path order.
    pub differences: Vec<Difference>,
}
impl Comparison {
    pub fn identical(&self) -> bool {
        self.difference_count == 0
    }
}

const DIFFERENCE_LIMIT: usize = 500;
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
    path.len() > SYSTEM_VOLUME_INFORMATION.len()
        && path[..SYSTEM_VOLUME_INFORMATION.len()].eq_ignore_ascii_case(SYSTEM_VOLUME_INFORMATION)
        && path.as_bytes()[SYSTEM_VOLUME_INFORMATION.len()] == b'\\'
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

/// Compares the listing taken before conversion with the one taken after.
pub fn compare(before: &[Record], after: &[Record]) -> Comparison {
    let mut result = Comparison {
        before_objects: before.len(),
        after_objects: after.len(),
        ..Comparison::default()
    };
    let mut differences: Vec<Difference> = Vec::new();
    let allow = |kind: &str, allowed: &mut BTreeMap<String, usize>| {
        *allowed.entry(kind.to_owned()).or_default() += 1;
    };
    let after_by_path: BTreeMap<&str, &Record> =
        after.iter().map(|record| (record.path.as_str(), record)).collect();
    let before_paths: BTreeSet<&str> = before.iter().map(|record| record.path.as_str()).collect();
    let mut explained_after: BTreeSet<String> = BTreeSet::new();

    for record in before {
        let mut differ = |what: String| {
            differences.push(Difference {
                path: record.path.clone(),
                what,
            })
        };
        for error in &record.errors {
            differ(format!("could not be read before conversion: {error}"));
        }
        // An 8.3 name must survive as a same-directory link to the long name.
        if let Some(short) = &record.short_name {
            let (parent, leaf) = parent_and_leaf(&record.path);
            if !short.eq_ignore_ascii_case(leaf) {
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
                    Some(_) => differ(format!("short name {short} exists but is not a link to {leaf}")),
                    None => differ(format!("short name {short} was lost")),
                }
            }
        }
        let Some(now) = after_by_path.get(record.path.as_str()) else {
            if inside_system_volume_information(&record.path) {
                allow("System Volume Information content", &mut result.allowed);
            } else {
                differ("missing after conversion".to_owned());
            }
            continue;
        };
        if inside_system_volume_information(&record.path) {
            allow("System Volume Information content", &mut result.allowed);
            continue;
        }
        for error in &now.errors {
            differ(format!("could not be read after conversion: {error}"));
        }
        if now.directory != record.directory {
            differ("file/directory kind changed".to_owned());
            continue;
        }
        let (was, is) = (
            attributes_for_comparison(record.attributes),
            attributes_for_comparison(now.attributes),
        );
        if was != is {
            if was & !COMPRESSED == is {
                allow("NTFS compression flag removed", &mut result.allowed);
            } else {
                differ(format!("attributes {:#x} became {:#x}", record.attributes, now.attributes));
            }
        }
        for (name, was, is) in [
            ("creation time", record.created, now.created),
            ("last write time", record.written, now.written),
            ("change time", record.changed, now.changed),
        ] {
            if was != is {
                differ(format!("{name} {was} became {is}"));
            }
        }
        if !record.directory && record.bytes != now.bytes {
            differ(format!("size {} became {}", record.bytes, now.bytes));
        }
        if record.sha256 != now.sha256 {
            differ("content differs".to_owned());
        }
        if record.streams != now.streams {
            differ("named streams differ".to_owned());
        }
        match (&record.security, &now.security) {
            (Some(was), Some(is)) if was == is => (),
            (Some(was), Some(is)) => {
                let (was_base, _) = security_for_comparison(was);
                let (is_base, _) = security_for_comparison(is);
                if was_base == is_base {
                    allow("empty system ACL versus none", &mut result.allowed);
                } else {
                    differ(format!("security {was} became {is}"));
                }
            }
            (None, None) => (),
            _ => differ("security could not be read on one side".to_owned()),
        }
        if record.reparse_tag != now.reparse_tag || record.reparse_sha256 != now.reparse_sha256 {
            differ("reparse point differs".to_owned());
        }
        if record.extended_attributes != now.extended_attributes {
            differ("extended attributes differ".to_owned());
        }
        if record.links != now.links {
            differ(format!("hard-link count {} became {}", record.links, now.links));
        }
    }

    // The same names must share one file before and after.
    let groups = |records: &[Record]| -> BTreeSet<BTreeSet<String>> {
        let mut by_group: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
        for record in records {
            if let Some(group) = &record.link_group {
                if !inside_system_volume_information(&record.path) {
                    by_group.entry(group).or_default().insert(record.path.clone());
                }
            }
        }
        by_group.into_values().filter(|names| names.len() > 1).collect()
    };
    let (before_groups, after_groups) = (groups(before), groups(after));
    for names in before_groups.difference(&after_groups) {
        differences.push(Difference {
            path: names.iter().next().cloned().unwrap_or_default(),
            what: format!("hard-link set of {} names is not preserved", names.len()),
        });
    }

    for record in after {
        if before_paths.contains(record.path.as_str()) || explained_after.contains(&record.path) {
            continue;
        }
        if inside_system_volume_information(&record.path) {
            allow("System Volume Information content", &mut result.allowed);
        } else {
            differences.push(Difference {
                path: record.path.clone(),
                what: "appeared after conversion".to_owned(),
            });
        }
    }

    differences.sort_by(|a, b| a.path.cmp(&b.path).then_with(|| a.what.cmp(&b.what)));
    result.difference_count = differences.len();
    differences.truncate(DIFFERENCE_LIMIT);
    result.differences = differences;
    result
}

#[cfg(windows)]
pub use capture::capture;

#[cfg(windows)]
mod capture {
    use super::{Record, Stream, SYMLINK_TAG};
    use sha2::{Digest, Sha256};
    use std::{
        fs::File,
        io::{self, Read, Seek, SeekFrom},
        os::windows::{ffi::OsStrExt, fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
        ptr,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::{Authorization::ConvertSecurityDescriptorToStringSecurityDescriptorW, GetKernelObjectSecurity},
        Storage::FileSystem::GetFileInformationByHandleEx,
    };

    // FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | ACCESS_SYSTEM_SECURITY
    const READ_EVERYTHING: u32 = 0x0102_0089;
    // FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN
    const OPEN_FLAGS: u32 = 0x0a20_0000;
    const REPARSE: u32 = 0x400;
    const DIRECTORY: u32 = 0x10;

    struct Pending {
        path: String,
        attributes: u32,
        created: i64,
        written: i64,
        changed: i64,
        bytes: u64,
        ea_bytes: u32,
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
        if ok == 0 { Err(io::Error::last_os_error()) } else { Ok(()) }
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
    fn utf16(bytes: &[u8]) -> String {
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16_lossy(&units)
    }

    /// One directory's entries, with the short names NTFS keeps beside them.
    fn list(prefix: &str, path: &str, out: &mut Vec<Pending>) -> io::Result<()> {
        let directory = open(prefix, path)?;
        let mut buffer = vec![0u64; 32 * 1024];
        loop {
            // FileIdBothDirectoryInfo
            match information(&directory, 10, &mut buffer) {
                Ok(()) => (),
                // ERROR_NO_MORE_FILES
                Err(error) if error.raw_os_error() == Some(18) => return Ok(()),
                Err(error) => return Err(error),
            }
            let bytes = bytes_of(&buffer);
            let mut at = 0usize;
            loop {
                let entry = &bytes[at..];
                let next = u32_at(entry, 0) as usize;
                let name_bytes = u32_at(entry, 60) as usize;
                let name = utf16(&entry[104..104 + name_bytes]);
                if name != "." && name != ".." {
                    let short_bytes = entry[68] as usize;
                    let short = utf16(&entry[70..70 + short_bytes]);
                    out.push(Pending {
                        path: if path == "\\" { format!("\\{name}") } else { format!("{path}\\{name}") },
                        attributes: u32_at(entry, 56),
                        created: i64_at(entry, 8),
                        written: i64_at(entry, 24),
                        changed: i64_at(entry, 32),
                        bytes: i64_at(entry, 40) as u64,
                        ea_bytes: u32_at(entry, 64),
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
            let end = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
            let value = String::from_utf16_lossy(&units[..end]);
            // SAFETY: allocated by the conversion call above.
            unsafe { LocalFree(text.cast()) };
            return Ok(value);
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

    fn named_streams(prefix: &str, path: &str, file: &File, buffer: &mut [u8]) -> io::Result<Vec<Stream>> {
        let mut listing = vec![0u64; 8192];
        // FileStreamInfo
        match information(file, 7, &mut listing) {
            Ok(()) => (),
            // ERROR_HANDLE_EOF: no streams at all (a directory without any).
            Err(error) if error.raw_os_error() == Some(38) => return Ok(Vec::new()),
            Err(error) => return Err(error),
        }
        let bytes = bytes_of(&listing);
        let mut streams = Vec::new();
        let mut at = 0usize;
        loop {
            let entry = &bytes[at..];
            let next = u32_at(entry, 0) as usize;
            let name_bytes = u32_at(entry, 4) as usize;
            let name = utf16(&entry[24..24 + name_bytes]);
            if name != "::$DATA" {
                let stream_name = name.strip_suffix(":$DATA").unwrap_or(&name);
                let mut stream = File::options()
                    .access_mode(0x0000_0081)
                    .share_mode(7)
                    .custom_flags(OPEN_FLAGS)
                    .open(format!("{prefix}{path}{stream_name}"))?;
                let (bytes, sha256) = hash(&mut stream, buffer)?;
                streams.push(Stream { name, bytes, sha256 });
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
        buffer.get(20 + offset..20 + offset + length).map(utf16)
    }

    fn observe(prefix: &str, pending: Pending, buffer: &mut [u8]) -> Record {
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
        let mut standard = [0u64; 3];
        // FileStandardInfo
        match information(&file, 1, &mut standard) {
            Ok(()) => record.links = u32_at(bytes_of(&standard), 16),
            Err(error) => note(&mut record, "link count", &error),
        }
        if record.links > 1 && !directory {
            let mut identity = [0u64; 3];
            // FileIdInfo
            match information(&file, 18, &mut identity) {
                Ok(()) => record.link_group = Some(hex::encode(&bytes_of(&identity)[8..24])),
                Err(error) => note(&mut record, "file identity", &error),
            }
        }
        if record.attributes & REPARSE != 0 {
            match crate::reparse_native::capture(&file) {
                Ok(Some(point)) => {
                    record.reparse_tag = Some(point.tag());
                    record.reparse_sha256 = Some(hex::encode(Sha256::digest(&point.buffer)));
                    record.relative_link_target = relative_target(&point.buffer);
                }
                Ok(None) => note(&mut record, "reparse point", &"attribute set but no reparse data"),
                Err(error) => note(&mut record, "reparse point", &error),
            }
        } else if pending.ea_bytes != 0 {
            match crate::extended_attributes_native::capture(&file) {
                Ok(set) if !set.is_empty() => {
                    let mut hasher = Sha256::new();
                    for entry in &set.entries {
                        hasher.update([entry.flags]);
                        hasher.update((entry.name.len() as u32).to_le_bytes());
                        hasher.update(entry.name.to_ascii_uppercase());
                        hasher.update((entry.value.len() as u32).to_le_bytes());
                        hasher.update(&entry.value);
                    }
                    record.extended_attributes = Some(hex::encode(hasher.finalize()));
                }
                Ok(_) => (),
                Err(error) => note(&mut record, "extended attributes", &format!("{error:?}")),
            }
        }
        match named_streams(prefix, &record.path, &file, buffer) {
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
        let text = String::from_utf16(&text).map_err(|_| io::Error::other("volume root is not Unicode"))?;
        let drive = text.trim_end_matches('\\');
        if drive.len() != 2 || !drive.as_bytes()[0].is_ascii_alphabetic() || drive.as_bytes()[1] != b':' {
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
            ea_bytes: 0,
            short_name: None,
        }];
        let mut listing_errors = Vec::new();
        let mut next = 0usize;
        while next < pending.len() {
            let entry = &pending[next];
            next += 1;
            // Links and junctions are recorded, never followed.
            if entry.attributes & DIRECTORY == 0 || entry.attributes & REPARSE != 0 {
                continue;
            }
            let path = entry.path.clone();
            if let Err(error) = list(&prefix, &path, &mut pending) {
                listing_errors.push((path, error.to_string()));
            }
        }

        let total = pending.len();
        let slots: Vec<std::sync::Mutex<Option<Pending>>> =
            pending.into_iter().map(|entry| std::sync::Mutex::new(Some(entry))).collect();
        let cursor = AtomicUsize::new(0);
        let mut records: Vec<Record> = std::thread::scope(|scope| {
            let workers: Vec<_> = (0..threads.clamp(1, 64))
                .map(|_| {
                    scope.spawn(|| {
                        let mut buffer = vec![0u8; 1024 * 1024];
                        let mut done = Vec::new();
                        loop {
                            let index = cursor.fetch_add(1, Ordering::Relaxed);
                            if index >= total {
                                return done;
                            }
                            let entry = slots[index]
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .take();
                            if let Some(entry) = entry {
                                done.push(observe(&prefix, entry, &mut buffer));
                            }
                        }
                    })
                })
                .collect();
            workers
                .into_iter()
                .flat_map(|worker| worker.join().unwrap_or_default())
                .collect()
        });
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

    #[test]
    fn identical_listings_have_no_differences() {
        let listing = vec![directory("\\"), directory("\\Windows"), file("\\Windows\\a.txt", "aa")];
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
        let before = vec![directory("\\"), compressed, audited, file("\\System Volume Information\\x", "33")];
        let mut plain = file("\\z", "11");
        plain.attributes = 0x20 | 0x8000;
        let mut empty_sacl = file("\\s", "22");
        empty_sacl.security = Some("O:SYG:SYD:(A;;FA;;;SY)S:".to_owned());
        let after = vec![directory("\\"), plain, empty_sacl, file("\\System Volume Information\\y", "44")];
        let comparison = compare(&before, &after);
        assert!(comparison.identical(), "{comparison:?}");
        assert_eq!(comparison.allowed["NTFS compression flag removed"], 1);
        assert_eq!(comparison.allowed["empty system ACL versus none"], 1);
        assert_eq!(comparison.allowed["System Volume Information content"], 2);

        let mut real_sacl = file("\\s", "22");
        real_sacl.security = Some("O:SYG:SYD:(A;;FA;;;SY)S:(AU;SA;FA;;;WD)".to_owned());
        let stricter = compare(&[directory("\\"), file("\\s", "22")], &[directory("\\"), real_sacl]);
        assert_eq!(stricter.difference_count, 1);
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
}
