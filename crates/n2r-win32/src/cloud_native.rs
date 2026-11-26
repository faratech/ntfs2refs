//! Cloud-files placeholders, as the Cloud Files API (cldflt) reports them
//! on a volume that is online and in use.
//!
//! A placeholder of a cloud provider (OneDrive Files On-Demand and any
//! other provider of the Cloud Files API: reparse tags 0x9000x01A) keeps on
//! the volume only the ranges of its file that have been downloaded. A run
//! that makes such a file plain needs every byte of it on the volume before
//! the volume is frozen, because the frozen volume is read without the
//! provider. This module asks Windows which ranges are on the volume
//! ([`on_disk_ranges`], CfGetPlaceholderRangeInfo with
//! CF_PLACEHOLDER_RANGE_INFO_ONDISK), which never downloads anything, and
//! downloads the rest ([`hydrate`], CfHydratePlaceholder), which needs the
//! provider running and is done only before the freeze, once the user
//! agreed, under a `SourceChangeAuthority`.
//!
//! A directory placeholder whose contents the provider has not listed yet
//! (CF_PLACEHOLDER_STATE_PARTIAL) holds only the entries listed so far:
//! listing it while the provider runs has the provider fill it in
//! ([`populate`]).
use serde::{Deserialize, Serialize};

/// One range of a file, as CF_FILE_RANGE gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileRange {
    pub offset: u64,
    pub length: u64,
}

/// How much of a placeholder is on the volume.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    /// Every byte is on the volume (or the file is empty).
    Full,
    /// Some bytes are on the volume and some are not.
    Partial,
    /// None of its bytes are.
    NotPresent,
}

impl Presence {
    pub fn name(self) -> &'static str {
        match self {
            Presence::Full => "fully present",
            Presence::Partial => "partly present",
            Presence::NotPresent => "not present",
        }
    }
}

/// What the Cloud Files API reports of one placeholder.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceholderReport {
    pub directory: bool,
    /// The file's length as a program reads it.
    pub size: u64,
    /// The bytes of it that are on the volume.
    pub present_bytes: u64,
    /// The bytes a hydration downloads: `size` less `present_bytes`.
    pub missing_bytes: u64,
    pub presence: Presence,
    /// A directory whose contents the provider has not listed in full
    /// (CF_PLACEHOLDER_STATE_PARTIAL on a directory).
    pub unpopulated: bool,
    /// The pin state the provider set (CF_PIN_STATE_*), where it was read.
    pub pin_state: Option<i32>,
}

impl PlaceholderReport {
    /// Whether a run has to bring anything onto the volume for it.
    pub fn needs_download(&self) -> bool {
        self.missing_bytes != 0 || self.unpopulated
    }
}

/// The ranges, merged and clamped to `size`, sorted by offset.
pub fn merge(size: u64, ranges: &[FileRange]) -> Vec<FileRange> {
    let mut spans: Vec<(u64, u64)> = ranges
        .iter()
        .filter(|range| range.length != 0 && range.offset < size)
        .map(|range| {
            (
                range.offset,
                range.offset.saturating_add(range.length).min(size),
            )
        })
        .collect();
    spans.sort_unstable();
    let mut merged: Vec<(u64, u64)> = Vec::with_capacity(spans.len());
    for (start, end) in spans {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    merged
        .into_iter()
        .map(|(start, end)| FileRange {
            offset: start,
            length: end - start,
        })
        .collect()
}

/// The bytes of a file of `size` bytes that `present` covers.
pub fn present_bytes(size: u64, present: &[FileRange]) -> u64 {
    merge(size, present).iter().map(|range| range.length).sum()
}

/// The ranges of `[0, size)` that `present` does not cover.
pub fn missing_ranges(size: u64, present: &[FileRange]) -> Vec<FileRange> {
    let mut missing = Vec::new();
    let mut at = 0u64;
    for range in merge(size, present) {
        if range.offset > at {
            missing.push(FileRange {
                offset: at,
                length: range.offset - at,
            });
        }
        at = range.offset + range.length;
    }
    if at < size {
        missing.push(FileRange {
            offset: at,
            length: size - at,
        });
    }
    missing
}

/// A file's report from its length and the ranges on the volume.
pub fn file_report(size: u64, present: &[FileRange], pin_state: Option<i32>) -> PlaceholderReport {
    let on_volume = present_bytes(size, present);
    PlaceholderReport {
        directory: false,
        size,
        present_bytes: on_volume,
        missing_bytes: size - on_volume,
        presence: if on_volume == size {
            Presence::Full
        } else if on_volume == 0 {
            Presence::NotPresent
        } else {
            Presence::Partial
        },
        unpopulated: false,
        pin_state,
    }
}

/// CF_PLACEHOLDER_STATE_PARTIAL: a directory not listed in full.
pub const PLACEHOLDER_STATE_PARTIAL: u32 = 0x10;
/// CF_PLACEHOLDER_STATE_PLACEHOLDER.
pub const PLACEHOLDER_STATE_PLACEHOLDER: u32 = 0x1;

/// A directory's report from its placeholder state.
pub fn directory_report(state: u32, pin_state: Option<i32>) -> PlaceholderReport {
    let unpopulated = state & PLACEHOLDER_STATE_PARTIAL != 0;
    PlaceholderReport {
        directory: true,
        size: 0,
        present_bytes: 0,
        missing_bytes: 0,
        presence: if unpopulated {
            Presence::Partial
        } else {
            Presence::Full
        },
        unpopulated,
        pin_state,
    }
}

/// What the Cloud Files API said of a placeholder it could not report on.
pub fn describe_error(code: i32) -> String {
    let text = std::io::Error::from_raw_os_error(code & 0xffff).to_string();
    match code as u32 & 0xffff {
        // ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING
        362 => format!("its cloud provider is not running ({text})"),
        // ERROR_CLOUD_FILE_NOT_IN_SYNC .. the 0x18x family of cloud errors.
        _ => format!("the Cloud Files API answered {code:#010x} ({text})"),
    }
}

#[cfg(windows)]
mod native {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io,
        os::windows::{fs::OpenOptionsExt, io::AsRawHandle},
        path::Path,
    };
    use windows_sys::Win32::Storage::CloudFilters::{
        CF_FILE_RANGE, CF_HYDRATE_FLAG_NONE, CF_PLACEHOLDER_INFO_BASIC,
        CF_PLACEHOLDER_RANGE_INFO_ONDISK, CfGetPlaceholderInfo, CfGetPlaceholderRangeInfo,
        CfGetPlaceholderStateFromAttributeTag, CfHydratePlaceholder,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_TAG_INFO, FileAttributeTagInfo, GetFileInformationByHandleEx,
    };

    /// FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT |
    /// FILE_FLAG_OPEN_NO_RECALL: the placeholder itself, recalling nothing.
    const QUERY_FLAGS: u32 = 0x0230_0000;
    /// FILE_READ_ATTRIBUTES | SYNCHRONIZE: all a query needs.
    const QUERY_ACCESS: u32 = 0x0010_0080;
    /// FILE_READ_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE: what a
    /// hydration needs (READ_DATA).
    const HYDRATE_ACCESS: u32 = 0x0010_0081;
    /// FILE_FLAG_BACKUP_SEMANTICS.
    const HYDRATE_FLAGS: u32 = 0x0200_0000;
    /// HRESULT_FROM_WIN32(ERROR_MORE_DATA).
    const MORE_DATA: i32 = 0x8007_00eau32 as i32;
    /// HRESULT_FROM_WIN32(ERROR_HANDLE_EOF).
    const HANDLE_EOF: i32 = 0x8007_0026u32 as i32;
    /// CF_EOF.
    const CF_EOF: i64 = -1;

    fn hresult(code: i32) -> io::Error {
        io::Error::other(describe_error(code))
    }

    fn open_query(path: &Path) -> io::Result<File> {
        OpenOptions::new()
            .access_mode(QUERY_ACCESS)
            .share_mode(7)
            .custom_flags(QUERY_FLAGS)
            .open(path)
    }

    /// The file attributes and the reparse tag of an open object.
    fn attribute_tag(file: &File) -> io::Result<(u32, u32)> {
        let mut info = FILE_ATTRIBUTE_TAG_INFO {
            FileAttributes: 0,
            ReparseTag: 0,
        };
        // SAFETY: a live handle and storage of the stated size.
        let ok = unsafe {
            GetFileInformationByHandleEx(
                file.as_raw_handle(),
                FileAttributeTagInfo,
                (&mut info as *mut FILE_ATTRIBUTE_TAG_INFO).cast(),
                std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
            )
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok((info.FileAttributes, info.ReparseTag))
    }

    /// The provider's pin state of an open placeholder, if it answers.
    fn pin_state(file: &File) -> Option<i32> {
        // CF_PLACEHOLDER_BASIC_INFO, with up to 4 KiB of file identity.
        let mut buffer = [0u64; 520];
        let mut returned = 0u32;
        // SAFETY: a live handle and aligned storage of the stated size.
        let result = unsafe {
            CfGetPlaceholderInfo(
                file.as_raw_handle(),
                CF_PLACEHOLDER_INFO_BASIC,
                buffer.as_mut_ptr().cast(),
                std::mem::size_of_val(&buffer) as u32,
                &mut returned,
            )
        };
        (result >= 0 && returned >= 4).then(|| buffer[0] as u32 as i32)
    }

    /// The ranges of `path` that are on the volume. Never downloads.
    pub fn on_disk_ranges(path: &Path) -> io::Result<Vec<FileRange>> {
        let file = open_query(path)?;
        on_disk_ranges_of(&file)
    }

    fn on_disk_ranges_of(file: &File) -> io::Result<Vec<FileRange>> {
        let mut ranges = Vec::new();
        let mut at = 0i64;
        loop {
            let mut buffer = [CF_FILE_RANGE {
                StartingOffset: 0,
                Length: 0,
            }; 256];
            let mut returned = 0u32;
            // SAFETY: a live handle and storage of the stated size.
            let result = unsafe {
                CfGetPlaceholderRangeInfo(
                    file.as_raw_handle(),
                    CF_PLACEHOLDER_RANGE_INFO_ONDISK,
                    at,
                    CF_EOF,
                    buffer.as_mut_ptr().cast(),
                    std::mem::size_of_val(&buffer) as u32,
                    &mut returned,
                )
            };
            if result == HANDLE_EOF {
                return Ok(ranges);
            }
            if result < 0 && result != MORE_DATA {
                return Err(hresult(result));
            }
            let count = returned as usize / std::mem::size_of::<CF_FILE_RANGE>();
            for range in &buffer[..count.min(buffer.len())] {
                ranges.push(FileRange {
                    offset: u64::try_from(range.StartingOffset).map_err(|_| {
                        io::Error::other("the Cloud Files API answered a negative offset")
                    })?,
                    length: u64::try_from(range.Length).map_err(|_| {
                        io::Error::other("the Cloud Files API answered a negative length")
                    })?,
                });
            }
            if result != MORE_DATA {
                return Ok(ranges);
            }
            let Some(last) = buffer[..count.min(buffer.len())].last() else {
                return Err(io::Error::other(
                    "the Cloud Files API asked for more room than one range takes",
                ));
            };
            let next = last.StartingOffset.saturating_add(last.Length);
            if next <= at {
                return Err(io::Error::other(
                    "the Cloud Files API answered ranges that do not advance",
                ));
            }
            at = next;
        }
    }

    /// What the Cloud Files API reports of the placeholder at `path`.
    /// Downloads nothing, and lists nothing that is not listed yet.
    pub fn report(path: &Path) -> io::Result<PlaceholderReport> {
        let file = open_query(path)?;
        let (attributes, tag) = attribute_tag(&file)?;
        let pin = pin_state(&file);
        if attributes & 0x10 != 0 {
            // SAFETY: a pure function of its two arguments.
            let state = unsafe { CfGetPlaceholderStateFromAttributeTag(attributes, tag) };
            return Ok(directory_report(state, pin));
        }
        let size = file.metadata()?.len();
        Ok(file_report(size, &on_disk_ranges_of(&file)?, pin))
    }

    /// Downloads every byte of the placeholder file at `path` that is not
    /// on the volume, from its provider, which has to be running.
    pub fn hydrate(path: &Path) -> io::Result<()> {
        let file = OpenOptions::new()
            .access_mode(HYDRATE_ACCESS)
            .share_mode(7)
            .custom_flags(HYDRATE_FLAGS)
            .open(path)?;
        // SAFETY: a live handle, the whole file, no overlapped I/O.
        let result = unsafe {
            CfHydratePlaceholder(
                file.as_raw_handle(),
                0,
                CF_EOF,
                CF_HYDRATE_FLAG_NONE,
                std::ptr::null_mut(),
            )
        };
        if result < 0 {
            return Err(hresult(result));
        }
        Ok(())
    }

    /// Lists the directory placeholder at `path`, which has its provider,
    /// where it is running, list what it holds. How many entries it has.
    pub fn populate(path: &Path) -> io::Result<usize> {
        let mut count = 0;
        for entry in std::fs::read_dir(path)? {
            entry?;
            count += 1;
        }
        Ok(count)
    }
}

#[cfg(windows)]
pub use native::{hydrate, on_disk_ranges, populate, report};

#[cfg(test)]
mod tests {
    use super::*;

    fn r(offset: u64, length: u64) -> FileRange {
        FileRange { offset, length }
    }

    #[test]
    fn ranges_are_merged_and_held_to_the_length() {
        assert_eq!(
            merge(100, &[r(50, 10), r(0, 10), r(5, 10), r(60, 0), r(90, 50)]),
            [r(0, 15), r(50, 10), r(90, 10)]
        );
        // Adjacent ranges are one; a range past the end is nothing.
        assert_eq!(merge(100, &[r(0, 10), r(10, 10), r(200, 5)]), [r(0, 20)]);
        assert_eq!(present_bytes(100, &[r(0, 60), r(40, 60)]), 100);
        assert_eq!(present_bytes(0, &[r(0, 60)]), 0);
    }

    #[test]
    fn what_is_missing_is_the_rest_of_the_file() {
        assert_eq!(
            missing_ranges(100, &[r(10, 10), r(50, 10)]),
            [r(0, 10), r(20, 30), r(60, 40)]
        );
        assert_eq!(missing_ranges(100, &[r(0, 100)]), []);
        assert_eq!(missing_ranges(100, &[]), [r(0, 100)]);
        assert_eq!(missing_ranges(0, &[]), []);
    }

    #[test]
    fn a_file_is_present_in_full_in_part_or_not_at_all() {
        let full = file_report(4096, &[r(0, 4096)], Some(1));
        assert_eq!(full.presence, Presence::Full);
        assert!(!full.needs_download());
        let partial = file_report(4096, &[r(0, 1024)], None);
        assert_eq!(partial.presence, Presence::Partial);
        assert_eq!(partial.missing_bytes, 3072);
        assert!(partial.needs_download());
        let none = file_report(4096, &[], None);
        assert_eq!(none.presence, Presence::NotPresent);
        assert_eq!(none.missing_bytes, 4096);
        // An empty file has nothing to download.
        assert_eq!(file_report(0, &[], None).presence, Presence::Full);
    }

    #[test]
    fn a_directory_not_listed_in_full_needs_its_provider() {
        let listed = directory_report(PLACEHOLDER_STATE_PLACEHOLDER, None);
        assert!(listed.directory && !listed.needs_download());
        let unlisted = directory_report(
            PLACEHOLDER_STATE_PLACEHOLDER | PLACEHOLDER_STATE_PARTIAL,
            None,
        );
        assert!(unlisted.unpopulated && unlisted.needs_download());
        assert_eq!(unlisted.presence, Presence::Partial);
    }

    #[test]
    fn a_provider_that_is_not_running_is_named() {
        // HRESULT_FROM_WIN32(ERROR_CLOUD_FILE_PROVIDER_NOT_RUNNING)
        assert!(describe_error(0x8007_016a_u32 as i32).contains("provider is not running"));
        assert!(describe_error(0x8007_0005_u32 as i32).contains("0x80070005"));
    }
}
