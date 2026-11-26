//! Read-only NTFS $LogFile restart-page checks. A clean-dismount flag is
//! useful evidence, not a complete log replay or TxF certificate.
//!
//! Both restart-page formats Windows writes are read: LFS 1.1 (what Windows
//! leaves after a clean dismount by default) and LFS 2.0 (what Windows 8 and
//! later write while a volume is mounted, and leave on a clean dismount when
//! the downgrade to 1.1 is turned off). The restart page header and restart
//! area have the same layout in both. The system and log page sizes are
//! taken from the restart page header (offsets 0x10 and 0x14), each a power
//! of two from 4 KiB to 64 KiB; the update sequence stride is always 512
//! bytes. Only the format is widened: every cleanliness requirement (a single
//! NTFS client, no client in use, the clean-dismount flag on both copies,
//! agreeing copies, a clean volume) is unchanged.
use crate::ntfs_inspect::{self, NtfsInspection};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};

/// The smallest and largest restart (system) and log page sizes admitted.
const MIN_PAGE: usize = 4096;
const MAX_PAGE: usize = 65536;
/// The update-sequence stride of LFS pages, whatever their size.
const SECTOR: usize = 512;
/// The restart-page versions Windows writes: (major, minor).
const VERSIONS: [(u16, u16); 2] = [(1, 1), (2, 0)];
const MAX_LOG_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct RestartPage {
    pub page_index: u8,
    pub raw_sha256: String,
    /// The LFS version of the restart page, "1.1" or "2.0".
    pub lfs_version: String,
    pub system_page_bytes: u32,
    pub log_page_bytes: u32,
    pub current_lsn: u64,
    pub revision_number: u32,
    pub flags: u16,
    pub log_clients: u16,
    pub client_name: String,
    pub log_file_bytes: u64,
    pub update_sequence_verified: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct RestartPair {
    pub profile: String,
    pub first: RestartPage,
    pub second: RestartPage,
    pub candidate_clean_dismount: bool,
    pub complete_log_recovery_proven: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct VerifiedRestart {
    inspection_fingerprint: String,
    pub log_file_sha256: String,
    pub log_file_bytes: u64,
    pub restart: RestartPair,
    pub complete_log_recovery_proven: bool,
}

impl VerifiedRestart {
    pub fn binds(&self, raw: &NtfsInspection) -> bool {
        serde_json::to_vec(raw)
            .ok()
            .is_some_and(|bytes| hex::encode(Sha256::digest(bytes)) == self.inspection_fingerprint)
    }

    #[cfg(windows)]
    pub fn binds_domain(&self, source: &ntfs_inspect::PagedInspection) -> bool {
        source
            .canonical_sha256()
            .is_ok_and(|hash| hash == self.inspection_fingerprint)
    }
}

fn u16le(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().unwrap())
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// A page size the restart page header states: a power of two from 4 KiB
/// to 64 KiB.
fn page_size(value: u32) -> Option<usize> {
    let value = usize::try_from(value).ok()?;
    (value.is_power_of_two() && (MIN_PAGE..=MAX_PAGE).contains(&value)).then_some(value)
}

/// The system (restart) page size the first restart page states, read
/// before its update sequence is applied: the field lies in the first
/// sector, ahead of any fixup.
fn stated_system_page(raw: &[u8]) -> Result<usize> {
    ensure!(
        raw.len() >= 0x20 && &raw[..4] == b"RSTR",
        "invalid LFS restart page"
    );
    page_size(u32le(raw, 0x10)).with_context(|| {
        format!(
            "unsupported LFS system page size {} (a power of two from 4 KiB to 64 KiB is read)",
            u32le(raw, 0x10)
        )
    })
}

fn parse_page(raw: &[u8], index: u8, log_bytes: u64) -> Result<RestartPage> {
    let system_page = stated_system_page(raw)?;
    ensure!(raw.len() == system_page, "invalid LFS restart page length");
    let mut page = raw.to_vec();
    let usa = usize::from(u16le(&page, 4));
    let count = usize::from(u16le(&page, 6));
    ensure!(
        usa >= 0x1e
            && usa.is_multiple_of(2)
            && count == system_page / SECTOR + 1
            && usa + count * 2 <= SECTOR - 2,
        "restart page update-sequence bounds differ"
    );
    let sequence = u16le(&page, usa);
    for sector in 0..system_page / SECTOR {
        let tail = (sector + 1) * SECTOR - 2;
        ensure!(
            u16le(&page, tail) == sequence,
            "torn LFS restart page sector"
        );
        let original = [
            page[usa + (sector + 1) * 2],
            page[usa + (sector + 1) * 2 + 1],
        ];
        page[tail..tail + 2].copy_from_slice(&original);
    }
    let log_page = page_size(u32le(&page, 0x14)).with_context(|| {
        format!(
            "unsupported LFS log page size {} (a power of two from 4 KiB to 64 KiB is read)",
            u32le(&page, 0x14)
        )
    })?;
    let version = (u16le(&page, 0x1c), u16le(&page, 0x1a));
    ensure!(
        VERSIONS.contains(&version),
        "unsupported LFS restart version {}.{} (1.1 and 2.0 are read)",
        version.0,
        version.1
    );
    ensure!(
        log_bytes.is_multiple_of(log_page as u64),
        "LFS log length {log_bytes} is not a whole number of {log_page}-byte log pages"
    );
    let area = usize::from(u16le(&page, 0x18));
    ensure!(
        area >= 0x30
            && area >= usa + count * 2
            && area.is_multiple_of(8)
            && area + 0x2c <= system_page,
        "restart area bounds differ"
    );
    let length = usize::from(u16le(&page, area + 0x14));
    let client_offset = usize::from(u16le(&page, area + 0x16));
    ensure!(
        length >= 0x28
            && area + length <= system_page
            && client_offset >= 0x2c
            && client_offset + 0xa0 <= length,
        "restart client array bounds differ"
    );
    let clients = u16le(&page, area + 8);
    let in_use = u16le(&page, area + 0xc);
    let flags = u16le(&page, area + 0xe);
    ensure!(
        clients == 1 && in_use == 0 && flags & !0x0003 == 0,
        "unsupported LFS client or restart flags"
    );
    let client = area + client_offset;
    let name_len = u32le(&page, client + 0x1c) as usize;
    ensure!(
        name_len == 8 && client + 0x20 + name_len <= area + length,
        "LFS client name bounds differ"
    );
    let name = String::from_utf16(
        &page[client + 0x20..client + 0x20 + name_len]
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes(pair.try_into().unwrap()))
            .collect::<Vec<_>>(),
    )?;
    ensure!(name == "NTFS", "unexpected LFS log client");
    let file_bytes = u64le(&page, area + 0x18);
    ensure!(
        file_bytes == log_bytes,
        "LFS restart length differs from stream"
    );
    Ok(RestartPage {
        page_index: index,
        raw_sha256: hex::encode(Sha256::digest(raw)),
        lfs_version: format!("{}.{}", version.0, version.1),
        system_page_bytes: system_page as u32,
        log_page_bytes: log_page as u32,
        current_lsn: u64le(&page, area),
        revision_number: u32le(&page, area + 0x28),
        flags,
        log_clients: clients,
        client_name: name,
        log_file_bytes: file_bytes,
        update_sequence_verified: true,
    })
}

pub fn parse_restart_pair(log: &[u8]) -> Result<RestartPair> {
    ensure!(
        log.len() as u64 <= MAX_LOG_BYTES,
        "unsupported LFS log length"
    );
    let system_page = stated_system_page(log)?;
    ensure!(log.len() >= 2 * system_page, "unsupported LFS log length");
    parse_restart_headers(&log[..2 * system_page], log.len() as u64)
}

/// The bytes of the log that hold both restart pages, as the first restart
/// page states them: twice its system page size.
pub fn restart_headers_bytes(first_page: &[u8]) -> Result<usize> {
    Ok(2 * stated_system_page(first_page)?)
}

fn parse_restart_headers(headers: &[u8], log_bytes: u64) -> Result<RestartPair> {
    let system_page = stated_system_page(headers)?;
    ensure!(
        headers.len() == 2 * system_page && log_bytes >= 2 * system_page as u64,
        "unsupported LFS log length"
    );
    let first = parse_page(&headers[..system_page], 0, log_bytes)?;
    let second = parse_page(&headers[system_page..], 1, log_bytes)?;
    ensure!(
        first.lfs_version == second.lfs_version
            && first.system_page_bytes == second.system_page_bytes
            && first.log_page_bytes == second.log_page_bytes,
        "restart copies disagree on the log format"
    );
    ensure!(
        first.current_lsn == second.current_lsn
            && first.revision_number == second.revision_number
            && first.flags == second.flags,
        "restart copies disagree on committed state"
    );
    let candidate_clean_dismount = first.flags & 2 != 0 && second.flags & 2 != 0;
    Ok(RestartPair {
        profile: format!(
            "LFS {} two {} KiB restart pages, {} KiB log pages",
            first.lfs_version,
            first.system_page_bytes / 1024,
            first.log_page_bytes / 1024
        ),
        first,
        second,
        candidate_clean_dismount,
        complete_log_recovery_proven: false,
    })
}

/// Re-read MFT record 2 and its DATA mapping from the supplied partition,
/// materialize the bounded logical stream, then parse both restart pages.
pub fn verify<R: Read + Seek>(reader: &mut R, raw: &NtfsInspection) -> Result<VerifiedRestart> {
    crate::ntfs_inspect::revalidate_mft_mapping(reader, raw)?;
    ensure!(
        raw.dirty == Some(false) && raw.volume_flags.is_some_and(|flags| flags & 1 == 0),
        "NTFS dirty state is unresolved"
    );
    let bytes = ntfs_inspect::read_plain_stream(reader, raw, 2, MAX_LOG_BYTES)
        .context("read frozen $LogFile through checked NTFS mapping")?;
    let restart = parse_restart_pair(&bytes)?;
    ensure!(
        restart.candidate_clean_dismount,
        "LFS restart pages lack clean-dismount flag"
    );
    Ok(VerifiedRestart {
        inspection_fingerprint: hex::encode(Sha256::digest(serde_json::to_vec(raw)?)),
        log_file_sha256: hex::encode(Sha256::digest(&bytes)),
        log_file_bytes: bytes.len() as u64,
        restart,
        complete_log_recovery_proven: false,
    })
}

/// Stream a completely mapped frozen LogFile through the same actual source
/// session as materialization. Only the two restart pages and one read window
/// remain in RAM; the complete logical digest and all restart checks remain.
#[cfg(windows)]
pub fn verify_domain<R: Read + Seek>(
    reader: &mut R,
    source: &ntfs_inspect::PagedInspection,
) -> Result<VerifiedRestart> {
    use ntfs_inspect::RootFileDomain;
    source.revalidate()?;
    ensure!(
        source.header().dirty == Some(false)
            && source
                .header()
                .volume_flags
                .is_some_and(|flags| flags & 1 == 0),
        "NTFS dirty state is unresolved"
    );
    let file = source
        .find_record(2, None)?
        .context("frozen LogFile absent")?;
    let mut streams = file.streams.iter().filter(|s| s.name_utf16.is_empty());
    let stream = streams.next().context("LogFile unnamed stream absent")?;
    ensure!(
        streams.next().is_none()
            && stream.logical_size >= 2 * MIN_PAGE as u64
            && stream.logical_size <= i64::MAX as u64
            && stream.logical_size.is_multiple_of(MIN_PAGE as u64),
        "unsupported LFS log length"
    );
    let expected = stream
        .logical_sha256
        .as_deref()
        .filter(|hash| n2r_win32::content_digest::is_hex(hash))
        .context("complete inspected LogFile logical digest absent")?;
    let length = stream.logical_size;
    let mut session =
        ntfs_inspect::PlainStreamRangeSession::open_named_domain(reader, source, 2, &[], length)?;
    let mut transfer = ntfs_inspect::StreamTransferBudget::new(length, length)?;
    let window = (u64::from(source.budget().page_bytes) / 4)
        .max(1)
        .min(ntfs_inspect::SESSION_READ_BYTES as u64);
    // The restart pages are at most two of the largest system pages; how
    // many bytes they take is known once the first page header is read.
    let _ram = source.lease_working_ram(window + 2 * MAX_PAGE as u64)?;
    let mut buffer = vec![0; usize::try_from(window)?];
    let mut prefix = vec![0u8; (2 * MAX_PAGE).min(usize::try_from(length)?)];
    let mut content = n2r_win32::content_digest::Hasher::new();
    let mut digest = Sha256::new();
    let mut offset = 0;
    while offset < length {
        let count = (length - offset).min(window) as usize;
        session.read_domain(reader, source, offset, &mut buffer[..count], &mut transfer)?;
        if offset < prefix.len() as u64 {
            let copied = count.min(prefix.len() - offset as usize);
            prefix[offset as usize..offset as usize + copied].copy_from_slice(&buffer[..copied]);
        }
        content.update(&buffer[..count]);
        digest.update(&buffer[..count]);
        offset += count as u64;
    }
    session.finish_domain(reader, source)?;
    ensure!(
        content.finish() == expected,
        "logical stream changed from inspection"
    );
    let headers = restart_headers_bytes(&prefix)?;
    ensure!(prefix.len() >= headers, "unsupported LFS log length");
    let restart = parse_restart_headers(&prefix[..headers], length)?;
    ensure!(
        restart.candidate_clean_dismount,
        "LFS restart pages lack clean-dismount flag"
    );
    source.revalidate()?;
    Ok(VerifiedRestart {
        inspection_fingerprint: source.canonical_sha256()?,
        log_file_sha256: hex::encode(digest.finalize()),
        log_file_bytes: length,
        restart,
        complete_log_recovery_proven: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One synthetic restart page as Windows lays it out: the restart area
    /// after the update sequence array, one client "NTFS", the update
    /// sequence applied with a 512-byte stride.
    struct Page {
        system: usize,
        log: usize,
        version: (u16, u16),
        flags: u16,
        in_use: u16,
        clients: u16,
        lsn: u64,
        log_bytes: u64,
    }

    impl Page {
        fn clean(system: usize, log: usize, version: (u16, u16)) -> Self {
            Self {
                system,
                log,
                version,
                flags: 2,
                in_use: 0,
                clients: 1,
                lsn: 0x1234_5678,
                log_bytes: (2 * system + 4 * log) as u64,
            }
        }

        fn bytes(&self) -> Vec<u8> {
            let mut page = vec![0u8; self.system];
            let usa = 0x1e;
            let count = self.system / SECTOR + 1;
            let area = (usa + count * 2).max(0x30).next_multiple_of(8);
            page[..4].copy_from_slice(b"RSTR");
            page[4..6].copy_from_slice(&(usa as u16).to_le_bytes());
            page[6..8].copy_from_slice(&(count as u16).to_le_bytes());
            page[0x10..0x14].copy_from_slice(&(self.system as u32).to_le_bytes());
            page[0x14..0x18].copy_from_slice(&(self.log as u32).to_le_bytes());
            page[0x18..0x1a].copy_from_slice(&(area as u16).to_le_bytes());
            page[0x1a..0x1c].copy_from_slice(&self.version.1.to_le_bytes());
            page[0x1c..0x1e].copy_from_slice(&self.version.0.to_le_bytes());
            page[area..area + 8].copy_from_slice(&self.lsn.to_le_bytes());
            page[area + 8..area + 0xa].copy_from_slice(&self.clients.to_le_bytes());
            page[area + 0xa..area + 0xc].copy_from_slice(&0xffffu16.to_le_bytes());
            page[area + 0xc..area + 0xe].copy_from_slice(&self.in_use.to_le_bytes());
            page[area + 0xe..area + 0x10].copy_from_slice(&self.flags.to_le_bytes());
            page[area + 0x14..area + 0x16].copy_from_slice(&(0x30u16 + 0xa0).to_le_bytes());
            page[area + 0x16..area + 0x18].copy_from_slice(&0x30u16.to_le_bytes());
            page[area + 0x18..area + 0x20].copy_from_slice(&self.log_bytes.to_le_bytes());
            page[area + 0x28..area + 0x2c].copy_from_slice(&7u32.to_le_bytes());
            let client = area + 0x30;
            page[client + 0x1c..client + 0x20].copy_from_slice(&8u32.to_le_bytes());
            for (at, unit) in "NTFS".encode_utf16().enumerate() {
                page[client + 0x20 + at * 2..client + 0x22 + at * 2]
                    .copy_from_slice(&unit.to_le_bytes());
            }
            let sequence = 0x0003u16.to_le_bytes();
            page[usa..usa + 2].copy_from_slice(&sequence);
            for sector in 0..self.system / SECTOR {
                let tail = (sector + 1) * SECTOR - 2;
                let saved = [page[tail], page[tail + 1]];
                page[usa + (sector + 1) * 2..usa + (sector + 1) * 2 + 2].copy_from_slice(&saved);
                page[tail..tail + 2].copy_from_slice(&sequence);
            }
            page
        }
    }

    fn log(first: &Page, second: &Page) -> Vec<u8> {
        let mut log = first.bytes();
        log.extend(second.bytes());
        log.resize(first.log_bytes as usize, 0xa5);
        log
    }

    fn same(page: &Page) -> Vec<u8> {
        log(page, page)
    }

    #[test]
    fn clean_restart_pages_of_both_versions_and_every_page_size_are_read() {
        for version in [(1, 1), (2, 0)] {
            for system in [4096, 8192, 16384, 32768, 65536] {
                for log_page in [4096, system] {
                    let page = Page::clean(system, log_page, version);
                    let pair = parse_restart_pair(&same(&page)).unwrap_or_else(|error| {
                        panic!("{version:?} {system} {log_page}: {error:#}")
                    });
                    assert!(pair.candidate_clean_dismount);
                    assert!(!pair.complete_log_recovery_proven);
                    for copy in [&pair.first, &pair.second] {
                        assert_eq!(copy.lfs_version, format!("{}.{}", version.0, version.1));
                        assert_eq!(copy.system_page_bytes as usize, system);
                        assert_eq!(copy.log_page_bytes as usize, log_page);
                        assert_eq!(copy.current_lsn, 0x1234_5678);
                        assert_eq!(copy.client_name, "NTFS");
                        assert!(copy.update_sequence_verified);
                    }
                    assert_eq!(pair.second.page_index, 1);
                    assert!(
                        pair.profile
                            .starts_with(&format!("LFS {}.{} ", version.0, version.1)),
                        "{}",
                        pair.profile
                    );
                    assert_eq!(restart_headers_bytes(&same(&page)).unwrap(), 2 * system);
                }
            }
        }
    }

    #[test]
    fn a_log_without_the_clean_dismount_flag_is_not_clean_in_either_version() {
        for version in [(1, 1), (2, 0)] {
            for system in [4096, 16384, 65536] {
                let mut page = Page::clean(system, 4096, version);
                page.flags = 0;
                let pair = parse_restart_pair(&same(&page)).unwrap();
                assert!(!pair.candidate_clean_dismount, "{version:?} {system}");
                // One copy clean and one not: the copies disagree.
                let clean = Page::clean(system, 4096, version);
                assert!(parse_restart_pair(&log(&clean, &page)).is_err());
            }
        }
    }

    #[test]
    fn a_client_in_use_or_unknown_flags_are_refused_in_either_version() {
        for version in [(1, 1), (2, 0)] {
            let mut in_use = Page::clean(8192, 8192, version);
            in_use.in_use = 1;
            assert!(parse_restart_pair(&same(&in_use)).is_err());
            let mut clients = Page::clean(8192, 8192, version);
            clients.clients = 2;
            assert!(parse_restart_pair(&same(&clients)).is_err());
            let mut flags = Page::clean(8192, 8192, version);
            flags.flags = 2 | 4;
            assert!(parse_restart_pair(&same(&flags)).is_err());
        }
    }

    #[test]
    fn other_versions_page_sizes_and_disagreeing_copies_are_refused() {
        for version in [(1, 0), (1, 2), (2, 1), (3, 0)] {
            let page = Page::clean(4096, 4096, version);
            assert!(parse_restart_pair(&same(&page)).is_err(), "{version:?}");
        }
        for (system, log_page) in [(2048, 4096), (4096, 2048), (4096, 6144), (131072, 4096)] {
            let mut page = Page::clean(4096, 4096, (2, 0));
            page.system = system;
            page.log = log_page;
            page.log_bytes = 4 * 131072;
            let bytes = if system.is_power_of_two() && (512..=65536).contains(&system) {
                same(&page)
            } else {
                // A page whose stated size cannot be laid out: the header
                // of a 4 KiB page claiming it.
                let mut good = Page::clean(4096, 4096, (2, 0));
                good.log_bytes = page.log_bytes;
                let mut bytes = same(&good);
                bytes[0x10..0x14].copy_from_slice(&(system as u32).to_le_bytes());
                bytes[0x14..0x18].copy_from_slice(&(log_page as u32).to_le_bytes());
                bytes
            };
            assert!(parse_restart_pair(&bytes).is_err(), "{system} {log_page}");
        }
        // Copies in different formats.
        let first = Page::clean(4096, 4096, (1, 1));
        let second = Page::clean(4096, 4096, (2, 0));
        assert!(parse_restart_pair(&log(&first, &second)).is_err());
        let mut second = Page::clean(4096, 8192, (1, 1));
        second.log_bytes = first.log_bytes;
        assert!(parse_restart_pair(&log(&first, &second)).is_err());
    }

    #[test]
    fn a_torn_sector_or_a_wrong_length_is_refused_at_every_page_size() {
        for system in [4096, 8192, 65536] {
            let page = Page::clean(system, system, (2, 0));
            for at in [SECTOR - 2, system - 2, system + SECTOR - 1, 2 * system - 1] {
                let mut bytes = same(&page);
                bytes[at] ^= 1;
                assert!(parse_restart_pair(&bytes).is_err(), "{system} {at}");
            }
            // The restart area states a length other than the stream's.
            let mut bytes = same(&page);
            bytes.extend(vec![0; system]);
            assert!(parse_restart_pair(&bytes).is_err(), "{system}");
            // A log that is not a whole number of log pages.
            let mut odd = Page::clean(system, 65536, (2, 0));
            odd.log_bytes = (2 * system + 4096) as u64;
            if !odd.log_bytes.is_multiple_of(65536) {
                assert!(parse_restart_pair(&same(&odd)).is_err(), "{system}");
            }
        }
    }
}
