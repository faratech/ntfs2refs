//! Read-only first-profile NTFS $LogFile restart-page checks. A clean-dismount
//! flag is useful evidence, not a complete log replay or TxF certificate.
use crate::ntfs_inspect::{self, NtfsInspection};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Read, Seek};

const PAGE: usize = 4096;
const SECTOR: usize = 512;
const MAX_LOG_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Debug, Clone, Serialize)]
pub struct RestartPage {
    pub page_index: u8,
    pub raw_sha256: String,
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
    pub profile: &'static str,
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

fn parse_page(raw: &[u8], index: u8, log_bytes: u64) -> Result<RestartPage> {
    ensure!(
        raw.len() == PAGE && &raw[..4] == b"RSTR",
        "invalid LFS restart page"
    );
    let mut page = raw.to_vec();
    let usa = usize::from(u16le(&page, 4));
    let count = usize::from(u16le(&page, 6));
    ensure!(
        usa >= 0x1e && count == PAGE / SECTOR + 1 && usa + count * 2 <= PAGE,
        "restart page update-sequence bounds differ"
    );
    let sequence = u16le(&page, usa);
    for sector in 0..PAGE / SECTOR {
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
    ensure!(
        u32le(&page, 0x10) == PAGE as u32
            && u32le(&page, 0x14) == PAGE as u32
            && u16le(&page, 0x1a) == 1
            && u16le(&page, 0x1c) == 1,
        "unsupported LFS 1.1/4 KiB restart profile"
    );
    let area = usize::from(u16le(&page, 0x18));
    ensure!(
        area >= 0x30 && area.is_multiple_of(8) && area + 0x2c <= PAGE,
        "restart area bounds differ"
    );
    let length = usize::from(u16le(&page, area + 0x14));
    let client_offset = usize::from(u16le(&page, area + 0x16));
    ensure!(
        length >= 0x28
            && area + length <= PAGE
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
        (PAGE * 2..=MAX_LOG_BYTES as usize).contains(&log.len()) && log.len().is_multiple_of(PAGE),
        "unsupported LFS log length"
    );
    let first = parse_page(&log[..PAGE], 0, log.len() as u64)?;
    let second = parse_page(&log[PAGE..2 * PAGE], 1, log.len() as u64)?;
    ensure!(
        first.current_lsn == second.current_lsn
            && first.revision_number == second.revision_number
            && first.flags == second.flags,
        "restart copies disagree on committed state"
    );
    let candidate_clean_dismount = first.flags & 2 != 0 && second.flags & 2 != 0;
    Ok(RestartPair {
        profile: "LFS 1.1 two 4 KiB restart pages",
        first,
        second,
        candidate_clean_dismount,
        complete_log_recovery_proven: false,
    })
}

/// Re-read MFT record 2 and its DATA mapping from the supplied partition,
/// materialize the bounded logical stream, then parse both restart pages.
pub fn verify<R: Read + Seek>(reader: &mut R, raw: &NtfsInspection) -> Result<VerifiedRestart> {
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
