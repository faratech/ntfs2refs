//! Disk quotas of a data volume, which a conversion records and does not
//! carry over.
//!
//! ReFS has no NTFS quotas: there is nowhere on the target to put a limit
//! or a user's usage. A data volume whose `$Extend\$Quota` indexes hold
//! anything besides NTFS's unlimited defaults (quota management switched
//! on, limits, or entries for users) converts: both indexes are walked
//! completely, as NTFS holds them, and every entry is kept in the run's
//! records, so that the limits can be set again elsewhere. The check and
//! the run say so before the conversion's question. A Windows boot volume
//! still needs the defaults with quota management off.
//!
//! The listing the lab compares (`lab-volume-manifest`) has no quota in
//! it, so the converted volume lists exactly as the source did.

use crate::ntfs_inspect::record_store::SortedRecordStore;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{BufWriter, Write},
    path::Path,
};

/// The two indexes of `$Extend\$Quota`: by owner SID, and by owner ID.
pub(crate) const INDEX_NAMES: [&str; 2] = ["$O", "$Q"];

/// Where a run lists the quota entries it does not carry over, in the
/// folder of its internal-index evidence.
pub(crate) const RECORDS_FILE: &str = "quotas-not-carried-over.jsonl";

/// The record kind of the file's first line.
const KIND: &str = "quotas-not-carried-over-v1";

/// What a data volume's quota state was, in numbers, once it is archived.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct QuotasNotCarried {
    /// Entries of the `$Q` index: the defaults (owner ID 1) and one per owner.
    pub quota_entries: u64,
    /// Entries of the `$O` index: one per owner SID.
    pub owners: u64,
    /// Whether NTFS's defaults say that quotas are tracked or enforced.
    pub tracked_or_enforced: bool,
    /// The archive, with its sha256.
    pub records_sha256: String,
}

/// An index entry as the internal-index walk stored it.
#[derive(Deserialize)]
struct StoredEntry {
    key_hex: String,
    value_hex: String,
}

/// One `$Q` value (QUOTA_USER_DATA) in words; `None` for one shorter than
/// its fixed part.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct QuotaValue {
    pub version: u32,
    pub flags: u32,
    pub bytes_used: u64,
    pub change_time: u64,
    pub warning_limit: i64,
    pub hard_limit: i64,
    pub exceeded_time: u64,
    pub sid_hex: String,
}

pub(crate) fn quota_value(value: &[u8]) -> Option<QuotaValue> {
    let u32_at = |at: usize| Some(u32::from_le_bytes(value.get(at..at + 4)?.try_into().ok()?));
    let u64_at = |at: usize| Some(u64::from_le_bytes(value.get(at..at + 8)?.try_into().ok()?));
    Some(QuotaValue {
        version: u32_at(0)?,
        flags: u32_at(4)?,
        bytes_used: u64_at(8)?,
        change_time: u64_at(16)?,
        warning_limit: u64_at(24)? as i64,
        hard_limit: u64_at(32)? as i64,
        exceeded_time: u64_at(40)?,
        sid_hex: hex::encode(value.get(48..)?),
    })
}

/// Tracking and enforcement (enabled or requested) and the event logging
/// of the defaults entry: what `fsutil quota track` and `enforce` set.
const TRACKED_OR_ENFORCED: u32 = 0x10 | 0x20 | 0x40 | 0x80 | 0x100;

/// Writes every entry of both quota indexes, as NTFS held them and in
/// words, to `path` (one JSON object per line, after a header), and says
/// what was archived. `owners` is the `$O` index's entry store, `ids` the
/// `$Q` index's.
pub(crate) fn archive(
    path: &Path,
    source_inspection_sha256: &str,
    owners: &SortedRecordStore,
    ids: &SortedRecordStore,
) -> Result<QuotasNotCarried> {
    ensure!(
        !path.exists(),
        "the quota record {} is there already",
        path.display()
    );
    let mut tracked_or_enforced = false;
    let mut out = BufWriter::new(
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .with_context(|| format!("creating the quota record {}", path.display()))?,
    );
    serde_json::to_writer(
        &mut out,
        &serde_json::json!({
            "kind": KIND,
            "source_inspection_sha256": source_inspection_sha256,
            "owners": owners.len(),
            "quota_entries": ids.len(),
            "target_has_quotas": false,
            "policy": "ReFS has no NTFS quotas: every entry of $Extend\\$Quota's $O and $Q indexes is listed here, as NTFS held it, and not carried over",
        }),
    )?;
    out.write_all(b"\n")?;
    for (name, store) in [("$O", owners), ("$Q", ids)] {
        for ordinal in 0..store.len() {
            let entry: StoredEntry = store.get(ordinal)?;
            let words = if name == "$Q" {
                let value = hex::decode(&entry.value_hex)?;
                let key = hex::decode(&entry.key_hex)?;
                let words = quota_value(&value);
                // The defaults entry is owner ID 1.
                if key == 1u32.to_le_bytes() {
                    tracked_or_enforced |= words
                        .as_ref()
                        .is_some_and(|w| w.flags & TRACKED_OR_ENFORCED != 0);
                }
                serde_json::to_value(words)?
            } else {
                serde_json::Value::Null
            };
            serde_json::to_writer(
                &mut out,
                &serde_json::json!({
                    "index": name, "key_hex": entry.key_hex, "value_hex": entry.value_hex,
                    "quota": words,
                }),
            )?;
            out.write_all(b"\n")?;
        }
    }
    let file = out.into_inner().map_err(|error| error.into_error())?;
    file.sync_all()?;
    drop(file);
    Ok(QuotasNotCarried {
        quota_entries: ids.len(),
        owners: owners.len(),
        tracked_or_enforced,
        records_sha256: file_sha256(path)?,
    })
}

fn file_sha256(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0u8; 1 << 16];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(hex::encode(digest.finalize()))
}

/// What a run and a check say of the quotas they leave behind, before the
/// conversion's question.
pub(crate) fn note(quotas: &QuotasNotCarried) -> String {
    format!(
        "Disk quotas are set on this volume ({}{} quota entr{}, for {} owner(s)). ReFS has no NTFS quotas: they are not carried over, and the converted volume has no limits. Every entry is kept in the run's records (internal-indexes\\{RECORDS_FILE} in its working directory), so the limits can be set again elsewhere.",
        if quotas.tracked_or_enforced {
            "quota management switched on, "
        } else {
            ""
        },
        quotas.quota_entries,
        if quotas.quota_entries == 1 {
            "y"
        } else {
            "ies"
        },
        quotas.owners,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_quota_value_reads_as_ntfs_stores_it() {
        let sid = hex::decode("01020000000000052000000020020000").unwrap();
        let mut value = vec![0; 48];
        value[..4].copy_from_slice(&2u32.to_le_bytes());
        value[4..8].copy_from_slice(&0x21u32.to_le_bytes());
        value[8..16].copy_from_slice(&4096u64.to_le_bytes());
        value[24..32].copy_from_slice(&100_000_000u64.to_le_bytes());
        value[32..40].copy_from_slice(&200_000_000u64.to_le_bytes());
        value.extend(&sid);
        let words = quota_value(&value).unwrap();
        assert_eq!(words.version, 2);
        assert_eq!(words.flags, 0x21);
        assert_eq!(words.bytes_used, 4096);
        assert_eq!(words.warning_limit, 100_000_000);
        assert_eq!(words.hard_limit, 200_000_000);
        assert_eq!(words.sid_hex, hex::encode(&sid));
        assert!(words.flags & TRACKED_OR_ENFORCED != 0);
        // Unlimited defaults, nothing tracked: -1 limits and flags 1.
        let mut defaults = vec![0; 48];
        defaults[..4].copy_from_slice(&2u32.to_le_bytes());
        defaults[4..8].copy_from_slice(&1u32.to_le_bytes());
        defaults[24..40].fill(0xff);
        let words = quota_value(&defaults).unwrap();
        assert_eq!((words.warning_limit, words.hard_limit), (-1, -1));
        assert!(words.flags & TRACKED_OR_ENFORCED == 0);
        assert_eq!(quota_value(&defaults[..47]), None);
    }

    #[test]
    fn the_note_says_what_is_left_behind_and_where_it_is_listed() {
        let said = note(&QuotasNotCarried {
            quota_entries: 2,
            owners: 1,
            tracked_or_enforced: true,
            records_sha256: String::new(),
        });
        assert!(said.starts_with("Disk quotas are set on this volume (quota management switched on, 2 quota entries, for 1 owner(s))."), "{said}");
        assert!(said.contains("not carried over"), "{said}");
        assert!(said.contains(RECORDS_FILE), "{said}");
    }
}
