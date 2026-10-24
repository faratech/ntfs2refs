//! Native qualification for the bounded data-volume laboratory profile.
//! Payload writes are not exposed by this probe. Isolation persists on failure.
use crate::lab_reconstruct::{DurableIo, ReadSeek};
use anyhow::{Result, ensure};
use n2r_win32::{NativeEvent, OfflinePartition, PartitionSnapshot, layout::DiskBinding};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Seek, SeekFrom};

impl ReadSeek for OfflinePartition {
    fn byte_len(&mut self) -> io::Result<u64> {
        Ok(OfflinePartition::byte_len(self))
    }
}
impl DurableIo for OfflinePartition {
    fn sync_all(&mut self) -> io::Result<()> {
        OfflinePartition::sync_all(self)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    pub schema_version: u32,
    pub experiment_id: String,
    pub fixture_evidence_sha256: String,
    pub target: DiskBinding,
    pub shadow: DiskBinding,
    pub retained_offset: u64,
    pub source_retained_sha256: String,
    pub shadow_retained_sha256: String,
}

impl ProbeRequest {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1 && is_hex(&self.experiment_id, 32),
            "invalid probe identity"
        );
        for pin in [
            &self.fixture_evidence_sha256,
            &self.source_retained_sha256,
            &self.shadow_retained_sha256,
        ] {
            ensure!(is_hex(pin, 64), "invalid evidence pin");
        }
        self.target.validate()?;
        self.shadow.validate()?;
        ensure!(
            self.target.disk_number == 1 && self.shadow.disk_number >= 3,
            "initial probe only accepts enrolled target and new shadow routes"
        );
        ensure!(
            n2r_win32::layout::guid_bytes(&self.target.identity.disk_guid)?
                != n2r_win32::layout::guid_bytes(&self.shadow.identity.disk_guid)?
                && n2r_win32::layout::guid_bytes(&self.target.identity.partition_guid)?
                    != n2r_win32::layout::guid_bytes(&self.shadow.identity.partition_guid)?
                && n2r_win32::layout::guid_bytes(&self.target.volume_guid)?
                    != n2r_win32::layout::guid_bytes(&self.shadow.volume_guid)?,
            "target and shadow identities overlap"
        );
        ensure!(
            self.retained_offset >= 8 * 1024 * 1024 * 1024
                && self.retained_offset <= 9 * 1024 * 1024 * 1024 - 65536
                && self.retained_offset.is_multiple_of(4096),
            "retained range outside fixture window"
        );
        ensure!(
            self.source_retained_sha256 != self.shadow_retained_sha256,
            "A/B fixture hashes must differ"
        );
        Ok(())
    }
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Debug, Serialize)]
pub struct ProbeReport {
    pub schema_version: u32,
    pub kind: String,
    pub request: ProbeRequest,
    pub reopen: bool,
    pub success: bool,
    pub phase: String,
    pub error: Option<String>,
    pub target_snapshot: Option<PartitionSnapshot>,
    pub shadow_snapshot: Option<PartitionSnapshot>,
    pub target_retained_sha256: Option<String>,
    pub shadow_retained_sha256: Option<String>,
    pub target_partition_sha256: Option<String>,
    pub shadow_partition_sha256: Option<String>,
    pub target_flush_succeeded: bool,
    pub target_bytes_read: u64,
    pub shadow_bytes_read: u64,
    pub payload_write_requests_issued: bool,
    pub conversion_qualified: bool,
    pub events: Vec<NativeEvent>,
}

fn hash_range(stream: &mut OfflinePartition, at: u64, length: u64) -> Result<String> {
    stream.seek(SeekFrom::Start(at))?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut left = length;
    while left != 0 {
        let count = left.min(buffer.len() as u64) as usize;
        stream.read_exact(&mut buffer[..count])?;
        hash.update(&buffer[..count]);
        left -= count as u64;
    }
    Ok(hex::encode(hash.finalize()))
}

/// The report survives ordinary native failure. A crash can still precede it;
/// the caller must persist intent first and preserve the isolated branch.
pub fn probe(request: ProbeRequest, reopen: bool, whole_partition: bool) -> ProbeReport {
    let mut report = ProbeReport {
        schema_version: 1,
        kind: "native-partition-isolation-probe".into(),
        request,
        reopen,
        success: false,
        phase: "validate".into(),
        error: None,
        target_snapshot: None,
        shadow_snapshot: None,
        target_retained_sha256: None,
        shadow_retained_sha256: None,
        target_partition_sha256: None,
        shadow_partition_sha256: None,
        target_flush_succeeded: false,
        target_bytes_read: 0,
        shadow_bytes_read: 0,
        payload_write_requests_issued: false,
        conversion_qualified: false,
        events: Vec::new(),
    };
    let result = (|| -> Result<()> {
        report.request.validate()?;
        report.phase = "target-isolation".into();
        let mut target = if reopen {
            OfflinePartition::reopen(report.request.target.clone(), false, &mut report.events)?
        } else {
            OfflinePartition::isolate(report.request.target.clone(), false, &mut report.events)?
        };
        report.target_snapshot = Some(target.inspect(&mut report.events)?);
        report.phase = "shadow-isolation".into();
        let mut shadow = if reopen {
            OfflinePartition::reopen(report.request.shadow.clone(), true, &mut report.events)?
        } else {
            OfflinePartition::isolate(report.request.shadow.clone(), true, &mut report.events)?
        };
        report.shadow_snapshot = Some(shadow.inspect(&mut report.events)?);
        report.phase = "raw-retained-proof".into();
        let checks = (|| -> Result<()> {
            let a = hash_range(&mut target, report.request.retained_offset, 65536)?;
            report.target_retained_sha256 = Some(a.clone());
            ensure!(
                a == report.request.source_retained_sha256,
                "raw source A differs"
            );
            let b = hash_range(&mut shadow, report.request.retained_offset, 65536)?;
            report.shadow_retained_sha256 = Some(b.clone());
            ensure!(
                b == report.request.shadow_retained_sha256,
                "raw shadow B differs"
            );
            report.phase = "target-flush".into();
            target.sync_all()?;
            report.target_flush_succeeded = true;
            if whole_partition {
                report.phase = "full-partition-pins".into();
                let target_len = target.byte_len();
                let shadow_len = shadow.byte_len();
                report.target_partition_sha256 = Some(hash_range(&mut target, 0, target_len)?);
                report.shadow_partition_sha256 = Some(hash_range(&mut shadow, 0, shadow_len)?);
            }
            report.phase = "post-read-isolation".into();
            report.target_snapshot = Some(target.inspect(&mut report.events)?);
            report.shadow_snapshot = Some(shadow.inspect(&mut report.events)?);
            ensure!(
                report.target_snapshot.as_ref().unwrap().disk_attributes == 1
                    && report.shadow_snapshot.as_ref().unwrap().disk_attributes == 3,
                "isolation changed during reads"
            );
            Ok(())
        })();
        report.target_bytes_read = target.native_bytes_read;
        report.shadow_bytes_read = shadow.native_bytes_read;
        checks?;
        report.phase = "complete-disks-remain-offline".into();
        report.success = true;
        Ok(())
    })();
    if let Err(error) = result {
        report.error = Some(format!("{error:#}"));
    }
    report
}
