//! Compare raw NTFS metadata with independently queried native file handles.
//! Diagnostic only: extent, namespace and preservation admission remain separate.
use crate::{
    ntfs_inspect::{FileInventory, NtfsInspection},
    ntfs_security::{self, Acl, Descriptor},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::attestation::{Report, Snapshot};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Serialize)]
pub struct FileComparison {
    pub record_number: u64,
    pub sequence_number: u16,
    pub matched: bool,
    pub issues: Vec<String>,
    pub raw_kernel_security_matched: Option<bool>,
    pub kernel_api_security_matched: Option<bool>,
}
#[derive(Debug, Serialize)]
pub struct Comparison {
    pub schema_version: u32,
    pub source_inspection_sha256: String,
    pub requested_files: usize,
    pub opened_files: usize,
    pub matched_files: usize,
    pub files: Vec<FileComparison>,
    pub all_requested_metadata_matched: bool,
    pub conversion_qualified: bool,
    pub native_streams: Option<crate::ntfs_stream_attestation::Reconciliation>,
}
fn acl_bytes(d: &Descriptor, a: &Acl) -> Result<Vec<Vec<u8>>> {
    let b = hex::decode(&d.relative_hex)?;
    a.aces
        .iter()
        .map(|ace| {
            Ok(b.get(
                ace.offset
                    ..ace
                        .offset
                        .checked_add(ace.length)
                        .context("ACE range overflow")?,
            )
            .context("ACE outside descriptor")?
            .to_vec())
        })
        .collect()
}
fn acl_equal(a: &Descriptor, ac: &Acl, b: &Descriptor, bc: &Acl) -> Result<bool> {
    Ok(
        ac.state == bc.state
            && ac.revision == bc.revision
            && acl_bytes(a, ac)? == acl_bytes(b, bc)?,
    )
}
/// Ignore placement offsets and padding. Preserve control, SID values, ACL
/// presence/null state, revision, ACE order and every complete ACE byte.
pub fn same_security(a: &[u8], b: &[u8]) -> Result<bool> {
    let a = ntfs_security::parse_descriptor(a)?;
    let b = ntfs_security::parse_descriptor(b)?;
    Ok(a.control == b.control
        && a.rm_control == b.rm_control
        && a.owner_sid == b.owner_sid
        && a.group_sid == b.group_sid
        && acl_equal(&a, &a.dacl, &b, &b.dacl)?
        && acl_equal(&a, &a.sacl, &b, &b.sacl)?)
}
fn buffer(s: &Snapshot, class: i32, length: usize) -> Result<&[u8]> {
    let q: Vec<_> = s.queries.iter().filter(|q| q.class == class).collect();
    ensure!(q.len() == 1, "native class {class} missing/duplicated");
    ensure!(
        q[0].native_error.is_none(),
        "native class {class}: error {:?}",
        q[0].native_error
    );
    ensure!(
        q[0].bytes.len() == length,
        "native class {class} length differs"
    );
    Ok(&q[0].bytes)
}
fn u64le(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}
fn u32le(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn check_snapshot(file: &FileInventory, serial: u64, sd: &[u8], s: &Snapshot) -> Result<()> {
    ensure!(s.queries.len() == 4, "unexpected native query count");
    let id = buffer(s, 18, 24)?;
    ensure!(
        u64le(id, 0) == serial
            && u64le(id, 8) == (file.record_number | u64::from(file.sequence_number) << 48)
            && u64le(id, 16) == 0,
        "native file or volume identity differs"
    );
    let basic = buffer(s, 0, 40)?;
    let si = file
        .standard_information
        .as_ref()
        .context("missing raw standard information")?;
    ensure!(
        [
            u64le(basic, 0),
            u64le(basic, 8),
            u64le(basic, 16),
            u64le(basic, 24)
        ] == [
            si.creation_time,
            si.access_time,
            si.modification_time,
            si.mft_change_time
        ],
        "native timestamps differ"
    );
    // NTFS $STANDARD_INFORMATION omits the directory bit and carries internal
    // index/view flags in the high nibble, outside Win32 FILE_ATTRIBUTE_*.
    let mut attrs = (si.file_attributes & 0x0fff_ffff) | if file.is_directory { 16 } else { 0 };
    if attrs == 0 {
        attrs = 128;
    }
    let tag = buffer(s, 9, 8)?;
    ensure!(
        u32le(basic, 32) == attrs && u32le(tag, 0) == attrs,
        "native attributes differ: expected {attrs:#x}, basic {:#x}, tag {:#x}",
        u32le(basic, 32),
        u32le(tag, 0)
    );
    let standard = buffer(s, 1, 24)?;
    ensure!(
        standard[20] == 0 && standard[21] == u8::from(file.is_directory),
        "native delete/directory state differs"
    );
    ensure!(
        u32le(standard, 16) == u32::from(file.hard_link_count),
        "native link count differs"
    );
    if let Some(stream) = file.streams.iter().find(|s| s.name_utf16.is_empty()) {
        ensure!(
            u64le(standard, 8) == stream.logical_size,
            "native unnamed stream EOF differs"
        );
    }
    ensure!(
        s.security_error.is_none(),
        "native security query failed: {:?}",
        s.security_error
    );
    ensure!(
        same_security(sd, &s.security)?,
        "native security semantics differ"
    );
    Ok(())
}

pub fn compare(
    raw: &NtfsInspection,
    inspection_sha256: &str,
    native: &Report,
) -> Result<Comparison> {
    native.request.validate()?;
    ensure!(
        matches!(native.schema_version, 2 | 3) && !native.conversion_qualified,
        "unexpected native report kind/claim"
    );
    ensure!(
        native.request.source_inspection_sha256 == inspection_sha256,
        "native/source report binding differs"
    );
    ensure!(
        native.request.ntfs_serial == raw.geometry.serial_number,
        "source serial differs"
    );
    ensure!(
        native.privileges_restored
            && native.write_protect_error_before == 19
            && native.write_protect_error_after == 19,
        "native protection or privilege restoration incomplete"
    );
    ensure!(
        native.privilege_states.len() == 2,
        "native privilege audit incomplete"
    );
    for (p, name) in native
        .privilege_states
        .iter()
        .zip(["SeBackupPrivilege", "SeSecurityPrivilege"])
    {
        ensure!(
            p.name == name
                && p.enabled == p.before | 2
                && (p.restored & !0x8000_0000) == (p.before & !0x8000_0000),
            "native privilege audit differs"
        );
    }
    ensure!(
        native.volume_extents_before == native.volume_extents_after
            && native.disk_attributes_before == native.disk_attributes_after
            && native.ntfs_data_before == native.ntfs_data_after,
        "native volume state changed"
    );
    let ext = &native.volume_extents_before;
    ensure!(
        ext.len() == 32
            && u32le(ext, 0) == 1
            && u32le(ext, 8) == native.request.disk_number
            && u64le(ext, 16) == native.request.partition_offset
            && u64le(ext, 24) == native.request.partition_length,
        "native disk route differs"
    );
    let attrs = &native.disk_attributes_before;
    ensure!(
        attrs.len() == 16 && u32le(attrs, 0) == 16 && u64le(attrs, 8) & 3 == 2,
        "native read-only attributes differ"
    );
    let data = &native.ntfs_data_before;
    ensure!(
        (96..=128).contains(&data.len())
            && u64le(data, 0) == raw.geometry.serial_number
            && u32le(data, 40) == u32::from(raw.geometry.bytes_per_sector)
            && u32le(data, 44) == raw.geometry.cluster_size
            && u32le(data, 48) == raw.geometry.file_record_size
            && u64le(data, 8) == raw.geometry.total_sectors
            && u64le(data, 16) == raw.geometry.total_clusters
            && u64le(data, 64) == raw.geometry.mft_lcn
            && u64le(data, 72) == raw.geometry.mftmirr_lcn,
        "native NTFS geometry differs"
    );
    ensure!(
        native.request.partition_length == raw.geometry.volume_size
            || native.request.partition_length
                == raw
                    .geometry
                    .volume_size
                    .checked_add(u64::from(raw.geometry.bytes_per_sector))
                    .context("source length overflow")?,
        "native/source partition length differs"
    );
    ensure!(
        raw.files.len() == native.request.files.len() && raw.files.len() == native.files.len(),
        "native inventory coverage differs"
    );
    let requested: BTreeSet<_> = native
        .request
        .files
        .iter()
        .map(|f| (f.record_number, f.sequence_number))
        .collect();
    let expected: BTreeSet<_> = raw
        .files
        .iter()
        .map(|f| (f.record_number, f.sequence_number))
        .collect();
    let observed: BTreeSet<_> = native
        .files
        .iter()
        .map(|f| (f.identity.record_number, f.identity.sequence_number))
        .collect();
    ensure!(
        requested == expected && observed == expected && observed.len() == native.files.len(),
        "missing, duplicate or unexpected file identity"
    );
    let security = raw
        .security_reconciliation
        .as_ref()
        .context("missing raw security reconciliation")?;
    ensure!(
        security.status == ntfs_security::Status::ConsistentRawModel,
        "raw security model inconsistent"
    );
    let bindings: BTreeMap<_, _> = security
        .bindings
        .iter()
        .map(|b| ((b.record_number, b.sequence_number), &b.descriptor_sha256))
        .collect();
    let descriptors: BTreeMap<_, _> = security
        .descriptors
        .iter()
        .map(|d| (&d.descriptor.sha256, &d.descriptor.relative_hex))
        .collect();
    let mut files = vec![];
    let mut opened = 0;
    for f in &raw.files {
        let obs = native
            .files
            .iter()
            .find(|o| {
                o.identity.record_number == f.record_number
                    && o.identity.sequence_number == f.sequence_number
            })
            .unwrap();
        let mut issues = vec![];
        let mut raw_kernel_security_matched = None;
        let mut kernel_api_security_matched = None;
        if let Some(e) = obs.open_error {
            ensure!(
                obs.before.is_none() && obs.after.is_none(),
                "failed open also carries snapshots"
            );
            issues.push(format!("OpenFileById refused with Windows error {e}"));
        } else {
            opened += 1;
            let before = obs
                .before
                .as_ref()
                .context("successful open missing before snapshot")?;
            let after = obs
                .after
                .as_ref()
                .context("successful open missing after snapshot")?;
            let hash = bindings
                .get(&(f.record_number, f.sequence_number))
                .context("missing descriptor binding")?;
            let sd = hex::decode(descriptors.get(hash).context("missing bound descriptor")?)?;
            match (&before.kernel_security, &after.kernel_security) {
                (Some(kb), Some(ka)) if kb.native_error.is_none() && ka.native_error.is_none() => {
                    raw_kernel_security_matched =
                        Some(same_security(&sd, &kb.bytes)? && same_security(&sd, &ka.bytes)?);
                    if raw_kernel_security_matched == Some(false) {
                        issues.push("raw/kernel security semantics differ".into());
                    }
                    if before.security_error.is_none() && after.security_error.is_none() {
                        kernel_api_security_matched = Some(
                            same_security(&before.security, &kb.bytes)?
                                && same_security(&after.security, &ka.bytes)?,
                        );
                    }
                }
                (Some(kb), Some(ka)) => issues.push(format!(
                    "kernel security query refused: before {:?}, after {:?}",
                    kb.native_error, ka.native_error
                )),
                _ => issues.push("kernel security query missing".into()),
            }
            for (name, snapshot) in [("before", before), ("after", after)] {
                if let Err(e) = check_snapshot(f, raw.geometry.serial_number, &sd, snapshot) {
                    issues.push(format!("{name}: {e:#}"));
                }
            }
            if before != after {
                issues.push("file metadata changed between native snapshots".into());
            }
        }
        files.push(FileComparison {
            record_number: f.record_number,
            sequence_number: f.sequence_number,
            matched: issues.is_empty(),
            issues,
            raw_kernel_security_matched,
            kernel_api_security_matched,
        });
    }
    let matched = files.iter().filter(|f| f.matched).count();
    let native_streams = if native.schema_version == 3 {
        Some(crate::ntfs_stream_attestation::reconcile(raw, native)?)
    } else {
        None
    };
    Ok(Comparison {
        schema_version: 1,
        source_inspection_sha256: inspection_sha256.into(),
        requested_files: files.len(),
        opened_files: opened,
        matched_files: matched,
        all_requested_metadata_matched: matched == files.len()
            && native_streams
                .as_ref()
                .is_none_or(|s| s.all_mappings_matched),
        files,
        conversion_qualified: false,
        native_streams,
    })
}
