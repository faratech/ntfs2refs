//! Capture exact natural-tree expectations before conversion and verify the
//! original partition through native ReFS after durable handoff.
use crate::{
    lab_tree_reconstruct::{Request, SOURCE_SHA256},
    ntfs_inspect, shadow_tree,
};
use anyhow::{Result, ensure};
use n2r_win32::{NativeEvent, OfflinePartition, shadow_native};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Object {
    path: Vec<String>,
    directory: bool,
    times: [u64; 4],
    attributes: u32,
    security_hex: String,
    payload_hex: String,
    payload_sha256: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Expectation {
    schema_version: u32,
    source_sha256: String,
    canonical_inspection_sha256: String,
    source: n2r_win32::layout::DiskBinding,
    objects: Vec<Object>,
}
pub fn capture(request: &Request, events: &mut Vec<NativeEvent>) -> Result<Expectation> {
    request.validate()?;
    let mut source = OfflinePartition::reopen(request.source.clone(), true, events)?;
    let length = source.byte_len();
    let raw = ntfs_inspect::inspect(&mut source, length)?;
    let tree = shadow_tree::derive(&raw)?;
    let inspection = crate::planner::Inspection {
        schema_version: 1,
        source: crate::block_io::SourceIdentity {
            path: source.binding().volume_path()?.into(),
            length,
            sha256: SOURCE_SHA256.into(),
        },
        filesystem: crate::planner::Filesystem::Ntfs(raw),
    };
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(&inspection)?));
    ensure!(
        pin == "23c1671ad98ec71bc0aaa8eebb17cd24330587c9fe3ea90173517a046f9baf5c"
            && tree.objects.len() == 8
            && tree.logical_bytes == 524288,
        "natural source metadata differs from the frozen enrollment"
    );
    let mut objects = vec![];
    for o in tree.objects {
        let mut payload = vec![0; o.length as usize];
        if let Some(offset) = o.source_offset {
            source.seek(SeekFrom::Start(offset))?;
            source.read_exact(&mut payload)?;
            ensure!(
                o.sha256.as_deref() == Some(&hex::encode(Sha256::digest(&payload))),
                "source payload differs"
            );
        }
        objects.push(Object {
            path: o.path,
            directory: o.directory,
            times: o.stored_times,
            attributes: o.attributes,
            security_hex: hex::encode(o.security),
            payload_hex: hex::encode(payload),
            payload_sha256: o.sha256,
        });
    }
    ensure!(
        source.inspect(events)?.disk_attributes == 3 && source.native_write_bytes_requested == 0,
        "source capture lost exclusion"
    );
    Ok(Expectation {
        schema_version: 1,
        source_sha256: SOURCE_SHA256.into(),
        canonical_inspection_sha256: pin,
        source: request.source.clone(),
        objects,
    })
}
impl Expectation {
    pub fn validate(&self, request: &Request) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && self.source_sha256 == SOURCE_SHA256
                && self.source == request.source
                && self.canonical_inspection_sha256
                    == "23c1671ad98ec71bc0aaa8eebb17cd24330587c9fe3ea90173517a046f9baf5c"
                && self.objects.len() == 8,
            "verification expectation binding differs"
        );
        let mut total = 0usize;
        let mut paths = std::collections::BTreeSet::new();
        for (index, o) in self.objects.iter().enumerate() {
            ensure!(
                paths.insert(o.path.clone())
                    && o.path.len() <= 16
                    && (index != 0 || (o.path.is_empty() && o.directory))
                    && (index == 0 || !o.path.is_empty())
                    && o.path.iter().all(|s| !s.is_empty()
                        && s.len() <= 100
                        && !s.ends_with([' ', '.'])
                        && s.bytes()
                            .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
                    && o.times.iter().all(|t| *t > 0 && *t < i64::MAX as u64)
                    && o.attributes & !0x2037 == 0
                    && (o.attributes & 16 != 0) == o.directory,
                "verification path or metadata profile differs"
            );
            let sd = hex::decode(&o.security_hex)?;
            ensure!(
                crate::ntfs_attestation::same_security(&sd, &sd)?,
                "invalid security descriptor"
            );
            let p = hex::decode(&o.payload_hex)?;
            total = total
                .checked_add(p.len())
                .ok_or_else(|| anyhow::anyhow!("payload overflow"))?;
            ensure!(
                if o.directory {
                    p.is_empty()
                } else {
                    !p.is_empty()
                        && p.len().is_multiple_of(65536)
                        && o.payload_sha256.as_deref() == Some(&hex::encode(Sha256::digest(&p)))
                },
                "verification payload differs"
            );
        }
        ensure!(total == 524288, "verification payload size differs");
        Ok(())
    }
    pub fn verify(&self, request: &Request) -> Result<shadow_native::Report> {
        request.validate()?;
        self.validate(request)?;
        ensure!(
            self.schema_version == 1
                && self.source_sha256 == SOURCE_SHA256
                && self.source == request.source
                && self.canonical_inspection_sha256
                    == "23c1671ad98ec71bc0aaa8eebb17cd24330587c9fe3ea90173517a046f9baf5c"
                && self.objects.len() == 8,
            "verification expectation binding differs"
        );
        let security: Vec<_> = self
            .objects
            .iter()
            .map(|o| hex::decode(&o.security_hex))
            .collect::<Result<_, _>>()?;
        let payload: Vec<_> = self
            .objects
            .iter()
            .map(|o| hex::decode(&o.payload_hex))
            .collect::<Result<_, _>>()?;
        ensure!(
            payload.iter().map(Vec::len).sum::<usize>() == 524288,
            "verification payload size differs"
        );
        for (o, p) in self.objects.iter().zip(&payload) {
            ensure!(
                o.directory || o.payload_sha256.as_deref() == Some(&hex::encode(Sha256::digest(p))),
                "verification payload hash differs"
            );
        }
        let input: Vec<_> = self
            .objects
            .iter()
            .enumerate()
            .map(|(i, o)| shadow_native::Input {
                components: &o.path,
                directory: o.directory,
                times: o.times,
                attributes: o.attributes,
                security: &security[i],
                payload: &payload[i],
                source_offset: None,
            })
            .collect();
        Ok(shadow_native::verify_converted(
            request.source.clone(),
            &input,
            |a, b| {
                crate::ntfs_attestation::same_security(a, b)
                    .map_err(|e| std::io::Error::other(e.to_string()))
            },
        )?)
    }
}
