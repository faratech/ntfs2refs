//! Capture exact natural-tree expectations before conversion and verify the
//! original partition through native ReFS after durable handoff.
use crate::{lab_tree_reconstruct::Request, ntfs_inspect, shadow_tree};
use anyhow::{Context, Result, ensure};
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
    #[serde(default)]
    logical_length: Option<u64>,
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
    let ordinary = request.schema_version == 3;
    let tree = if ordinary {
        shadow_tree::derive_ordinary(&raw)?
    } else {
        shadow_tree::derive(&raw)?
    };
    let inspection = crate::planner::Inspection {
        schema_version: 1,
        source: crate::block_io::SourceIdentity {
            path: source.binding().volume_path()?.into(),
            length,
            sha256: request.comparison.source_sha256.clone(),
        },
        filesystem: crate::planner::Filesystem::Ntfs(raw.clone()),
    };
    let pin = hex::encode(Sha256::digest(serde_json::to_vec(&inspection)?));
    if !ordinary {
        ensure!(
            pin == "23c1671ad98ec71bc0aaa8eebb17cd24330587c9fe3ea90173517a046f9baf5c"
                && tree.objects.len() == 8
                && tree.logical_bytes == 524288,
            "natural source metadata differs from the frozen enrollment"
        );
    }
    let mut objects = vec![];
    for o in tree.objects {
        let mut payload = vec![0; o.length as usize];
        if ordinary && !o.directory {
            payload = ntfs_inspect::read_plain_stream(
                &mut source,
                &raw,
                o.record_number,
                256 * 1024 * 1024,
            )?;
        } else if let Some(offset) = o.source_offset {
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
            payload_hex: if ordinary {
                String::new()
            } else {
                hex::encode(&payload)
            },
            payload_sha256: if ordinary && !o.directory {
                Some(hex::encode(Sha256::digest(&payload)))
            } else {
                o.sha256
            },
            logical_length: ordinary.then_some(o.length),
        });
    }
    ensure!(
        source.inspect(events)?.disk_attributes == 3 && source.native_write_bytes_requested == 0,
        "source capture lost exclusion"
    );
    Ok(Expectation {
        schema_version: if ordinary { 3 } else { 1 },
        source_sha256: request.comparison.source_sha256.clone(),
        canonical_inspection_sha256: pin,
        source: request.source.clone(),
        objects,
    })
}
impl Expectation {
    pub fn validate(&self, request: &Request) -> Result<()> {
        let ordinary = request.schema_version == 3;
        let hash_only = self.schema_version == 3;
        ensure!(
            (if ordinary {
                matches!(self.schema_version, 2 | 3)
            } else {
                self.schema_version == 1
            }) && self.source_sha256 == request.comparison.source_sha256
                && self.source == request.source
                && (ordinary
                    || self.canonical_inspection_sha256
                        == "23c1671ad98ec71bc0aaa8eebb17cd24330587c9fe3ea90173517a046f9baf5c")
                && (ordinary || self.objects.len() == 8),
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
            let length = if hash_only {
                ensure!(p.is_empty(), "hash-only expectation embeds payload bytes");
                o.logical_length.context("hash-only stream length absent")?
            } else {
                p.len() as u64
            };
            total = total
                .checked_add(usize::try_from(length)?)
                .ok_or_else(|| anyhow::anyhow!("payload overflow"))?;
            ensure!(
                if o.directory {
                    p.is_empty() && (!hash_only || (length == 0 && o.payload_sha256.is_none()))
                } else if hash_only {
                    o.payload_sha256.as_ref().is_some_and(|hash| {
                        hash.len() == 64
                            && hash
                                .bytes()
                                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    })
                } else {
                    (ordinary || (!p.is_empty() && p.len().is_multiple_of(65536)))
                        && (p.is_empty() && ordinary && o.payload_sha256.is_none()
                            || o.payload_sha256.as_deref()
                                == Some(&hex::encode(Sha256::digest(&p))))
                },
                "verification payload differs"
            );
        }
        ensure!(
            if ordinary {
                total <= 256 * 1024 * 1024
            } else {
                total == 524288
            },
            "verification payload size differs"
        );
        Ok(())
    }
    pub fn verify(&self, request: &Request) -> Result<shadow_native::Report> {
        request.validate()?;
        self.validate(request)?;
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
        let hash_only = self.schema_version == 3;
        for (o, p) in self.objects.iter().zip(&payload) {
            ensure!(
                hash_only
                    || o.directory
                    || o.payload_sha256.as_deref() == Some(&hex::encode(Sha256::digest(p))),
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
                expected_length: if hash_only && !o.directory {
                    o.logical_length
                } else {
                    None
                },
                expected_sha256: if hash_only && !o.directory {
                    o.payload_sha256.as_deref()
                } else {
                    None
                },
                source_offset: None,
            })
            .collect();
        let same = |a: &[u8], b: &[u8]| {
            crate::ntfs_attestation::same_security(a, b)
                .map_err(|e| std::io::Error::other(e.to_string()))
        };
        Ok(if request.schema_version == 3 {
            shadow_native::verify_converted_ordinary(request.source.clone(), &input, same)?
        } else {
            shadow_native::verify_converted(request.source.clone(), &input, same)?
        })
    }
}
