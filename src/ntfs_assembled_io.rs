//! Actual MFT reads and conservation for the bounded ordinary DATA-list profile.
use super::*;
use crate::ntfs_attribute_list::{self as lists, Assembly, RecordEvidence};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct MftContext<'a> {
    pub data: &'a Attribute,
    pub bitmap: &'a [u8],
    pub geometry: &'a NtfsGeometry,
    pub record_count: u64,
}

fn candidate(number: u64, record: &Record) -> bool {
    number >= 16
        && record.base == 0
        && record.flags == 1
        && record.links == 1
        && record.attributes.iter().all(|a| {
            let a = &a.report;
            a.name_utf16.is_empty()
                && a.flags == 0
                && a.compression_unit == 0
                && match a.type_code {
                    0x10 | 0x30 | 0x50 => a.resident,
                    0x20 => a.lowest_vcn == 0,
                    0x80 => !a.resident && a.lowest_vcn == 0,
                    _ => false,
                }
        })
        && [0x10, 0x20, 0x30, 0x80].iter().all(|kind| {
            record
                .attributes
                .iter()
                .filter(|a| a.report.type_code == *kind)
                .count()
                == 1
        })
}

// Broader ordinary-file profile. Actual list/record ownership and complete
// stream coverage are established by assemble_streams, never by this filter.
fn stream_candidate(number: u64, record: &Record) -> bool {
    number >= 16
        && record.base == 0
        && record.flags == 1
        && record.links > 0
        && record.attributes.iter().all(|attribute| {
            let a = &attribute.report;
            a.flags == 0
                && a.compression_unit == 0
                && match a.type_code {
                    0x10 | 0x30 | 0x50 => a.resident && a.name_utf16.is_empty(),
                    0x20 => a.name_utf16.is_empty() && a.lowest_vcn == 0,
                    0x80 => true,
                    _ => false,
                }
        })
        && record
            .attributes
            .iter()
            .filter(|a| a.report.type_code == 0x20)
            .count()
            == 1
}

pub(super) fn evidence(number: u64, raw: &[u8], record: &Record) -> RecordEvidence {
    RecordEvidence {
        record_number: number,
        sequence_number: record.sequence,
        hard_link_count: record.links,
        is_directory: record.flags & 2 != 0,
        base_file_reference: record.base,
        raw_record_sha256: hex::encode(Sha256::digest(raw)),
        attributes: record.attributes.iter().map(|a| a.report.clone()).collect(),
    }
}

impl MftContext<'_> {
    /// Unsupported forms keep their existing diagnostic/refusal path. Once a
    /// supported shape is selected, malformed/missing references are errors;
    /// no partial canonical stream can be returned or hashed.
    pub(super) fn resolve<R: Read + Seek>(
        &self,
        reader: &mut R,
        number: u64,
        raw: &[u8],
        record: &mut Record,
    ) -> Result<Option<Assembly>> {
        let legacy_base = candidate(number, record);
        if !legacy_base && !stream_candidate(number, record) {
            return Ok(None);
        }
        ensure!(
            number < self.record_count
                && self
                    .bitmap
                    .get(number as usize / 8)
                    .is_some_and(|b| b & (1 << (number % 8)) != 0),
            "attribute-list base is not currently allocated in the MFT bitmap"
        );
        let list = unnamed(record, 0x20)?;
        lists::validate_list_storage(&list.report, self.geometry)?;
        let value =
            read_small_attribute(reader, list, self.geometry, lists::MAX_LIST_BYTES as u64)?;
        // A legacy-looking base can own named streams or resident metadata in
        // extension records. Discover the complete set before choosing the
        // assembly profile; the base record alone cannot decide that.
        let entries = lists::parse_stream_entries(&value)?;
        let references: BTreeSet<_> = entries
            .iter()
            .filter(|e| e.record_number != number)
            .map(|e| (e.record_number, e.sequence_number))
            .collect();
        ensure!(
            references.len() <= 1024,
            "attribute-list extension budget exceeded"
        );
        let mut extensions = Vec::new();
        let mut resident_values = BTreeMap::new();
        for attribute in &record.attributes {
            if let Some(bytes) = &attribute.resident_value {
                resident_values.insert(
                    (number, record.sequence, attribute.report.instance),
                    bytes.clone(),
                );
            }
        }
        let mut runs = record
            .attributes
            .iter()
            .filter(|a| a.report.type_code == 0x80)
            .map(|a| a.report.extents.len())
            .sum::<usize>();
        ensure!(runs <= 1024, "assembled DATA run budget exceeded");
        for (extension, sequence) in references {
            ensure!(
                extension < self.record_count
                    && self
                        .bitmap
                        .get(extension as usize / 8)
                        .is_some_and(|b| b & (1 << (extension % 8)) != 0),
                "attribute list references an unallocated/out-of-range MFT record"
            );
            let mut bytes = vec![0; self.geometry.file_record_size as usize];
            read_attribute_range(
                reader,
                self.data,
                extension
                    .checked_mul(u64::from(self.geometry.file_record_size))
                    .context("extension offset overflow")?,
                &mut bytes,
                self.geometry,
            )?;
            let parsed = parse_record(bytes.clone(), self.geometry)?;
            ensure!(
                parsed.flags == 1 && parsed.sequence == sequence,
                "attribute-list extension is not the current allocated file segment"
            );
            runs = parsed
                .attributes
                .iter()
                .filter(|a| a.report.type_code == 0x80)
                .try_fold(runs, |n, a| n.checked_add(a.report.extents.len()))
                .context("assembled DATA run count overflow")?;
            ensure!(runs <= 1024, "assembled DATA run budget exceeded");
            for attribute in &parsed.attributes {
                if let Some(bytes) = &attribute.resident_value {
                    ensure!(
                        resident_values
                            .insert(
                                (extension, parsed.sequence, attribute.report.instance),
                                bytes.clone(),
                            )
                            .is_none(),
                        "duplicate resident attribute origin"
                    );
                }
            }
            extensions.push(evidence(extension, &bytes, &parsed));
        }
        let legacy = legacy_base
            && entries.iter().all(|entry| entry.name_utf16.is_empty())
            && !extensions.is_empty()
            && extensions.iter().all(|record| {
                record.attributes.len() == 1
                    && record.attributes[0].type_code == 0x80
                    && record.attributes[0].name_utf16.is_empty()
                    && !record.attributes[0].resident
                    && record.attributes[0].lowest_vcn > 0
            });
        let (canonical, assembly) = if legacy {
            lists::assemble(
                evidence(number, raw, record),
                extensions,
                &value,
                self.geometry,
            )?
        } else {
            lists::assemble_streams(
                evidence(number, raw, record),
                extensions,
                &value,
                self.geometry,
            )?
        };
        if let Some(origins) = &assembly.canonical_origins {
            ensure!(
                origins.len() == canonical.len(),
                "canonical attribute origins are incomplete"
            );
            record.attributes = canonical
                .into_iter()
                .zip(origins)
                .map(|(report, origin)| -> Result<Attribute> {
                    let resident_value = if report.resident {
                        let bytes = resident_values
                            .get(&(
                                origin.record_number,
                                origin.sequence_number,
                                origin.instance,
                            ))
                            .context("canonical resident attribute has no physical bytes")?;
                        ensure!(
                            bytes.len() as u64 == report.logical_size
                                && report.resident_sha256.as_deref().is_some_and(|hash| {
                                    lists::resident_digest_matches(hash, bytes)
                                }),
                            "canonical resident bytes differ from their raw origin"
                        );
                        Some(bytes.clone())
                    } else {
                        None
                    };
                    Ok(Attribute {
                        report,
                        resident_value,
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            return Ok(Some(assembly));
        }
        let old = std::mem::take(&mut record.attributes);
        record.attributes = canonical
            .into_iter()
            .map(|report| {
                let resident_value = old
                    .iter()
                    .find(|a| a.report.instance == report.instance)
                    .and_then(|a| a.resident_value.clone());
                Attribute {
                    report,
                    resident_value,
                }
            })
            .collect();
        Ok(Some(assembly))
    }
}

/// Reconstruct the canonical model from its physical-record ledger. This is a
/// consistency check, not authentication of JSON or authority to mutate a disk.
pub fn validate_record_coverage(raw: &NtfsInspection) -> Result<()> {
    ensure!(
        raw.files.len() as u64 <= MAX_MFT_RECORDS
            && raw.records_scanned <= raw.mft_record_count
            && raw.mft_record_count <= MAX_MFT_RECORDS,
        "MFT record accounting outside bounds"
    );
    let mut physical = BTreeMap::new();
    for file in &raw.files {
        ensure!(
            file.record_number < raw.mft_record_count
                && physical
                    .insert(file.record_number, file.sequence_number)
                    .is_none(),
            "duplicate/out-of-range canonical MFT record"
        );
    }
    let mut bases = BTreeSet::new();
    ensure!(
        raw.attribute_assemblies.len() <= raw.files.len(),
        "assembly ledger count exceeds base files"
    );
    for assembly in &raw.attribute_assemblies {
        ensure!(
            assembly.list_value_hex.len() <= 2 * 65536 && assembly.extensions.len() <= 1024,
            "assembly replay exceeds bounded evidence profile"
        );
        let base = &assembly.base;
        ensure!(
            bases.insert(base.record_number),
            "duplicate assembled base record"
        );
        let file = raw
            .files
            .iter()
            .find(|f| f.record_number == base.record_number)
            .context("assembly has no canonical base file")?;
        let mft = matches!(assembly.schema_version, 3 | 4);
        ensure!(
            mft || assembly.mft_bitmap_hex.is_none(),
            "ordinary file cannot supply MFT bitmap authority"
        );
        let expected_role = if mft {
            MetadataRole::ReservedSystemRecord
        } else {
            MetadataRole::OutsideExtendCandidate
        };
        ensure!(
            (!mft || base.record_number == 0)
                && file.sequence_number == base.sequence_number
                && file.base_file_reference == 0
                && file.hard_link_count == base.hard_link_count
                && file.is_directory == base.is_directory
                && file.metadata_role == expected_role
                && file.metadata_role_issue.is_none(),
            "assembled file identity/ordinary namespace role differs"
        );
        let value =
            hex::decode(&assembly.list_value_hex).context("invalid attribute-list evidence")?;
        let (canonical, replay) = if mft {
            let encoded = assembly
                .mft_bitmap_hex
                .as_ref()
                .context("MFT bitmap replay evidence absent")?;
            ensure!(
                encoded.len() <= MAX_MFT_RECORDS.div_ceil(8) as usize * 2,
                "MFT bitmap replay budget exceeded"
            );
            let bitmap = hex::decode(encoded)?;
            lists::assemble_mft(
                base.clone(),
                assembly.extensions.clone(),
                &value,
                &bitmap,
                &raw.geometry,
            )?
        } else if matches!(assembly.schema_version, 5 | 6) {
            lists::assemble_streams(
                base.clone(),
                assembly.extensions.clone(),
                &value,
                &raw.geometry,
            )?
        } else {
            ensure!(
                matches!(assembly.schema_version, 1 | 2),
                "unknown ordinary assembly schema"
            );
            lists::assemble(
                base.clone(),
                assembly.extensions.clone(),
                &value,
                &raw.geometry,
            )?
        };
        ensure!(
            matches!(assembly.schema_version, 1..=6)
                && serde_json::to_vec(&replay)? == serde_json::to_vec(assembly)?
                && serde_json::to_vec(&canonical)? == serde_json::to_vec(&file.attributes)?,
            "assembly evidence does not reproduce the canonical attributes"
        );
        for extension in &assembly.extensions {
            ensure!(
                extension.record_number < raw.mft_record_count
                    && physical
                        .insert(extension.record_number, extension.sequence_number)
                        .is_none(),
                "extension record is orphaned, shared or also published as a file"
            );
        }
    }
    ensure!(
        physical.len() as u64 == raw.records_scanned,
        "physical MFT records are missing from canonical files/assembly ledgers"
    );
    if let Some(mft) = raw
        .attribute_assemblies
        .iter()
        .find(|a| a.base.record_number == 0)
    {
        let bitmap = hex::decode(mft.mft_bitmap_hex.as_ref().context("MFT bitmap absent")?)?;
        let allocated: u64 = bitmap.iter().map(|b| u64::from(b.count_ones())).sum();
        ensure!(
            allocated == physical.len() as u64
                && physical.keys().all(|number| bitmap
                    .get(*number as usize / 8)
                    .is_some_and(|byte| byte & (1 << (*number % 8)) != 0)),
            "MFT bitmap and complete physical-record ownership disagree"
        );
    }
    Ok(())
}

fn attributes_heap_bytes(attributes: &[AttributeInventory], capacity: usize) -> Result<u64> {
    let mut counter = ReportBudget {
        limit: u64::MAX,
        used: 0,
    };
    counter.charge((capacity * std::mem::size_of::<AttributeInventory>()) as u64)?;
    for a in attributes {
        counter.charge((a.name_utf16.capacity() * 2) as u64)?;
        counter.charge((a.extents.capacity() * std::mem::size_of::<Extent>()) as u64)?;
        if let Some(hash) = &a.resident_sha256 {
            counter.charge(hash.capacity() as u64)?;
        }
        if let Some(value) = &a.resident_metadata_hex {
            counter.charge(value.capacity() as u64)?;
        }
    }
    Ok(counter.used)
}
pub(super) fn heap_bytes(assembly: &Assembly) -> Result<u64> {
    let mut total = assembly.list_value_hex.capacity() as u64;
    if let Some(origins) = &assembly.canonical_origins {
        total = total
            .checked_add(
                origins
                    .capacity()
                    .checked_mul(std::mem::size_of::<lists::CanonicalOrigin>())
                    .context("canonical origin memory overflow")? as u64,
            )
            .context("canonical origin accounting overflow")?;
    }
    if let Some(bitmap) = &assembly.mft_bitmap_hex {
        total = total
            .checked_add(bitmap.capacity() as u64)
            .context("MFT bitmap accounting overflow")?;
    }
    total = total
        .checked_add(
            (assembly.extensions.capacity() * std::mem::size_of::<RecordEvidence>()) as u64,
        )
        .context("assembly memory accounting overflow")?;
    for record in std::iter::once(&assembly.base).chain(&assembly.extensions) {
        total = total
            .checked_add(record.raw_record_sha256.capacity() as u64)
            .and_then(|n| {
                n.checked_add(
                    attributes_heap_bytes(&record.attributes, record.attributes.capacity()).ok()?,
                )
            })
            .context("assembly record accounting overflow")?;
    }
    Ok(total)
}

pub(super) fn retain_assembly(
    report: &mut NtfsInspection,
    budget: &mut ReportBudget,
    consumed: &mut BTreeMap<u64, (usize, usize)>,
    assembly: Assembly,
) -> Result<()> {
    let index = report.attribute_assemblies.len();
    budget.charge(
        (assembly.extensions.len() as u64)
            .checked_mul(128)
            .context("assembly ownership accounting overflow")?,
    )?;
    for (extension, segment) in assembly.extensions.iter().enumerate() {
        ensure!(
            consumed
                .insert(segment.record_number, (index, extension))
                .is_none(),
            "one physical extension is claimed by multiple base files"
        );
    }
    let retained = heap_bytes(&assembly)?;
    budget.push(&mut report.attribute_assemblies, assembly, retained)
}
