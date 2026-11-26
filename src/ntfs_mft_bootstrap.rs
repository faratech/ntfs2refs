//! Bounded MFT self-mapping. Never search for a record at an assumed raw LCN.
use super::*;
use crate::ntfs_attribute_list::{self as lists, Assembly};
use std::collections::BTreeSet;

pub(super) struct Bootstrap {
    pub record: Record,
    pub data: Attribute,
    pub bitmap: Vec<u8>,
    pub record_count: u64,
    pub assembly: Option<Assembly>,
}

impl Bootstrap {
    pub(super) fn verify_inventory(&self, raw: &NtfsInspection) -> Result<()> {
        let mut expected = raw
            .attribute_assemblies
            .iter()
            .filter(|a| a.base.record_number == 0);
        let first = expected.next();
        ensure!(
            expected.next().is_none(),
            "duplicate MFT bootstrap evidence"
        );
        match (first, &self.assembly) {
            (None, None) => Ok(()), // Preserve the legacy per-file diagnostic contract.
            (Some(expected), Some(actual)) => {
                ensure!(
                    serde_json::to_vec(expected)? == serde_json::to_vec(actual)?,
                    "actual MFT bootstrap/bitmap differs from inspection"
                );
                let file = raw
                    .files
                    .iter()
                    .find(|f| f.record_number == 0)
                    .context("canonical MFT absent")?;
                let attrs: Vec<_> = self.record.attributes.iter().map(|a| &a.report).collect();
                ensure!(
                    serde_json::to_vec(&attrs)? == serde_json::to_vec(&file.attributes)?,
                    "canonical MFT mapping differs from actual bootstrap"
                );
                Ok(())
            }
            _ => anyhow::bail!("MFT list requires its actual complete bootstrap ledger"),
        }
    }
}

fn known_mapping(data: &AttributeInventory, geometry: &NtfsGeometry) -> Result<()> {
    known_mapping_resource(data, geometry, lists::MAX_RUNS)
}

fn known_mapping_resource(
    data: &AttributeInventory,
    geometry: &NtfsGeometry,
    maximum_runs: usize,
) -> Result<()> {
    let cluster = u64::from(geometry.cluster_size);
    ensure!(
        !data.resident
            && data.flags == 0
            && data.compression_unit == 0
            && data.lowest_vcn == 0
            && data.initialized_size <= data.logical_size
            && data.logical_size <= data.allocated_size
            && data.allocated_size.is_multiple_of(cluster)
            && !data.extents.is_empty()
            && data.extents.len() <= maximum_runs,
        "invalid partial MFT DATA map"
    );
    ensure!(
        data.extents[0].logical_offset == 0
            && data.extents[0].physical_offset == Some(geometry.mft_lcn * cluster),
        "MFT first extent differs from boot location"
    );
    let mut end = 0u64;
    let mut physical = Vec::new();
    for run in &data.extents {
        ensure!(
            run.logical_offset >= end
                && run.logical_offset.is_multiple_of(cluster)
                && run.length > 0
                && run.length.is_multiple_of(cluster),
            "overlapping/unaligned known MFT VCNs"
        );
        end = run
            .logical_offset
            .checked_add(run.length)
            .context("MFT VCN overflow")?;
        ensure!(
            end <= data.allocated_size,
            "known MFT mapping exceeds allocation"
        );
        let start = run
            .physical_offset
            .context("MFT DATA cannot contain sparse holes")?;
        let finish = start
            .checked_add(run.length)
            .context("MFT physical overflow")?;
        ensure!(
            start.is_multiple_of(cluster) && finish <= geometry.volume_size,
            "MFT extent escapes volume"
        );
        physical.push((start, finish));
    }
    physical.sort_unstable();
    ensure!(
        physical.windows(2).all(|p| p[0].1 <= p[1].0),
        "known MFT physical extents overlap"
    );
    Ok(())
}

fn reachable(data: &AttributeInventory, start: u64, bytes: u64) -> bool {
    let Some(end) = start.checked_add(bytes) else {
        return false;
    };
    if end > data.initialized_size || end > data.logical_size {
        return false;
    }
    let first = data
        .extents
        .partition_point(|run| run.logical_offset + run.length <= start);
    let mut at = start;
    for run in &data.extents[first..] {
        if run.logical_offset > at {
            return false;
        }
        at = end.min(run.logical_offset + run.length);
        if at == end {
            return true;
        }
    }
    false
}

pub(super) fn read<R: Read + Seek>(reader: &mut R, geometry: &NtfsGeometry) -> Result<Bootstrap> {
    let mut bytes = vec![0; geometry.file_record_size as usize];
    read_at(
        reader,
        geometry
            .mft_lcn
            .checked_mul(u64::from(geometry.cluster_size))
            .context("MFT bootstrap offset overflow")?,
        &mut bytes,
        geometry.volume_size,
    )?;
    let mut record =
        parse_record(bytes.clone(), geometry).context("invalid MFT bootstrap record")?;
    ensure!(
        record.flags & 1 != 0 && record.base == 0,
        "MFT bootstrap is not an allocated base record"
    );
    let list_present = record.attributes.iter().any(|a| a.report.type_code == 0x20);
    if list_present {
        let types: BTreeSet<_> = record
            .attributes
            .iter()
            .map(|a| a.report.type_code)
            .collect();
        ensure!(
            record.flags == 1
                && record.links == 1
                && record.sequence != 0
                && record.attributes.len() == 5
                && types == BTreeSet::from([0x10, 0x20, 0x30, 0x80, 0xb0]),
            "MFT attribute-list assembly is unsupported for this base-record profile"
        );
    }
    let mut data = unnamed(&record, 0x80)?.clone();
    ensure!(
        !data.report.resident && data.report.flags == 0 && data.report.compression_unit == 0,
        "invalid MFT DATA stream layout"
    );
    ensure!(
        data.report
            .logical_size
            .is_multiple_of(u64::from(geometry.file_record_size)),
        "partial MFT record at EOF"
    );
    let record_count = data.report.logical_size / u64::from(geometry.file_record_size);
    ensure!(
        record_count > 6 && record_count <= MAX_MFT_RECORDS,
        "MFT record count exceeds inspection limit or lacks system records"
    );
    let bitmap_attribute = unnamed(&record, 0xb0)?;
    require_bitmap_bytes(
        &bitmap_attribute.report,
        bitmap_attribute.report.logical_size,
    )?;
    if list_present {
        lists::validate_mft_bitmap_storage(&bitmap_attribute.report, geometry, record_count)?;
    }
    let bitmap = read_small_attribute(
        reader,
        bitmap_attribute,
        geometry,
        MAX_MFT_RECORDS.div_ceil(8),
    )?;
    ensure!(
        bitmap.len() as u64 >= record_count.div_ceil(8),
        "MFT bitmap is too short"
    );
    ensure!(
        (record_count as usize..bitmap.len() * 8).all(|b| bitmap[b / 8] & (1 << (b % 8)) == 0),
        "MFT bitmap contains allocated records beyond MFT EOF"
    );
    let assembly = if list_present {
        ensure!(
            bitmap[0] & 1 != 0,
            "MFT bitmap does not allocate its base record"
        );
        known_mapping(&data.report, geometry)?;
        let list = unnamed(&record, 0x20)?;
        lists::validate_list_storage(&list.report, geometry)?;
        let value = read_small_attribute(reader, list, geometry, lists::MAX_LIST_BYTES as u64)?;
        let entries = lists::parse(&value)?;
        ensure!(
            entries
                .iter()
                .all(|entry| entry.record_number == 0 || entry.type_code == 0x80),
            "MFT auxiliary attributes must be complete in the base record"
        );
        let mut pending: Vec<_> = entries
            .into_iter()
            .filter(|entry| entry.record_number != 0)
            .collect();
        ensure!(
            !pending.is_empty() && pending.len() <= lists::MAX_EXTENSION_RECORDS,
            "MFT extension budget exceeded or list has no extensions"
        );
        let mut identities = BTreeSet::new();
        for entry in &pending {
            ensure!(
                entry.record_number >= 16
                    && entry.record_number < record_count
                    && identities.insert(entry.record_number)
                    && bitmap[entry.record_number as usize / 8] & (1 << (entry.record_number % 8))
                        != 0,
                "MFT extension identity/allocation differs"
            );
        }
        let base = assembled_io::evidence(0, &bytes, &record);
        let mut extensions = Vec::new();
        while !pending.is_empty() {
            let before = pending.len();
            let mut index = 0;
            while index < pending.len() {
                let entry = &pending[index];
                let offset = entry
                    .record_number
                    .checked_mul(u64::from(geometry.file_record_size))
                    .context("MFT extension offset overflow")?;
                if !reachable(&data.report, offset, u64::from(geometry.file_record_size)) {
                    index += 1;
                    continue;
                }
                let mut raw = vec![0; geometry.file_record_size as usize];
                read_attribute_range(reader, &data, offset, &mut raw, geometry)?;
                let extension = parse_record(raw.clone(), geometry)?;
                ensure!(
                    extension.flags == 1
                        && extension.links == 0
                        && extension.sequence == entry.sequence_number
                        && extension.base == (u64::from(record.sequence) << 48)
                        && extension.attributes.len() == 1,
                    "MFT extension header/sequence/base differs"
                );
                let segment = &extension.attributes[0].report;
                ensure!(
                    segment.type_code == 0x80
                        && !segment.resident
                        && segment.flags == 0
                        && segment.compression_unit == 0
                        && segment.name_utf16.is_empty()
                        && segment.instance == entry.instance
                        && segment.lowest_vcn == entry.lowest_vcn
                        && segment.lowest_vcn > 0
                        && segment.extents.first().is_some_and(|run| segment
                            .lowest_vcn
                            .checked_mul(u64::from(geometry.cluster_size))
                            == Some(run.logical_offset)),
                    "MFT extension DATA differs from its list origin"
                );
                ensure!(
                    data.report
                        .extents
                        .len()
                        .checked_add(segment.extents.len())
                        .is_some_and(|n| n <= lists::MAX_RUNS),
                    "MFT mapping run budget exceeded"
                );
                data.report.extents.extend_from_slice(&segment.extents);
                data.report
                    .extents
                    .sort_unstable_by_key(|run| run.logical_offset);
                known_mapping(&data.report, geometry)?;
                extensions.push(assembled_io::evidence(
                    entry.record_number,
                    &raw,
                    &extension,
                ));
                pending.remove(index);
            }
            ensure!(
                pending.len() < before,
                "MFT bootstrap made no progress: circular or unreachable extension"
            );
        }
        let (canonical, assembly) =
            lists::assemble_mft(base, extensions, &value, &bitmap, geometry)?;
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
        data = unnamed(&record, 0x80)?.clone();
        Some(assembly)
    } else {
        None
    };
    validate_stream_mapping(&data.report, geometry)?;
    Ok(Bootstrap {
        record,
        data,
        bitmap,
        record_count,
        assembly,
    })
}

/// The working memory of the paged bootstrap: leased as the records it
/// reads are known, never beyond what the assembly limits were made from.
#[cfg(windows)]
struct WorkingRam<'a> {
    scratch: &'a paged_storage::SourceScratch,
    admitted: u64,
    held: u64,
    leases: Vec<paged_storage::SourceRamLease>,
}
#[cfg(windows)]
impl WorkingRam<'_> {
    /// Hold `bytes` in all from here on, or all that was admitted where
    /// that is less: an assembly that takes more is refused by its limits.
    fn cover(&mut self, bytes: u64, what: &str) -> Result<()> {
        let wanted = bytes.min(self.admitted);
        if wanted > self.held {
            let more = wanted - self.held;
            let lease = self.scratch.lease_ram(more).with_context(|| {
                format!(
                    "the MFT's bootstrap (FILE 0) needs {more} more bytes of working memory for {what}"
                )
            })?;
            self.leases.push(lease);
            self.held = wanted;
        }
        Ok(())
    }
}

#[cfg(windows)]
pub(super) struct PagedBootstrap {
    pub record: Record,
    pub base_raw_sha256: String,
    pub data: Attribute,
    pub bitmap: Box<dyn SourceMetadataRange>,
    pub record_count: u64,
    pub resolver: assembled_io::PagedMftResolver,
}

/// Bootstrap the MFT using its own progressively established DATA map. Its
/// allocation bitmap is captured in authenticated chunks, never a whole Vec.
#[cfg(windows)]
pub(super) fn read_paged<R: Read + Seek>(
    reader: &mut R,
    geometry: &NtfsGeometry,
    root: &std::path::Path,
    scratch: &paged_storage::SourceScratch,
) -> Result<PagedBootstrap> {
    use assembled_io::{PagedMftResolver, SharedBitmap};
    use paged_storage::PagedMetadataRange;
    use std::rc::Rc;
    // What may be admitted is a quarter of the budget, as before; what is
    // leased follows the records read. (The quarter was leased whole for
    // the whole bootstrap, whatever the MFT held: 1,122 MiB at this place
    // on a volume of 143,000 objects, among its largest holders.)
    let working = scratch.budget().ram_bytes / 4;
    let limits = lists::AssemblyLimits::from_working_bytes(working, geometry.file_record_size)?;
    let record_work = lists::record_working_bound(geometry.file_record_size)?;
    let mut working_ram = WorkingRam {
        scratch,
        admitted: working,
        held: 0,
        leases: Vec::new(),
    };
    working_ram.cover(record_work, "its base record")?;
    let mut raw = vec![0; geometry.file_record_size as usize];
    read_at(
        reader,
        geometry
            .mft_lcn
            .checked_mul(u64::from(geometry.cluster_size))
            .context("MFT bootstrap offset overflow")?,
        &mut raw,
        geometry.volume_size,
    )?;
    let mut record = parse_record(raw.clone(), geometry)?;
    ensure!(
        record.flags & 1 != 0 && record.base == 0,
        "MFT bootstrap is not an allocated base record"
    );
    let list_present = record.attributes.iter().any(|a| a.report.type_code == 0x20);
    if list_present {
        let types: BTreeSet<_> = record
            .attributes
            .iter()
            .map(|a| a.report.type_code)
            .collect();
        ensure!(
            record.flags == 1
                && record.links == 1
                && record.sequence != 0
                && record.attributes.len() == 5
                && types == BTreeSet::from([0x10, 0x20, 0x30, 0x80, 0xb0]),
            "unsupported MFT bootstrap attribute-list base profile"
        );
    }
    let mut data = unnamed(&record, 0x80)?.clone();
    ensure!(
        !data.report.resident
            && data.report.flags == 0
            && data.report.compression_unit == 0
            && data
                .report
                .logical_size
                .is_multiple_of(u64::from(geometry.file_record_size)),
        "invalid MFT DATA form or partial EOF record"
    );
    let record_count = data.report.logical_size / u64::from(geometry.file_record_size);
    ensure!(
        record_count > 6 && record_count <= 0x0000_ffff_ffff_ffff,
        "MFT record count escapes the intrinsic file-reference domain"
    );
    let bitmap_attribute = unnamed(&record, 0xb0)?;
    require_bitmap_bytes(
        &bitmap_attribute.report,
        bitmap_attribute.report.logical_size,
    )?;
    lists::validate_bitmap_resource(
        &bitmap_attribute.report,
        geometry,
        record_count,
        limits.runs,
    )?;
    let mut writer = scratch.writer(&root.join("mft-bitmap.pages"), *b"MFTBMP01")?;
    let mut window = [0u8; 4096];
    let mut offset = 0;
    while offset < bitmap_attribute.report.logical_size {
        let count = usize::try_from(
            (bitmap_attribute.report.logical_size - offset).min(window.len() as u64),
        )?;
        read_attribute_range(
            reader,
            bitmap_attribute,
            offset,
            &mut window[..count],
            geometry,
        )?;
        for (i, byte) in window[..count].iter().enumerate() {
            let bit = (offset + i as u64) * 8;
            if bit >= record_count {
                ensure!(*byte == 0, "MFT bitmap allocates records beyond EOF");
            } else if record_count - bit < 8 {
                let allowed = (1u8 << (record_count - bit)) - 1;
                ensure!(
                    *byte & !allowed == 0,
                    "MFT bitmap allocates records beyond EOF"
                );
            }
        }
        writer.write_all(&window[..count])?;
        offset += count as u64;
    }
    let bitmap_pin = writer.finish()?;
    let bitmap = SharedBitmap(Rc::new(PagedMetadataRange::open(&bitmap_pin, scratch)?));
    let allocated = |number: u64| -> Result<bool> {
        if number >= record_count {
            return Ok(false);
        }
        let mut byte = [0];
        bitmap.read_exact_at(number / 8, &mut byte)?;
        Ok(byte[0] & (1 << (number % 8)) != 0)
    };
    ensure!(
        allocated(0)?,
        "MFT bitmap does not allocate its bootstrap base"
    );
    let assembly = if list_present {
        known_mapping_resource(&data.report, geometry, limits.runs)?;
        let list = unnamed(&record, 0x20)?;
        lists::validate_list_resource(&list.report, geometry, limits)?;
        // The list as read, its entries, those still pending and their
        // identities: as the paged assembler pays for a file's list.
        let list_work = list
            .report
            .logical_size
            .saturating_mul(32)
            .saturating_add(1024 * 1024);
        working_ram.cover(record_work.saturating_add(list_work), "its attribute list")?;
        let value = read_small_attribute(reader, list, geometry, limits.list_bytes as u64)?;
        let entries = lists::parse_with_limit(&value, limits.list_bytes)?;
        ensure!(
            entries
                .iter()
                .all(|e| e.record_number == 0 || e.type_code == 0x80),
            "MFT auxiliary attributes require complete base storage"
        );
        let mut pending: Vec<_> = entries
            .into_iter()
            .filter(|e| e.record_number != 0)
            .collect();
        ensure!(
            !pending.is_empty() && pending.len() <= limits.extension_records,
            "MFT extensions exceed admitted per-record working RAM"
        );
        // Every extension record before the first is read.
        working_ram.cover(
            (pending.len() as u64)
                .saturating_add(1)
                .saturating_mul(record_work)
                .saturating_add(list_work),
            "its extension records",
        )?;
        let mut identities = BTreeSet::new();
        for entry in &pending {
            ensure!(
                entry.record_number >= 16
                    && identities.insert(entry.record_number)
                    && allocated(entry.record_number)?,
                "MFT extension identity/allocation differs"
            );
        }
        let base = assembled_io::evidence(0, &raw, &record);
        let mut extensions = Vec::new();
        while !pending.is_empty() {
            let before = pending.len();
            let mut index = 0;
            while index < pending.len() {
                let entry = &pending[index];
                let offset = entry
                    .record_number
                    .checked_mul(u64::from(geometry.file_record_size))
                    .context("MFT extension offset overflow")?;
                if !reachable(&data.report, offset, u64::from(geometry.file_record_size)) {
                    index += 1;
                    continue;
                }
                let mut bytes = vec![0; geometry.file_record_size as usize];
                read_attribute_range(reader, &data, offset, &mut bytes, geometry)?;
                let extension = parse_record(bytes.clone(), geometry)?;
                ensure!(
                    extension.flags == 1
                        && extension.links == 0
                        && extension.sequence == entry.sequence_number
                        && extension.base == (u64::from(record.sequence) << 48)
                        && extension.attributes.len() == 1,
                    "MFT extension physical header/sequence/base differs"
                );
                let segment = &extension.attributes[0].report;
                ensure!(
                    segment.type_code == 0x80
                        && !segment.resident
                        && segment.flags == 0
                        && segment.compression_unit == 0
                        && segment.name_utf16.is_empty()
                        && segment.instance == entry.instance
                        && segment.lowest_vcn == entry.lowest_vcn
                        && segment.lowest_vcn > 0
                        && segment.extents.first().is_some_and(|run| segment
                            .lowest_vcn
                            .checked_mul(u64::from(geometry.cluster_size))
                            == Some(run.logical_offset)),
                    "MFT continuation differs from its exact listed origin"
                );
                ensure!(
                    data.report
                        .extents
                        .len()
                        .checked_add(segment.extents.len())
                        .is_some_and(|n| n <= limits.runs),
                    "MFT run mapping exceeds admitted working RAM"
                );
                data.report.extents.extend_from_slice(&segment.extents);
                data.report
                    .extents
                    .sort_unstable_by_key(|run| run.logical_offset);
                known_mapping_resource(&data.report, geometry, limits.runs)?;
                extensions.push(assembled_io::evidence(
                    entry.record_number,
                    &bytes,
                    &extension,
                ));
                pending.remove(index);
            }
            ensure!(
                pending.len() < before,
                "MFT self-mapping cannot reach a remaining extension"
            );
        }
        // What the assembly is counted as holding, by the count it is then
        // held to the admitted memory with.
        working_ram.cover(
            lists::working_assembly_bytes(&base, &extensions, value.len())?,
            "its assembly",
        )?;
        let (canonical, assembly) =
            lists::assemble_mft_resource(base, extensions, &value, &bitmap, geometry, limits)?;
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
        data = unnamed(&record, 0x80)?.clone();
        Some(assembly)
    } else {
        None
    };
    validate_stream_mapping(&data.report, geometry)?;
    let mut resolver = PagedMftResolver::new(
        &data,
        geometry,
        bitmap.clone(),
        bitmap_pin,
        record_count,
        root,
        scratch,
    )?;
    if let Some(assembly) = assembly {
        resolver.retain_bootstrap(assembly)?;
    }
    bitmap.revalidate()?;
    Ok(PagedBootstrap {
        record,
        base_raw_sha256: hex::encode(Sha256::digest(&raw)),
        data,
        bitmap: Box::new(bitmap),
        record_count,
        resolver,
    })
}

#[cfg(all(test, windows))]
mod working_ram_tests {
    use super::*;

    fn geometry(record: u32) -> NtfsGeometry {
        NtfsGeometry {
            bytes_per_sector: 512,
            sectors_per_cluster: 8,
            cluster_size: 4096,
            total_sectors: 1 << 40,
            volume_size: 1 << 49,
            total_clusters: 1 << 37,
            mft_lcn: 4,
            mftmirr_lcn: 8,
            file_record_size: record,
            index_record_size: 4096,
            serial_number: 1,
        }
    }
    /// A FILE record of `size` bytes whose attributes are `body`, with its
    /// update sequence array applied as it is on disk.
    fn file_record(size: usize, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; size];
        let entries = usa_entries(size);
        let first = (48 + entries * 2).next_multiple_of(8);
        bytes[..4].copy_from_slice(b"FILE");
        bytes[4..6].copy_from_slice(&48u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&(entries as u16).to_le_bytes());
        bytes[16..18].copy_from_slice(&1u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&1u16.to_le_bytes());
        bytes[20..22].copy_from_slice(&(first as u16).to_le_bytes());
        bytes[22..24].copy_from_slice(&1u16.to_le_bytes());
        let used = first + body.len() + 8;
        assert!(used <= size, "{used} of {size}");
        bytes[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        bytes[28..32].copy_from_slice(&(size as u32).to_le_bytes());
        bytes[first..first + body.len()].copy_from_slice(body);
        bytes[first + body.len()..first + body.len() + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[48..50].copy_from_slice(&[0x5a, 0xa5]);
        for index in 1..entries {
            let tail = index * USA_STRIDE - 2;
            let saved = [bytes[tail], bytes[tail + 1]];
            bytes[48 + index * 2..48 + index * 2 + 2].copy_from_slice(&saved);
            bytes[tail..tail + 2].copy_from_slice(&[0x5a, 0xa5]);
        }
        bytes
    }
    /// One nonresident attribute whose mapping is as many runs as `bytes`
    /// can hold: two bytes a run, the least a run takes.
    fn densest_mapping(bytes: usize) -> Vec<u8> {
        let size = bytes / 8 * 8;
        let runs = (size - 64 - 1) / 2;
        let mut raw = vec![0u8; size];
        raw[..4].copy_from_slice(&0x80u32.to_le_bytes());
        raw[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        raw[8] = 1;
        raw[24..32].copy_from_slice(&(runs as u64 - 1).to_le_bytes());
        raw[32..34].copy_from_slice(&64u16.to_le_bytes());
        let length = runs as u64 * 4096;
        for at in [40, 48, 56] {
            raw[at..at + 8].copy_from_slice(&length.to_le_bytes());
        }
        for run in 0..runs {
            raw[64 + run * 2] = 0x01;
            raw[64 + run * 2 + 1] = 1;
        }
        raw
    }
    /// As many attributes as `bytes` can hold: resident, of the smallest
    /// form, each with a digest and its value in hexadecimal.
    fn most_attributes(bytes: usize) -> Vec<u8> {
        let mut raw = Vec::new();
        for instance in 0..bytes / 24 {
            let mut attribute = [0u8; 24];
            attribute[..4].copy_from_slice(&0x10u32.to_le_bytes());
            attribute[4..8].copy_from_slice(&24u32.to_le_bytes());
            attribute[14..16].copy_from_slice(&(instance as u16).to_le_bytes());
            attribute[20..22].copy_from_slice(&24u16.to_le_bytes());
            raw.extend_from_slice(&attribute);
        }
        raw
    }
    /// One resident attribute whose value fills `bytes`, kept as
    /// hexadecimal.
    fn largest_resident(bytes: usize) -> Vec<u8> {
        let size = bytes / 8 * 8;
        let mut raw = vec![0x77u8; size];
        raw[..4].copy_from_slice(&0x10u32.to_le_bytes());
        raw[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        raw[8..16].fill(0);
        raw[16..20].copy_from_slice(&(size as u32 - 24).to_le_bytes());
        raw[20..22].copy_from_slice(&24u16.to_le_bytes());
        raw[22..24].fill(0);
        raw
    }

    #[test]
    fn what_is_leased_for_a_record_covers_what_the_fullest_record_is_counted_as() {
        // Every FILE record size the boot sector can state.
        for size in [512usize, 1024, 2048, 4096, 8192, 65536] {
            let geometry = geometry(size as u32);
            let bound = lists::record_working_bound(size as u32).unwrap();
            let room = size - (48 + usa_entries(size) * 2).next_multiple_of(8) - 8;
            let mut most = 0;
            for (name, body) in [
                ("runs", densest_mapping(room)),
                ("attributes", most_attributes(room)),
                ("resident", largest_resident(room)),
            ] {
                let raw = file_record(size, &body);
                let record = parse_record(raw.clone(), &geometry)
                    .unwrap_or_else(|error| panic!("{size} {name}: {error:#}"));
                let evidence = assembled_io::evidence(16, &raw, &record);
                let counted = lists::working_assembly_bytes(&evidence, &[], 0).unwrap();
                assert!(counted <= bound, "{size} {name}: {counted} > {bound}");
                most = most.max(counted);
            }
            // The bound is of the size of what it covers (it allows for
            // the most runs, attributes and resident bytes at once, and
            // for vectors grown to twice their length): within eight
            // times the fullest of these records, and a few MiB, not a
            // share of the budget.
            assert!(bound <= most * 8, "{size}: {bound} for {most}");
            // It grows with the record: 16 MiB for each 4 KiB of it.
            assert!(
                bound <= 16 * 1024 * 1024 * (size as u64 / 4096).max(1),
                "{size}: {bound}"
            );
        }
        // The densest mapping really is dense: half the record in runs.
        let raw = file_record(1024, &densest_mapping(1024 - 56 - 8));
        let record = parse_record(raw, &geometry(1024)).unwrap();
        assert!(record.attributes[0].report.extents.len() >= 440);
    }
}
