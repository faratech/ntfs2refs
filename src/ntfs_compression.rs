//! Logical reads of the initial NTFS LZNT1 compression profile.
//!
//! Compression padding in a run list is part of the encoded representation,
//! not a logical sparse-file layout. None of these physical bytes is adoptable
//! as ordinary ReFS payload. The reader materializes initialized logical bytes
//! and returns zero for the NTFS uninitialized tail.
//!
//! Independently implemented from Microsoft's public MS-XCA 2.5 description:
//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/124d9696-a69c-409a-a055-2562fbe255f9
//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/cba0fa15-bd62-4eda-8838-8fc7ab406df1
//! https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca/b1ba6d34-499c-4017-ab0c-fe2daee93efc
//! The complete physical allocation is checked against ATTRIBUTE_RECORD_HEADER
//! TotalAllocated; it is deliberately distinct from logical mapped coverage.
//! https://learn.microsoft.com/en-us/windows/win32/devnotes/attribute-record-header
//! A resident DATA value can carry compression policy without encoded bytes.
//! Directory policy is handled separately, never by the DATA decoder.
//! https://learn.microsoft.com/en-us/windows/win32/fileio/compression-state

use crate::ntfs_inspect::{AttributeInventory, Extent, NtfsGeometry};
use anyhow::{Context, Result, ensure};
use std::io::{Read, Seek, SeekFrom};

/// NTFS compresses in units of 16 clusters, and only on clusters of 4 KiB
/// and smaller: 8 KiB units of 512-byte clusters up to 64 KiB units.
const UNIT_CLUSTERS: u64 = 16;
const MAX_CLUSTER: u32 = 4096;
/// An LZNT1 chunk decodes to 4096 bytes whatever the cluster size.
const CHUNK: usize = 4096;

fn unit_bytes(g: &NtfsGeometry) -> Result<u64> {
    ensure!(
        g.cluster_size.is_power_of_two() && (512..=MAX_CLUSTER).contains(&g.cluster_size),
        "NTFS compresses only on clusters of 512 bytes to 4 KiB; this volume has {}-byte clusters",
        g.cluster_size
    );
    Ok(UNIT_CLUSTERS * u64::from(g.cluster_size))
}

/// Check encoding, geometry, complete mapping and physical allocation before
/// any logical byte is accepted. This is not source-volume admission.
pub fn supported(a: &AttributeInventory, g: &NtfsGeometry) -> Result<()> {
    ensure!(a.type_code == 0x80, "compression reader supports DATA only");
    ensure!(a.flags == 1, "unsupported NTFS compression encoding");
    let unit = unit_bytes(g)?;
    let cluster = u64::from(g.cluster_size);
    ensure!(a.lowest_vcn == 0, "LZNT1 mapping must start at VCN zero");
    if a.resident {
        ensure!(
            a.compression_unit == 0
                && a.total_allocated_size.is_none()
                && a.extents.is_empty()
                && a.logical_size == a.initialized_size
                && a.logical_size == a.allocated_size,
            "invalid resident compression-policy DATA"
        );
        return Ok(());
    }
    ensure!(
        a.compression_unit == 4,
        "unsupported nonresident NTFS compression unit"
    );
    ensure!(
        a.initialized_size <= a.logical_size,
        "compressed DATA initialized size exceeds EOF"
    );
    ensure!(
        a.allocated_size.is_multiple_of(cluster),
        "compressed DATA allocation is not cluster aligned"
    );

    let mut coverage = 0u64;
    let mut physical = 0u64;
    let mut ranges = Vec::new();
    ranges
        .try_reserve_exact(a.extents.len())
        .context("compressed extent validation allocation")?;
    let mut previous_hole = false;
    let mut last_physical_end = 0u64;
    for e in &a.extents {
        ensure!(
            e.logical_offset == coverage,
            "compressed DATA mapping gap or overlap"
        );
        ensure!(
            e.length > 0 && e.length.is_multiple_of(cluster),
            "invalid compressed DATA run length"
        );
        coverage = coverage
            .checked_add(e.length)
            .context("compressed DATA coverage overflow")?;
        if let Some(start) = e.physical_offset {
            ensure!(
                !previous_hole || e.logical_offset.is_multiple_of(unit),
                "physical run follows compression padding inside one unit"
            );
            ensure!(
                start.is_multiple_of(cluster),
                "compressed DATA physical offset is not cluster aligned"
            );
            let end = start
                .checked_add(e.length)
                .context("compressed DATA physical end overflow")?;
            ensure!(
                end <= g.volume_size,
                "compressed DATA physical run exceeds partition"
            );
            physical = physical
                .checked_add(e.length)
                .context("compressed DATA physical allocation overflow")?;
            ranges.push((start, end));
            last_physical_end = coverage;
            previous_hole = false;
        } else {
            previous_hole = true;
        }
    }
    ensure!(
        coverage >= a.logical_size,
        "compressed DATA mapping ends before EOF"
    );
    // A mixed unit is encoded as its physical prefix and a complete remainder
    // of padding. A final partial raw unit is permitted if it covers EOF.
    if previous_hole && !last_physical_end.is_multiple_of(unit) {
        let padded_end = last_physical_end
            .checked_add(unit - last_physical_end % unit)
            .context("compressed unit padding overflow")?;
        ensure!(
            coverage >= padded_end,
            "partial encoded compression unit lacks complete padding"
        );
    }
    ensure!(
        physical <= a.allocated_size && a.allocated_size <= coverage,
        "compressed DATA allocation differs from coverage"
    );
    ensure!(
        a.total_allocated_size == Some(physical),
        "compressed DATA TotalAllocated differs from physical runs"
    );
    ranges.sort_unstable();
    ensure!(
        ranges.windows(2).all(|p| p[0].1 <= p[1].0),
        "compressed DATA physical runs overlap"
    );
    Ok(())
}

/// Bounded random-access decoder. The run map is validated once, then a binary
/// lookup locates each requested unit. Only one decoded unit is cached.
#[derive(Debug)]
pub struct Reader {
    extents: Vec<Extent>,
    logical_size: u64,
    initialized_size: u64,
    coverage: u64,
    /// Bytes in one compression unit of this volume.
    unit: u64,
    cached_start: Option<u64>,
    decoded: Vec<u8>,
    encoded: Vec<u8>,
}

impl Reader {
    pub fn new(a: &AttributeInventory, g: &NtfsGeometry) -> Result<Self> {
        supported(a, g)?;
        let unit = unit_bytes(g)?;
        ensure!(
            !a.resident,
            "resident compression-policy DATA requires checked resident bytes"
        );
        let mut extents = Vec::new();
        extents
            .try_reserve_exact(a.extents.len())
            .context("compressed reader run-map allocation")?;
        extents.extend_from_slice(&a.extents);
        let mut decoded = Vec::new();
        decoded
            .try_reserve_exact(unit as usize)
            .context("compressed reader unit allocation")?;
        decoded.resize(unit as usize, 0);
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(unit as usize)
            .context("compressed reader encoded allocation")?;
        Ok(Self {
            unit,
            coverage: a.extents.last().map_or(0, |e| e.logical_offset + e.length),
            extents,
            logical_size: a.logical_size,
            initialized_size: a.initialized_size,
            cached_start: None,
            decoded,
            encoded,
        })
    }

    pub fn read_range<R: Read + Seek>(
        &mut self,
        source: &mut R,
        logical_offset: u64,
        out: &mut [u8],
    ) -> Result<()> {
        let end = logical_offset
            .checked_add(out.len() as u64)
            .context("compressed logical read overflow")?;
        ensure!(
            end <= self.logical_size,
            "compressed logical read exceeds EOF"
        );
        out.fill(0);
        let valid_end = end.min(self.initialized_size);
        let mut offset = logical_offset;
        while offset < valid_end {
            let unit = offset / self.unit * self.unit;
            if self.cached_start != Some(unit) {
                self.load_unit(source, unit)?;
            }
            let within = (offset - unit) as usize;
            let length = (valid_end - offset).min(self.unit - (offset - unit)) as usize;
            let destination = (offset - logical_offset) as usize;
            out[destination..destination + length]
                .copy_from_slice(&self.decoded[within..within + length]);
            offset += length as u64;
        }
        Ok(())
    }

    fn load_unit<R: Read + Seek>(&mut self, source: &mut R, start: u64) -> Result<()> {
        self.cached_start = None;
        self.decoded.fill(0);
        self.encoded.clear();
        let end = start
            .checked_add(self.unit)
            .context("compression unit end overflow")?
            .min(self.coverage);
        ensure!(start < end, "missing compressed unit mapping");
        let mut index = self
            .extents
            .partition_point(|e| e.logical_offset <= start)
            .checked_sub(1)
            .context("missing compressed unit start")?;
        let mut position = start;
        let mut hole = false;
        while position < end {
            let e = self
                .extents
                .get(index)
                .context("compressed unit map is incomplete")?;
            ensure!(
                e.logical_offset <= position && position < e.logical_offset + e.length,
                "compressed unit map has a gap"
            );
            let length = (e.logical_offset + e.length).min(end) - position;
            if let Some(physical) = e.physical_offset {
                ensure!(!hole, "physical bytes follow compression padding");
                let old = self.encoded.len();
                let new = old
                    .checked_add(length as usize)
                    .context("compressed unit length overflow")?;
                ensure!(new <= self.unit as usize, "compressed unit exceeds buffer");
                self.encoded.resize(new, 0);
                source
                    .seek(SeekFrom::Start(physical + position - e.logical_offset))
                    .context("seek compressed DATA")?;
                source
                    .read_exact(&mut self.encoded[old..new])
                    .context("read compressed DATA")?;
            } else {
                hole = true;
            }
            position += length;
            index += 1;
        }
        let required = self.initialized_size.saturating_sub(start).min(self.unit) as usize;
        if !hole {
            ensure!(
                self.encoded.len() >= required,
                "raw compression unit lacks initialized bytes"
            );
            self.decoded[..self.encoded.len()].copy_from_slice(&self.encoded);
        } else if !self.encoded.is_empty() {
            ensure!(
                end - start == self.unit,
                "encoded compression unit lacks complete mapping"
            );
            let produced = decode_lznt1(&self.encoded, &mut self.decoded)?;
            ensure!(
                produced >= required,
                "LZNT1 output ends before initialized DATA"
            );
        }
        self.cached_start = Some(start);
        Ok(())
    }
}

/// Decode bounded LZNT1 chunks and return the number of produced bytes. The
/// caller supplies the output bound. A zero header terminates the encoded data;
/// allocation slack after it is not logical data and is never read as such.
pub fn decode_lznt1(input: &[u8], output: &mut [u8]) -> Result<usize> {
    let mut cursor = 0usize;
    let mut written = 0usize;
    while cursor < input.len() {
        let header_bytes = input
            .get(cursor..cursor + 2)
            .context("truncated LZNT1 chunk header")?;
        let header = u16::from_le_bytes([header_bytes[0], header_bytes[1]]);
        cursor += 2;
        if header == 0 {
            return Ok(written);
        }
        ensure!(header & 0x7000 == 0x3000, "invalid LZNT1 chunk signature");
        let stored = usize::from(header & 0x0fff) + 1;
        let chunk_end = cursor
            .checked_add(stored)
            .context("LZNT1 chunk end overflow")?;
        ensure!(chunk_end <= input.len(), "truncated LZNT1 chunk payload");
        let base = written;
        let limit = base
            .checked_add(CHUNK)
            .context("LZNT1 output offset overflow")?
            .min(output.len());
        if header & 0x8000 == 0 {
            ensure!(
                stored <= limit - written,
                "LZNT1 literal chunk exceeds output"
            );
            output[written..written + stored].copy_from_slice(&input[cursor..chunk_end]);
            written += stored;
            cursor = chunk_end;
        } else {
            while cursor < chunk_end {
                let flags = input[cursor];
                cursor += 1;
                ensure!(cursor < chunk_end, "LZNT1 flag group has no elements");
                for bit in 0..8 {
                    if cursor == chunk_end {
                        break;
                    }
                    if flags & (1 << bit) == 0 {
                        ensure!(written < limit, "LZNT1 literal exceeds chunk output");
                        output[written] = input[cursor];
                        cursor += 1;
                        written += 1;
                    } else {
                        ensure!(cursor + 2 <= chunk_end, "truncated LZNT1 match token");
                        let token = u16::from_le_bytes([input[cursor], input[cursor + 1]]);
                        cursor += 2;
                        let local = written - base;
                        let mut length_bits = 12u32;
                        let mut boundary = 16usize;
                        while boundary < local {
                            boundary <<= 1;
                            length_bits -= 1;
                        }
                        let length = usize::from(token & ((1u16 << length_bits) - 1)) + 3;
                        let distance = usize::from(token >> length_bits) + 1;
                        ensure!(distance <= local, "LZNT1 match precedes chunk start");
                        ensure!(
                            length <= limit - written,
                            "LZNT1 match exceeds chunk output"
                        );
                        // Overlapping matches intentionally consume newly
                        // produced bytes; slice copy would have different semantics.
                        for _ in 0..length {
                            output[written] = output[written - distance];
                            written += 1;
                        }
                    }
                }
            }
        }
        if written == output.len() {
            return Ok(written);
        }
        if written - base != CHUNK {
            // A short final chunk may be followed only by the optional terminal,
            // not another chunk whose logical placement would be ambiguous.
            ensure!(
                cursor == input.len() || input.get(cursor..cursor + 2) == Some(&[0, 0]),
                "nonfinal LZNT1 chunk has short output"
            );
        }
    }
    Ok(written)
}
