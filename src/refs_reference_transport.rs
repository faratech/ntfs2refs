//! Bounded transport for a pinned Windows-generated reference disk. Zero chunks
//! are omitted from the packet, not allocated as a large sparse output file.
//! This module never opens or writes a device, mounts a filesystem or applies
//! the experimental writer's metadata. Native import must independently prove
//! a newly created blank disk and verify its complete imported hash.
use crate::fixed_vhd;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};

const MAGIC: &[u8; 8] = b"N2RREF01";
const CHUNK: &[u8; 8] = b"N2RRNG01";
const END: &[u8; 8] = b"N2REND01";
pub const CHUNK_BYTES: usize = 1024 * 1024;
pub const MAX_PACKET_BYTES: u64 = 256 * 1024 * 1024;
const MAX_JSON_BYTES: usize = 16 * 1024;
const MAX_CHUNKS: usize = 8192;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Selection {
    pub schema_version: u32,
    pub disk_bytes: u64,
    pub fixed_vhd_sha256: String,
    pub partition_offset: u64,
    pub partition_bytes: u64,
    pub partition_sha256: String,
    /// Offset relative to the selected partition, not the whole disk.
    pub payload_offset: u64,
    pub payload_bytes: u64,
    pub payload_sha256: String,
}
fn is_hash(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Selection {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.schema_version == 1
                && (1024 * 1024..=128u64 << 30).contains(&self.disk_bytes)
                && self.disk_bytes.is_multiple_of(4096)
                && self.partition_offset.is_multiple_of(4096)
                && self.partition_bytes >= 4096
                && self.partition_bytes.is_multiple_of(4096)
                && self
                    .partition_offset
                    .checked_add(self.partition_bytes)
                    .is_some_and(|end| end <= self.disk_bytes)
                && self.payload_offset.is_multiple_of(4096)
                && (4096..=256u64 << 20).contains(&self.payload_bytes)
                && self.payload_bytes.is_multiple_of(4096)
                && self
                    .payload_offset
                    .checked_add(self.payload_bytes)
                    .is_some_and(|end| end <= self.partition_bytes)
                && is_hash(&self.fixed_vhd_sha256)
                && is_hash(&self.partition_sha256)
                && is_hash(&self.payload_sha256),
            "reference transport selection differs from bounded aligned profile"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub selection: Selection,
    pub fixed_footer_hex: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Summary {
    pub disk_sha256: String,
    pub fixed_vhd_sha256: String,
    pub partition_sha256: String,
    pub payload_sha256: String,
    pub nonzero_chunks: u32,
    pub nonzero_bytes: u64,
}
#[derive(Debug, Serialize)]
pub struct PackReport {
    pub kind: &'static str,
    pub source: PathBuf,
    pub output: PathBuf,
    pub header: Header,
    pub summary: Summary,
    pub packet_bytes: u64,
    pub packet_sha256: String,
    pub devices_written: u64,
    pub native_import_qualified: bool,
}

fn json_bytes(value: &impl Serialize) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_JSON_BYTES,
        "transport JSON exceeds bound"
    );
    Ok(bytes)
}
fn overlap_hash(hash: &mut Sha256, buffer: &[u8], offset: u64, first: u64, bytes: u64) {
    let lo = offset.max(first);
    let hi = (offset + buffer.len() as u64).min(first + bytes);
    if lo < hi {
        hash.update(&buffer[(lo - offset) as usize..(hi - offset) as usize]);
    }
}
fn write_json(writer: &mut impl Write, value: &impl Serialize) -> Result<u64> {
    let bytes = json_bytes(value)?;
    writer.write_all(&(bytes.len() as u32).to_le_bytes())?;
    writer.write_all(&bytes)?;
    Ok(4 + bytes.len() as u64)
}

/// Produce a packet in one full fixed-VHD pass. Errors leave an incomplete
/// stream that `decode` refuses; a successful trailer is emitted only after all
/// source pins, the exact footer and EOF match. No large output is preallocated.
pub fn encode<R: Read + Seek, W: Write>(
    source: &mut R,
    output: &mut W,
    selection: &Selection,
) -> Result<(Header, Summary, u64)> {
    selection.validate()?;
    let expected_file_bytes = selection.disk_bytes + 512;
    ensure!(
        source.seek(SeekFrom::End(0))? == expected_file_bytes,
        "fixed source length differs"
    );
    source.seek(SeekFrom::Start(selection.disk_bytes))?;
    let mut footer = [0; 512];
    source.read_exact(&mut footer)?;
    fixed_vhd::validate_footer(&footer, expected_file_bytes, selection.disk_bytes)?;
    let header = Header {
        selection: selection.clone(),
        fixed_footer_hex: hex::encode(footer),
    };
    output.write_all(MAGIC)?;
    let mut encoded_bytes = 8 + write_json(output, &header)?;
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut disk = Sha256::new();
    let mut partition = Sha256::new();
    let mut payload = Sha256::new();
    let mut chunks = 0u32;
    let mut nonzero_bytes = 0u64;
    let mut offset = 0u64;
    source.seek(SeekFrom::Start(0))?;
    while offset < selection.disk_bytes {
        let count = (selection.disk_bytes - offset).min(CHUNK_BYTES as u64) as usize;
        source
            .read_exact(&mut buffer[..count])
            .context("read complete reference chunk")?;
        let bytes = &buffer[..count];
        disk.update(bytes);
        overlap_hash(
            &mut partition,
            bytes,
            offset,
            selection.partition_offset,
            selection.partition_bytes,
        );
        overlap_hash(
            &mut payload,
            bytes,
            offset,
            selection.partition_offset + selection.payload_offset,
            selection.payload_bytes,
        );
        if bytes.iter().any(|b| *b != 0) {
            chunks += 1;
            ensure!(
                chunks as usize <= MAX_CHUNKS,
                "reference chunk budget exceeded"
            );
            encoded_bytes = encoded_bytes
                .checked_add(52 + count as u64)
                .context("packet length overflow")?;
            ensure!(
                encoded_bytes + MAX_JSON_BYTES as u64 + 12 <= MAX_PACKET_BYTES,
                "reference packet capacity exceeded"
            );
            output.write_all(CHUNK)?;
            output.write_all(&offset.to_le_bytes())?;
            output.write_all(&(count as u32).to_le_bytes())?;
            output.write_all(&Sha256::digest(bytes))?;
            output.write_all(bytes)?;
            nonzero_bytes += count as u64;
        }
        offset += count as u64;
    }
    let mut final_footer = [0; 512];
    source.read_exact(&mut final_footer)?;
    ensure!(
        final_footer == footer && source.read(&mut [0])? == 0,
        "fixed footer or EOF changed"
    );
    let disk_sha256 = hex::encode(disk.clone().finalize());
    disk.update(footer);
    let summary = Summary {
        disk_sha256,
        fixed_vhd_sha256: hex::encode(disk.finalize()),
        partition_sha256: hex::encode(partition.finalize()),
        payload_sha256: hex::encode(payload.finalize()),
        nonzero_chunks: chunks,
        nonzero_bytes,
    };
    ensure!(
        summary.fixed_vhd_sha256 == selection.fixed_vhd_sha256
            && summary.partition_sha256 == selection.partition_sha256
            && summary.payload_sha256 == selection.payload_sha256,
        "full reference/partition/payload SHA-256 pin differs"
    );
    output.write_all(END)?;
    encoded_bytes += 8 + write_json(output, &summary)?;
    Ok((header, summary, encoded_bytes))
}

#[derive(Debug)]
pub struct Chunk {
    pub offset: u64,
    data: Vec<u8>,
}
impl Chunk {
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}
#[derive(Debug)]
pub struct ReferencePacket {
    pub header: Header,
    pub summary: Summary,
    chunks: Vec<Chunk>,
}
impl ReferencePacket {
    pub fn chunks(&self) -> &[Chunk] {
        &self.chunks
    }
    /// Virtual disk bytes reconstructed from packet records plus zero holes.
    /// Hash this complete view, or the imported disk, before native patching.
    pub fn reader(&self) -> ReferenceReader<'_> {
        ReferenceReader {
            packet: self,
            position: 0,
        }
    }
    /// Decode checks packet grammar and record hashes only. This full virtual
    /// scan also binds offsets/zero holes to the independent source pins. A
    /// native importer may instead compare its complete imported disk hash to
    /// `summary.disk_sha256` before any experimental metadata write.
    pub fn verify_reconstructed_contents(&self) -> Result<()> {
        let s = &self.header.selection;
        let mut reader = self.reader();
        let mut buffer = vec![0; CHUNK_BYTES];
        let mut disk = Sha256::new();
        let mut partition = Sha256::new();
        let mut payload = Sha256::new();
        let mut offset = 0u64;
        while offset < s.disk_bytes {
            let count = (s.disk_bytes - offset).min(CHUNK_BYTES as u64) as usize;
            reader.read_exact(&mut buffer[..count])?;
            disk.update(&buffer[..count]);
            overlap_hash(
                &mut partition,
                &buffer[..count],
                offset,
                s.partition_offset,
                s.partition_bytes,
            );
            overlap_hash(
                &mut payload,
                &buffer[..count],
                offset,
                s.partition_offset + s.payload_offset,
                s.payload_bytes,
            );
            offset += count as u64;
        }
        ensure!(
            hex::encode(disk.clone().finalize()) == self.summary.disk_sha256,
            "reconstructed disk SHA-256 differs"
        );
        disk.update(hex::decode(&self.header.fixed_footer_hex)?);
        ensure!(
            hex::encode(disk.finalize()) == s.fixed_vhd_sha256
                && hex::encode(partition.finalize()) == s.partition_sha256
                && hex::encode(payload.finalize()) == s.payload_sha256,
            "reconstructed source/partition/payload SHA-256 differs"
        );
        Ok(())
    }
}
pub struct ReferenceReader<'a> {
    packet: &'a ReferencePacket,
    position: u64,
}
impl Read for ReferenceReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = self
            .packet
            .header
            .selection
            .disk_bytes
            .saturating_sub(self.position)
            .min(output.len() as u64) as usize;
        output[..count].fill(0);
        let end = self.position + count as u64;
        for chunk in &self.packet.chunks {
            let lo = self.position.max(chunk.offset);
            let hi = end.min(chunk.offset + chunk.data.len() as u64);
            if lo < hi {
                output[(lo - self.position) as usize..(hi - self.position) as usize]
                    .copy_from_slice(
                        &chunk.data[(lo - chunk.offset) as usize..(hi - chunk.offset) as usize],
                    );
            }
            if chunk.offset >= end {
                break;
            }
        }
        self.position = end;
        Ok(count)
    }
}
impl Seek for ReferenceReader<'_> {
    fn seek(&mut self, seek: SeekFrom) -> io::Result<u64> {
        let position = match seek {
            SeekFrom::Start(v) => i128::from(v),
            SeekFrom::Current(v) => i128::from(self.position) + i128::from(v),
            SeekFrom::End(v) => i128::from(self.packet.header.selection.disk_bytes) + i128::from(v),
        };
        if !(0..=i128::from(self.packet.header.selection.disk_bytes)).contains(&position) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "reference seek outside disk",
            ));
        }
        self.position = position as u64;
        Ok(self.position)
    }
}
fn read_json<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    consumed: &mut u64,
) -> Result<T> {
    let mut length = [0; 4];
    reader.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    ensure!(
        (1..=MAX_JSON_BYTES).contains(&length),
        "transport JSON size differs"
    );
    let mut bytes = vec![0; length];
    reader.read_exact(&mut bytes)?;
    *consumed += 4 + length as u64;
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn decode(reader: &mut impl Read) -> Result<ReferencePacket> {
    let mut magic = [0; 8];
    reader.read_exact(&mut magic)?;
    ensure!(&magic == MAGIC, "reference packet magic differs");
    let mut consumed = 8;
    let header: Header = read_json(reader, &mut consumed)?;
    header.selection.validate()?;
    let footer = hex::decode(&header.fixed_footer_hex)?;
    fixed_vhd::validate_footer(
        &footer,
        header.selection.disk_bytes + 512,
        header.selection.disk_bytes,
    )?;
    let mut chunks = Vec::<Chunk>::new();
    let mut total = 0u64;
    let mut end = 0u64;
    loop {
        reader.read_exact(&mut magic)?;
        consumed += 8;
        if &magic == END {
            break;
        }
        ensure!(
            &magic == CHUNK && chunks.len() < MAX_CHUNKS,
            "reference chunk signature or count differs"
        );
        let mut metadata = [0; 44];
        reader.read_exact(&mut metadata)?;
        let offset = u64::from_le_bytes(metadata[..8].try_into()?);
        let length = u32::from_le_bytes(metadata[8..12].try_into()?) as usize;
        ensure!(
            offset >= end
                && offset.is_multiple_of(CHUNK_BYTES as u64)
                && (1..=CHUNK_BYTES).contains(&length)
                && offset
                    .checked_add(length as u64)
                    .is_some_and(|v| v <= header.selection.disk_bytes)
                && length as u64 == (header.selection.disk_bytes - offset).min(CHUNK_BYTES as u64),
            "reference chunk bounds/order differ"
        );
        consumed += 44 + length as u64;
        ensure!(
            consumed <= MAX_PACKET_BYTES,
            "reference packet exceeds capacity"
        );
        let mut data = vec![0; length];
        reader.read_exact(&mut data)?;
        ensure!(
            data.iter().any(|b| *b != 0) && Sha256::digest(&data).as_slice() == &metadata[12..],
            "reference chunk data/hash differs"
        );
        end = offset + length as u64;
        total += length as u64;
        chunks.push(Chunk { offset, data });
    }
    let summary: Summary = read_json(reader, &mut consumed)?;
    ensure!(
        consumed <= MAX_PACKET_BYTES && reader.read(&mut [0])? == 0,
        "reference trailer EOF/size differs"
    );
    ensure!(
        is_hash(&summary.disk_sha256)
            && summary.fixed_vhd_sha256 == header.selection.fixed_vhd_sha256
            && summary.partition_sha256 == header.selection.partition_sha256
            && summary.payload_sha256 == header.selection.payload_sha256
            && summary.nonzero_chunks as usize == chunks.len()
            && summary.nonzero_bytes == total,
        "reference summary differs"
    );
    Ok(ReferencePacket {
        header,
        summary,
        chunks,
    })
}

pub fn pack_files(source: &Path, output: &Path, selection: &Selection) -> Result<PackReport> {
    selection.validate()?;
    let source = fixed_vhd::checked_path(source, false)?;
    let output = fixed_vhd::checked_path(output, true)?;
    ensure!(
        output
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("n2rref")),
        "reference output must end in .n2rref"
    );
    let partial = fixed_vhd::append_suffix(&output, ".partial");
    fixed_vhd::checked_path(&partial, true)?;
    fixed_vhd::require_absent(&output)?;
    fixed_vhd::require_absent(&partial)?;
    let mut input = fixed_vhd::open_read_only(&source)?;
    let before = input.metadata()?;
    let mut result = fixed_vhd::create_new(&partial)?;
    let (header, summary, packet_bytes) = encode(&mut input, &mut result, selection)?;
    ensure!(
        input.metadata()?.len() == before.len()
            && input.metadata()?.modified()? == before.modified()?,
        "reference source metadata changed"
    );
    result.sync_all()?;
    ensure!(
        result.metadata()?.len() == packet_bytes,
        "packet length differs after write"
    );
    result.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    io::copy(&mut result, &mut HashWriter(&mut hash))?;
    let packet_sha256 = hex::encode(hash.finalize());
    result.seek(SeekFrom::Start(0))?;
    decode(&mut result)?;
    drop(result);
    fixed_vhd::publish_new(&partial, &output)?;
    Ok(PackReport {
        kind: "bounded-fixed-vhd-reference-transport",
        source,
        output,
        header,
        summary,
        packet_bytes,
        packet_sha256,
        devices_written: 0,
        native_import_qualified: false,
    })
}
struct HashWriter<'a>(&'a mut Sha256);
impl Write for HashWriter<'_> {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.0.update(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
