//! Stream complete leased native proofs into bounded rows. Closed receipts
//! are evidence of NTFS-owned work, never replay or conversion authority.
use crate::ntfs_inspect::{
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{SortedRecordStore, SortedRecordWriter},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, Write},
    path::Path,
};

#[derive(Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum Row<'a> {
    Header {
        kind: &'a str,
        maximum_json_bytes: u64,
    },
    Chunk {
        ordinal: u64,
        data: &'a str,
    },
    Footer {
        bytes: u64,
        chunks: u64,
        sha256: &'a str,
    },
}
#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum ReadRow {
    Header {
        kind: String,
        maximum_json_bytes: u64,
    },
    Chunk {
        ordinal: u64,
        data: String,
    },
    Footer {
        bytes: u64,
        chunks: u64,
        sha256: String,
    },
}
fn key(proof: u64, chunk: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&proof.to_be_bytes());
    key[8..].copy_from_slice(&chunk.to_be_bytes());
    key
}
fn encode(input: &[u8]) -> Result<String> {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let size = input
        .len()
        .checked_add(2)
        .and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4))
        .context("preparation base64 overflow")?;
    let mut out = Vec::new();
    out.try_reserve_exact(size)?;
    for c in input.chunks(3) {
        let a = c[0];
        let b = c.get(1).copied();
        let d = c.get(2).copied();
        out.extend_from_slice(&[
            ABC[(a >> 2) as usize],
            ABC[(((a & 3) << 4) | (b.unwrap_or(0) >> 4)) as usize],
            b.map_or(b'=', |b| {
                ABC[(((b & 15) << 2) | (d.unwrap_or(0) >> 6)) as usize]
            }),
            d.map_or(b'=', |d| ABC[(d & 63) as usize]),
        ]);
    }
    Ok(String::from_utf8(out)?)
}
fn decode(text: &str, maximum: usize) -> Result<Vec<u8>> {
    let input = text.as_bytes();
    ensure!(
        !input.is_empty() && input.len().is_multiple_of(4),
        "preparation base64 length differs"
    );
    let pad = input.iter().rev().take_while(|&&b| b == b'=').count();
    ensure!(pad <= 2, "preparation padding differs");
    let bytes = (input.len() / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_sub(pad))
        .context("preparation decoded size overflow")?;
    ensure!(
        bytes <= maximum,
        "preparation decoded chunk exceeds its window"
    );
    let digit = |b| -> Result<u8> {
        Ok(match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical preparation base64"),
        })
    };
    let mut output = Vec::new();
    output.try_reserve_exact(bytes)?;
    for (ordinal, c) in input.chunks_exact(4).enumerate() {
        let last = ordinal + 1 == input.len() / 4;
        let a = digit(c[0])?;
        let b = digit(c[1])?;
        output.push((a << 2) | (b >> 4));
        if c[2] == b'=' {
            ensure!(
                last && c[3] == b'=' && b & 15 == 0,
                "preparation padding bits differ"
            );
        } else {
            let n = digit(c[2])?;
            output.push((b << 4) | (n >> 2));
            if c[3] == b'=' {
                ensure!(last && n & 3 == 0, "preparation padding bits differ");
            } else {
                output.push((n << 6) | digit(c[3])?);
            }
        }
    }
    ensure!(output.len() == bytes, "preparation decoded size differs");
    Ok(output)
}
struct Count(u64);
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| io::Error::other("preparation receipt size overflow"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct Chunks<'a> {
    writer: &'a mut SortedRecordWriter,
    proof: u64,
    maximum: u64,
    chunk_bytes: usize,
    buffer: Vec<u8>,
    bytes: u64,
    chunks: u64,
    hash: Sha256,
}
impl Chunks<'_> {
    fn emit(&mut self) -> Result<()> {
        if self.buffer.is_empty() {
            return Ok(());
        }
        let data = encode(&self.buffer)?;
        let next = self
            .chunks
            .checked_add(1)
            .context("preparation chunk ordinal overflow")?;
        ensure!(next < u64::MAX, "preparation chunk ordinal is reserved");
        self.writer.push(
            key(self.proof, next),
            &Row::Chunk {
                ordinal: self.chunks,
                data: &data,
            },
        )?;
        self.chunks = next;
        self.buffer.clear();
        Ok(())
    }
}
impl Write for Chunks<'_> {
    fn write(&mut self, mut bytes: &[u8]) -> io::Result<usize> {
        let length = bytes.len();
        (|| -> Result<()> {
            self.bytes = self
                .bytes
                .checked_add(length as u64)
                .filter(|n| *n <= self.maximum)
                .context("native preparation proof exceeded its complete prepaid bound")?;
            self.hash.update(bytes);
            while !bytes.is_empty() {
                let n = bytes.len().min(self.chunk_bytes - self.buffer.len());
                self.buffer.extend_from_slice(&bytes[..n]);
                bytes = &bytes[n..];
                if self.buffer.len() == self.chunk_bytes {
                    self.emit()?;
                }
            }
            Ok(())
        })()
        .map(|()| length)
        .map_err(io::Error::other)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
pub(super) struct ReceiptWriter {
    writer: SortedRecordWriter,
    scratch: SourceScratch,
    proofs: u64,
    rows: u64,
    pending: Option<u64>,
    chunk_bytes: usize,
    poisoned: bool,
    memory: SourceRamLease,
}
pub(super) struct ClosedReceipts {
    owner: SortedRecordStore,
    proofs: u64,
    _memory: SourceRamLease,
}
impl ClosedReceipts {
    pub(super) fn revalidate(&self) -> Result<()> {
        self.owner.revalidate()
    }
    pub(super) fn summary(&self) -> serde_json::Value {
        serde_json::json!({"logical_receipts":self.proofs,"rows":self.owner.len(),"store":self.owner.pin(),
            "closed_readback":true,"per_attempt_crash_durability_claimed":false,"source_admission":false})
    }
}
impl ReceiptWriter {
    pub(super) fn new(path: &Path, scratch: SourceScratch) -> Result<Self> {
        let window = scratch
            .budget()
            .record_bytes
            .min(u64::from(scratch.budget().page_bytes));
        let chunk_bytes = usize::try_from(
            window
                .checked_sub(512)
                .context("preparation row cannot contain receipt framing")?
                / 4
                * 3,
        )?;
        ensure!(chunk_bytes > 0, "empty preparation receipt window");
        let memory = scratch.lease_ram(
            (chunk_bytes as u64)
                .checked_mul(6)
                .and_then(|n| {
                    n.checked_add((path.as_os_str().as_encoded_bytes().len() as u64) * 12)
                })
                .and_then(|n| n.checked_add(65536))
                .context("preparation receipt workspace overflow")?,
        )?;
        let writer = SortedRecordWriter::new(path, *b"N2RPRE01", &scratch)?;
        Ok(Self {
            writer,
            scratch,
            proofs: 0,
            rows: 0,
            pending: None,
            chunk_bytes,
            poisoned: false,
            memory,
        })
    }
    pub(super) fn reserve_native(&mut self, maximum: u64) -> Result<()> {
        // The SDK bound covers its complete native proof. This covers the
        // fixed executor ordinal/request envelope, independently of proof size.
        self.reserve(
            maximum
                .checked_add(4096)
                .context("preparation envelope overflow")?,
        )
    }
    fn reserve(&mut self, maximum: u64) -> Result<()> {
        ensure!(
            !self.poisoned && self.pending.is_none() && maximum > 0,
            "preparation receipt reservation state differs"
        );
        let chunks = maximum.div_ceil(self.chunk_bytes as u64);
        let encoded = maximum
            .div_ceil(3)
            .checked_mul(4)
            .and_then(|n| chunks.checked_mul(256).and_then(|f| n.checked_add(f)))
            .and_then(|n| n.checked_add(2048))
            .context("preparation complete receipt wire overflow")?;
        self.writer.reserve_record_batch(
            encoded,
            chunks
                .checked_add(2)
                .context("preparation row count overflow")?,
        )?;
        self.pending = Some(maximum);
        Ok(())
    }
    pub(super) fn append(&mut self, kind: &'static str, value: &impl Serialize) -> Result<()> {
        ensure!(!self.poisoned, "preparation receipt writer is poisoned");
        if self.pending.is_none() {
            let mut count = Count(0);
            serde_json::to_writer(&mut count, value)?;
            self.reserve(count.0)?;
        }
        let maximum = self
            .pending
            .context("preparation receipt lacks wire prepayment")?;
        self.poisoned = true;
        self.writer.push(
            key(self.proofs, 0),
            &Row::Header {
                kind,
                maximum_json_bytes: maximum,
            },
        )?;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(self.chunk_bytes)?;
        let mut chunks = Chunks {
            writer: &mut self.writer,
            proof: self.proofs,
            maximum,
            chunk_bytes: self.chunk_bytes,
            buffer,
            bytes: 0,
            chunks: 0,
            hash: Sha256::new(),
        };
        serde_json::to_writer(&mut chunks, value)?;
        chunks.emit()?;
        ensure!(
            chunks.bytes > 0 && chunks.chunks > 0,
            "empty preparation receipt"
        );
        let bytes = chunks.bytes;
        let count = chunks.chunks;
        let sha = hex::encode(chunks.hash.finalize());
        chunks.writer.push(
            key(self.proofs, u64::MAX),
            &Row::Footer {
                bytes,
                chunks: count,
                sha256: &sha,
            },
        )?;
        self.rows = self
            .rows
            .checked_add(count)
            .and_then(|n| n.checked_add(2))
            .context("preparation rows overflow")?;
        self.proofs = self
            .proofs
            .checked_add(1)
            .context("preparation receipt count overflow")?;
        self.pending = None;
        self.poisoned = false;
        Ok(())
    }
    pub(super) fn close(self) -> Result<ClosedReceipts> {
        ensure!(
            !self.poisoned && self.pending.is_none(),
            "cannot close unsettled preparation receipts"
        );
        let pin = self.writer.finish()?;
        ensure!(
            pin.records == self.rows,
            "preparation complete stored row count differs"
        );
        let owner = SortedRecordStore::open(&pin, &self.scratch)?;
        let mut row = 0u64;
        for proof in 0..self.proofs {
            ensure!(
                owner.key(row)? == key(proof, 0),
                "preparation receipt header order differs"
            );
            let ReadRow::Header {
                kind,
                maximum_json_bytes,
            } = owner.get(row)?
            else {
                anyhow::bail!("preparation receipt header missing")
            };
            ensure!(
                !kind.is_empty() && kind.len() <= 64,
                "preparation receipt kind differs"
            );
            row += 1;
            let mut bytes = 0u64;
            let mut chunks = 0u64;
            let mut hash = Sha256::new();
            loop {
                match owner.get::<ReadRow>(row)? {
                    ReadRow::Chunk { ordinal, data } => {
                        ensure!(
                            ordinal == chunks && owner.key(row)? == key(proof, chunks + 1),
                            "preparation receipt chunk order differs"
                        );
                        let raw = decode(&data, self.chunk_bytes)?;
                        bytes = bytes
                            .checked_add(raw.len() as u64)
                            .filter(|n| *n <= maximum_json_bytes)
                            .context("preparation receipt exceeds complete native bound")?;
                        hash.update(&raw);
                        chunks += 1;
                        row += 1;
                    }
                    ReadRow::Footer {
                        bytes: expected,
                        chunks: count,
                        sha256,
                    } => {
                        ensure!(
                            owner.key(row)? == key(proof, u64::MAX)
                                && bytes == expected
                                && chunks == count
                                && bytes > 0
                                && chunks > 0
                                && hex::encode(hash.finalize()) == sha256,
                            "preparation complete receipt hash/count differs"
                        );
                        row += 1;
                        break;
                    }
                    _ => anyhow::bail!("preparation logical receipt is incomplete"),
                }
            }
        }
        ensure!(
            row == owner.len(),
            "preparation receipt archive has extra rows"
        );
        owner.revalidate()?;
        Ok(ClosedReceipts {
            owner,
            proofs: self.proofs,
            _memory: self.memory,
        })
    }
}
