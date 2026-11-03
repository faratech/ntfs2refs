//! Complete logical placement proofs, chunked under the admitted row window.
//! A native move prepays the entire proof's encoded data/directory wire. The
//! retained page owner is a fact archive, never a source-write capability.
use crate::ntfs_inspect::{
    paged_storage::{SourceRamLease, SourceScratch},
    record_store::{SortedRecordStore, SortedRecordWriter},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::shadow_native::private_tree::PlacementEvidenceSink;
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
struct Count {
    bytes: u64,
    maximum: u64,
}
impl Write for Count {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(b.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| {
                io::Error::other("placement logical proof exceeds admitted evidence budget")
            })?;
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn key(proof: u64, chunk: u64) -> [u8; 16] {
    let mut k = [0; 16];
    k[..8].copy_from_slice(&proof.to_be_bytes());
    k[8..].copy_from_slice(&chunk.to_be_bytes());
    k
}
fn encode(bytes: &[u8]) -> Result<String> {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let size = bytes
        .len()
        .checked_add(2)
        .and_then(|n| n.checked_div(3))
        .and_then(|n| n.checked_mul(4))
        .context("placement base64 overflow")?;
    let mut out = Vec::new();
    out.try_reserve_exact(size)?;
    for c in bytes.chunks(3) {
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
    let b = text.as_bytes();
    ensure!(
        !b.is_empty() && b.len().is_multiple_of(4),
        "placement base64 length differs"
    );
    let pad = b.iter().rev().take_while(|&&x| x == b'=').count();
    ensure!(pad <= 2, "placement base64 padding differs");
    let size = (b.len() / 4)
        .checked_mul(3)
        .and_then(|n| n.checked_sub(pad))
        .context("placement decoded length overflow")?;
    ensure!(
        size <= maximum,
        "placement decoded chunk exceeds its actual window"
    );
    let digit = |x: u8| -> Result<u8> {
        Ok(match x {
            b'A'..=b'Z' => x - b'A',
            b'a'..=b'z' => x - b'a' + 26,
            b'0'..=b'9' => x - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => anyhow::bail!("noncanonical placement base64"),
        })
    };
    let mut out = Vec::new();
    out.try_reserve_exact(size)?;
    for (i, c) in b.chunks_exact(4).enumerate() {
        let last = i + 1 == b.len() / 4;
        let a = digit(c[0])?;
        let n = digit(c[1])?;
        out.push((a << 2) | (n >> 4));
        if c[2] == b'=' {
            ensure!(
                last && c[3] == b'=' && n & 15 == 0,
                "placement padding bits differ"
            );
        } else {
            let m = digit(c[2])?;
            out.push((n << 4) | (m >> 2));
            if c[3] == b'=' {
                ensure!(last && m & 3 == 0, "placement padding bits differ");
            } else {
                out.push((m << 6) | digit(c[3])?);
            }
        }
    }
    ensure!(out.len() == size, "placement decoded length differs");
    Ok(out)
}

pub(crate) struct PagedPlacementEvidence {
    writer: Option<SortedRecordWriter>,
    closed: Option<SortedRecordStore>,
    scratch: SourceScratch,
    proofs: u64,
    records: u64,
    pending: Option<u64>,
    maximum: u64,
    chunk_bytes: usize,
    poisoned: bool,
    _memory: SourceRamLease,
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
        let ordinal = self
            .chunks
            .checked_add(1)
            .context("placement chunk ordinal overflow")?;
        self.writer.push(
            key(self.proof, ordinal),
            &Row::Chunk {
                ordinal: self.chunks,
                data: &data,
            },
        )?;
        self.chunks = ordinal;
        self.buffer.clear();
        Ok(())
    }
}
impl Write for Chunks<'_> {
    fn write(&mut self, mut b: &[u8]) -> io::Result<usize> {
        let length = b.len();
        let result = (|| -> Result<()> {
            self.bytes = self
                .bytes
                .checked_add(length as u64)
                .filter(|n| *n <= self.maximum)
                .context("native placement proof exceeded its prepaid complete bound")?;
            self.hash.update(b);
            while !b.is_empty() {
                let n = b.len().min(self.chunk_bytes - self.buffer.len());
                self.buffer.extend_from_slice(&b[..n]);
                b = &b[n..];
                if self.buffer.len() == self.chunk_bytes {
                    self.emit()?;
                }
            }
            Ok(())
        })();
        result.map(|()| length).map_err(io::Error::other)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl PagedPlacementEvidence {
    pub(crate) fn create(path: &Path, scratch: SourceScratch) -> Result<Self> {
        let group = scratch
            .artifact_group()
            .context("placement requires actual arena quota")?;
        ensure!(
            group.group() == crate::artifact_arena::ArtifactGroup::Capture,
            "placement group differs"
        );
        let window = scratch
            .budget()
            .record_bytes
            .min(u64::from(scratch.budget().page_bytes));
        let chunk_bytes = usize::try_from(
            window
                .checked_sub(512)
                .context("placement row cannot hold framing")?
                / 4
                * 3,
        )?;
        ensure!(chunk_bytes > 0, "placement chunk window is empty");
        let memory = scratch.lease_ram(
            (chunk_bytes as u64)
                .checked_mul(6)
                .and_then(|n| {
                    (path.as_os_str().as_encoded_bytes().len() as u64)
                        .checked_mul(12)
                        .and_then(|p| n.checked_add(p))
                })
                .and_then(|n| n.checked_add(65536))
                .context("placement chunk workspace overflow")?,
        )?;
        let writer = SortedRecordWriter::new(path, *b"N2RPLC02", &scratch)?;
        Ok(Self {
            writer: Some(writer),
            closed: None,
            maximum: scratch.budget().scratch_bytes,
            scratch,
            proofs: 0,
            records: 0,
            pending: None,
            chunk_bytes,
            poisoned: false,
            _memory: memory,
        })
    }
    fn reserve(&mut self, maximum: u64) -> Result<()> {
        ensure!(
            !self.poisoned && self.closed.is_none() && maximum > 0,
            "placement sink state differs"
        );
        let chunks = maximum.div_ceil(self.chunk_bytes as u64);
        let encoded = maximum
            .div_ceil(3)
            .checked_mul(4)
            .and_then(|n| chunks.checked_mul(256).and_then(|f| n.checked_add(f)))
            .and_then(|n| n.checked_add(2048))
            .context("complete placement proof wire overflow")?;
        let records = chunks
            .checked_add(2)
            .context("placement record count overflow")?;
        // Prepay ALL chunk rows and their ordinal directory, with the existing
        // SourceRangeWriter's extra base64/page/index/physical framing bound.
        self.writer
            .as_mut()
            .context("placement writer absent")?
            .reserve_record_batch(encoded, records)?;
        self.pending = Some(maximum);
        Ok(())
    }
    fn append(&mut self, kind: &'static str, value: &serde_json::Value) -> Result<()> {
        ensure!(
            !self.poisoned && self.closed.is_none() && matches!(kind, "section" | "move"),
            "placement sink state/kind differs"
        );
        if kind == "move" {
            ensure!(
                self.pending.is_some(),
                "native move lacks complete proof prepayment"
            );
        }
        if self.pending.is_none() {
            let mut c = Count {
                bytes: 0,
                maximum: self.maximum,
            };
            serde_json::to_writer(&mut c, value)?;
            self.reserve(c.bytes)?;
        }
        let maximum = self.pending.context("placement proof prepayment absent")?;
        self.poisoned = true;
        let writer = self.writer.as_mut().context("placement writer absent")?;
        writer.push(
            key(self.proofs, 0),
            &Row::Header {
                kind,
                maximum_json_bytes: maximum,
            },
        )?;
        let mut buffer = Vec::new();
        buffer.try_reserve_exact(self.chunk_bytes)?;
        let mut chunks = Chunks {
            writer,
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
            "empty placement proof"
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
        self.records = self
            .records
            .checked_add(count)
            .and_then(|n| n.checked_add(2))
            .context("placement complete record count overflow")?;
        self.proofs = self
            .proofs
            .checked_add(1)
            .context("placement proof count overflow")?;
        self.pending = None;
        self.poisoned = false;
        Ok(())
    }
    fn close(&mut self) -> Result<serde_json::Value> {
        ensure!(
            !self.poisoned && self.closed.is_none() && self.pending.is_none(),
            "placement cannot close after failure/twice"
        );
        let pin = self
            .writer
            .take()
            .context("placement writer absent")?
            .finish()?;
        ensure!(
            pin.records == self.records,
            "placement stored record count differs"
        );
        let owner = SortedRecordStore::open(&pin, &self.scratch)?;
        let mut record = 0;
        for proof in 0..self.proofs {
            ensure!(
                owner.key(record)? == key(proof, 0),
                "placement proof header order differs"
            );
            let ReadRow::Header {
                kind,
                maximum_json_bytes,
            } = owner.get(record)?
            else {
                anyhow::bail!("placement header missing")
            };
            ensure!(
                matches!(kind.as_str(), "section" | "move"),
                "placement header kind differs"
            );
            record += 1;
            let mut bytes = 0u64;
            let mut chunks = 0u64;
            let mut hash = Sha256::new();
            loop {
                match owner.get::<ReadRow>(record)? {
                    ReadRow::Chunk { ordinal, data } => {
                        ensure!(
                            ordinal == chunks && owner.key(record)? == key(proof, chunks + 1),
                            "placement chunk order differs"
                        );
                        let raw = decode(&data, self.chunk_bytes)?;
                        ensure!(!raw.is_empty(), "empty placement chunk");
                        bytes = bytes
                            .checked_add(raw.len() as u64)
                            .filter(|n| *n <= maximum_json_bytes)
                            .context("placement proof exceeds native bound")?;
                        hash.update(&raw);
                        chunks += 1;
                        record += 1;
                    }
                    ReadRow::Footer {
                        bytes: expected,
                        chunks: expected_chunks,
                        sha256,
                    } => {
                        ensure!(
                            owner.key(record)? == key(proof, u64::MAX)
                                && bytes == expected
                                && chunks == expected_chunks
                                && bytes > 0
                                && chunks > 0
                                && hex::encode(hash.finalize()) == sha256,
                            "complete placement proof digest/count differs"
                        );
                        record += 1;
                        break;
                    }
                    _ => anyhow::bail!("incomplete placement logical proof"),
                }
            }
        }
        ensure!(
            record == owner.len(),
            "placement proof archive has unconsumed rows"
        );
        owner.revalidate()?;
        let receipt = serde_json::json!({"kind":"complete-chunked-placement-evidence-v2","logical_proofs":self.proofs,
            "records":self.records,"store":owner.pin(),"wire_budget_bytes":self.maximum,"complete":true,"source_write_authority":false});
        self.closed = Some(owner);
        Ok(receipt)
    }
}
impl PlacementEvidenceSink for PagedPlacementEvidence {
    fn maximum_bytes(&self) -> u64 {
        self.maximum
    }
    fn reserve_next(&mut self, maximum: u64) -> io::Result<()> {
        self.reserve(maximum).map_err(io::Error::other)
    }
    fn push(&mut self, kind: &'static str, value: &serde_json::Value) -> io::Result<()> {
        self.append(kind, value).map_err(io::Error::other)
    }
    fn finish(&mut self) -> io::Result<serde_json::Value> {
        self.close().map_err(io::Error::other)
    }
}
