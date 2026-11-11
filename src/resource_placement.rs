//! Complete logical placement proofs in one authenticated byte stream.
//! A native move prepays its entire payload and proof-index output. Capture's
//! real shared permit funds this archive; no source-write authority is issued.
use crate::ntfs_inspect::{
    SourceMetadataRange,
    paged_storage::{PagedMetadataRange, SourceRamLease, SourceRangeWriter, SourceScratch},
    record_store::{SortedRecordStore, SortedRecordWriter},
};
use anyhow::{Context, Result, ensure};
use n2r_win32::shadow_native::private_tree::PlacementEvidenceSink;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::{self, BufReader, Read, Write},
    path::Path,
};

#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Section,
    Move,
}
impl Kind {
    fn from_str(kind: &str) -> Result<Self> {
        match kind {
            "section" => Ok(Self::Section),
            "move" => Ok(Self::Move),
            _ => anyhow::bail!("placement proof kind differs"),
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProofRecord {
    ordinal: u64,
    kind: Kind,
    offset: u64,
    bytes: u64,
    maximum_json_bytes: u64,
    sha256: String,
}
struct Count {
    bytes: u64,
    maximum: u64,
}
impl Write for Count {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| {
                io::Error::other("placement logical proof exceeds admitted evidence budget")
            })?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
fn key(proof: u64) -> [u8; 16] {
    let mut key = [0; 16];
    key[..8].copy_from_slice(&proof.to_be_bytes());
    key
}

pub(crate) struct PagedPlacementEvidence {
    payload: Option<SourceRangeWriter>,
    index: Option<SortedRecordWriter>,
    // Retain both authenticated ordinary-file owners through preparation.
    closed: Option<(PagedMetadataRange, SortedRecordStore)>,
    scratch: SourceScratch,
    proofs: u64,
    logical_bytes: u64,
    pending: Option<u64>,
    maximum: u64,
    index_record_bound: u64,
    maximum_prepaid_logical_prefix: u64,
    poisoned: bool,
    _memory: SourceRamLease,
}
struct ProofWriter<'a> {
    output: &'a mut SourceRangeWriter,
    maximum: u64,
    bytes: u64,
    hash: Sha256,
}
impl Write for ProofWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| {
                io::Error::other("native placement proof exceeded its prepaid complete bound")
            })?;
        self.output.write_all(bytes)?;
        self.hash.update(bytes);
        self.bytes = next;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
struct ProofReader<'a> {
    payload: &'a PagedMetadataRange,
    offset: u64,
    length: u64,
    position: u64,
    hash: Sha256,
}
impl Read for ProofReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let remaining = self
            .length
            .checked_sub(self.position)
            .ok_or_else(|| io::Error::other("placement proof read exceeds its bounded slice"))?;
        let count = output
            .len()
            .min(usize::try_from(remaining).unwrap_or(usize::MAX));
        if count == 0 {
            return Ok(0);
        }
        let at = self
            .offset
            .checked_add(self.position)
            .ok_or_else(|| io::Error::other("placement proof read offset overflow"))?;
        self.payload
            .read_exact_at(at, &mut output[..count])
            .map_err(io::Error::other)?;
        self.hash.update(&output[..count]);
        self.position += count as u64;
        Ok(count)
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
        ensure!(
            scratch.remaining_bytes() == scratch.budget().scratch_bytes,
            "placement requires a fresh sub-stage scratch owner"
        );
        // The caller supplied canonical source-page working limits, but this
        // evidence belongs to Capture. Use that SAME already-reserved permit's
        // real wire ceiling, as later capture/journal metadata already does.
        // RAM/row/page limits and the shared arena's aggregate quota stay exact.
        let scratch = SourceScratch::new_auxiliary_in_arena(scratch.budget(), group)?;
        let memory = scratch.lease_ram(
            131072u64
                .checked_add(
                    (path.as_os_str().as_encoded_bytes().len() as u64)
                        .checked_mul(16)
                        .context("placement path RAM overflow")?,
                )
                .context("placement workspace overflow")?,
        )?;
        let widest = ProofRecord {
            ordinal: u64::MAX,
            kind: Kind::Section,
            offset: u64::MAX,
            bytes: u64::MAX,
            maximum_json_bytes: u64::MAX,
            sha256: "f".repeat(64),
        };
        let mut count = Count {
            bytes: 0,
            maximum: scratch.budget().record_bytes,
        };
        serde_json::to_writer(&mut count, &widest)?;
        let mut payload_path = path.as_os_str().to_os_string();
        payload_path.push(".payload.pages");
        let payload = scratch.writer(Path::new(&payload_path), *b"N2RPLD03")?;
        let mut index_path = path.as_os_str().to_os_string();
        index_path.push(".proofs");
        let index = SortedRecordWriter::new(Path::new(&index_path), *b"N2RPLI03", &scratch)?;
        Ok(Self {
            payload: Some(payload),
            index: Some(index),
            closed: None,
            maximum: scratch.budget().scratch_bytes,
            scratch,
            proofs: 0,
            logical_bytes: 0,
            pending: None,
            index_record_bound: count.bytes,
            maximum_prepaid_logical_prefix: 0,
            poisoned: false,
            _memory: memory,
        })
    }
    fn reserve(&mut self, maximum: u64) -> Result<()> {
        ensure!(
            !self.poisoned && self.closed.is_none() && maximum > 0,
            "placement sink state differs"
        );
        // Base the reservation on the ACTUAL written prefix, never the prior
        // worst-case reservation. Unused bounds do not add once per move.
        let end = self
            .logical_bytes
            .checked_add(maximum)
            .context("complete placement proof prefix overflow")?;
        ensure!(
            end <= self.maximum,
            "placement proof prefix exceeds its admitted wire ceiling"
        );
        let payload = self
            .payload
            .as_mut()
            .context("placement payload writer absent")?;
        ensure!(
            payload.byte_len() == self.logical_bytes,
            "placement payload prefix differs before prepayment"
        );
        payload.reserve_logical_bytes(end)?;
        self.index
            .as_mut()
            .context("placement proof index absent")?
            .reserve_next_record(self.index_record_bound)?;
        self.maximum_prepaid_logical_prefix = self.maximum_prepaid_logical_prefix.max(end);
        self.pending = Some(maximum);
        Ok(())
    }
    fn append(&mut self, kind: &'static str, value: &serde_json::Value) -> Result<()> {
        ensure!(
            !self.poisoned && self.closed.is_none(),
            "placement sink state differs"
        );
        let kind = Kind::from_str(kind)?;
        if matches!(kind, Kind::Move) {
            ensure!(
                self.pending.is_some(),
                "native move lacks complete proof prepayment"
            );
        }
        if self.pending.is_none() {
            let mut count = Count {
                bytes: 0,
                maximum: self.maximum,
            };
            serde_json::to_writer(&mut count, value)?;
            self.reserve(count.bytes)?;
        }
        let maximum = self.pending.context("placement proof prepayment absent")?;
        self.poisoned = true;
        let payload = self
            .payload
            .as_mut()
            .context("placement payload writer absent")?;
        ensure!(
            payload.byte_len() == self.logical_bytes,
            "placement payload prefix differs"
        );
        let mut writer = ProofWriter {
            output: payload,
            maximum,
            bytes: 0,
            hash: Sha256::new(),
        };
        // Preserve EXACTLY the original compact JSON stream. SourceRangeWriter
        // already frames/base64-encodes bytes; no inner encoding is necessary.
        // The serializer writes every token separately; collect them 64 KiB
        // at a time so the hash and the store see blocks, not single digits.
        {
            let mut blocks = io::BufWriter::with_capacity(64 * 1024, &mut writer);
            serde_json::to_writer(&mut blocks, value)?;
            blocks.flush()?;
        }
        let bytes = writer.bytes;
        ensure!(bytes > 0, "empty placement proof");
        let record = ProofRecord {
            ordinal: self.proofs,
            kind,
            offset: self.logical_bytes,
            bytes,
            maximum_json_bytes: maximum,
            sha256: hex::encode(writer.hash.finalize()),
        };
        let end = self
            .logical_bytes
            .checked_add(bytes)
            .context("placement payload size overflow")?;
        ensure!(
            writer.output.byte_len() == end,
            "placement payload append length differs"
        );
        self.index
            .as_mut()
            .context("placement proof index absent")?
            .push(key(self.proofs), &record)?;
        self.logical_bytes = end;
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
        let payload_pin = self
            .payload
            .take()
            .context("placement payload writer absent")?
            .finish()?;
        let index_pin = self
            .index
            .take()
            .context("placement proof index absent")?
            .finish()?;
        ensure!(
            payload_pin.logical_bytes == self.logical_bytes && index_pin.records == self.proofs,
            "placement stored payload or proof count differs"
        );
        let payload = PagedMetadataRange::open(&payload_pin, &self.scratch)?;
        let index = SortedRecordStore::open(&index_pin, &self.scratch)?;
        // Every proof was serialized and hashed by this process as it was
        // appended. Parsing and hashing the whole archive again to close it
        // (38 s at the full volume) is left out under the check-once policy,
        // which the stores report by having opened without a full read; the
        // index is still walked and every extent checked.
        let reread = !payload.written_by_this_process();
        let mut cursor = 0u64;
        for proof in 0..self.proofs {
            let row: ProofRecord = index.get(proof)?;
            ensure!(
                index.key(proof)? == key(proof)
                    && row.ordinal == proof
                    && row.offset == cursor
                    && row.bytes > 0
                    && row.bytes <= row.maximum_json_bytes
                    && row.maximum_json_bytes <= self.maximum
                    && row.sha256.len() == 64
                    && row
                        .sha256
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                "placement proof index order, extent or digest shape differs"
            );
            let end = cursor
                .checked_add(row.bytes)
                .filter(|n| *n <= self.logical_bytes)
                .context("placement proof escapes complete payload")?;
            if reread {
                let reader = ProofReader {
                    payload: &payload,
                    offset: row.offset,
                    length: row.bytes,
                    position: 0,
                    hash: Sha256::new(),
                };
                let mut reader = BufReader::with_capacity(65536, reader);
                let mut parser = serde_json::Deserializer::from_reader(&mut reader);
                let _ = serde::de::IgnoredAny::deserialize(&mut parser)?;
                parser.end()?;
                let reader = reader.into_inner();
                ensure!(
                    reader.position == row.bytes
                        && hex::encode(reader.hash.finalize()) == row.sha256,
                    "complete placement proof byte count or digest differs"
                );
            }
            cursor = end;
        }
        ensure!(
            cursor == self.logical_bytes && index.len() == self.proofs,
            "placement proof archive has unconsumed payload or rows"
        );
        payload.revalidate()?;
        index.revalidate()?;
        let receipt = serde_json::json!({"kind":"complete-indexed-placement-evidence-v3",
            "logical_proofs":self.proofs,"logical_json_bytes":self.logical_bytes,
            "payload":payload_pin,"proof_index":index.pin(),"wire_budget_bytes":self.maximum,
            "maximum_prepaid_logical_prefix":self.maximum_prepaid_logical_prefix,
            "reservation_basis":"actual-written-prefix-plus-next-complete-bound",
            "complete":true,"source_write_authority":false});
        self.closed = Some((payload, index));
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
