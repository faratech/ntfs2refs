//! Lossless compact transport for the complete bytes of a bitmap-window proof.
//! This changes storage only. Decode and replay every native query before using
//! any claimed field; neither this transport nor a window digest is a full map.
use crate::{attestation::IoctlQuery, bitmap_paging::PAGE_BYTES, bitmap_window};
use serde::{Deserialize, Serialize};
use std::io;

pub const ENCODING: &str = "native-bitmap-window-compact-v1";

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
enum Codec {
    #[serde(rename = "raw-hex-v1")]
    Raw,
    #[serde(rename = "rle-hex-v1")]
    Rle,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteBuffer {
    codec: Codec,
    decoded_bytes: usize,
    decoded_sha256: String,
    data_hex: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Query {
    pub code: u32,
    pub input: ByteBuffer,
    pub bytes: ByteBuffer,
    pub native_error: Option<i32>,
}

/// All original header fields survive independently of the transport version.
/// The byte-buffer hashes cover original bytes, not compressed representations.
/// They must never populate Candidate.bitmap_sha256 or another full-map field.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Proof {
    pub schema_version: u32,
    pub encoding: String,
    pub window_schema_version: u32,
    pub window_encoding: String,
    pub request: bitmap_window::Request,
    pub template: ByteBuffer,
    pub declared_volume_clusters: u64,
    pub window_bits: ByteBuffer,
    pub allocated_clusters: u64,
    pub window_sha256: String,
    pub returned_bytes: usize,
    pub whole_volume_complete: bool,
    pub queries: Vec<Query>,
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn unavailable() -> io::Error {
    io::Error::new(
        io::ErrorKind::OutOfMemory,
        "compact window storage unavailable",
    )
}

fn zeros(bytes: usize) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    output.try_reserve_exact(bytes).map_err(|_| unavailable())?;
    output.resize(bytes, 0);
    Ok(output)
}

fn digest_valid(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|v| v.is_ascii_digit() || (b'a'..=b'f').contains(&v))
}

fn hex_encode(bytes: &[u8]) -> io::Result<String> {
    let length = bytes
        .len()
        .checked_mul(2)
        .ok_or_else(|| bad("hex length overflow"))?;
    let mut output = zeros(length)?;
    hex::encode_to_slice(bytes, &mut output).map_err(|_| bad("hex encoding failed"))?;
    String::from_utf8(output).map_err(|_| bad("invalid hexadecimal encoding"))
}

// Packets carry 1..128 bytes. High-bit packets repeat the following byte;
// low-bit packets contain that many literal bytes. All lengths are explicit.
fn encode_rle(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(bytes.len())
        .map_err(|_| unavailable())?;
    let mut cursor = 0;
    while cursor < bytes.len() {
        let repeated = repeat_length(bytes, cursor);
        if repeated >= 3 {
            if encoded
                .len()
                .checked_add(2)
                .is_none_or(|size| size >= bytes.len())
            {
                return Ok(Vec::new());
            }
            encoded.extend_from_slice(&[0x80 | (repeated - 1) as u8, bytes[cursor]]);
            cursor += repeated;
        } else {
            let start = cursor;
            cursor += repeated;
            while cursor < bytes.len() && cursor - start < 128 {
                let repeated = repeat_length(bytes, cursor);
                if repeated >= 3 {
                    break;
                }
                cursor += repeated.min(128 - (cursor - start));
            }
            if encoded
                .len()
                .checked_add((cursor - start) + 1)
                .is_none_or(|size| size >= bytes.len())
            {
                return Ok(Vec::new());
            }
            encoded.push((cursor - start - 1) as u8);
            encoded.extend_from_slice(&bytes[start..cursor]);
        }
    }
    Ok(encoded)
}

fn repeat_length(bytes: &[u8], start: usize) -> usize {
    bytes[start..]
        .iter()
        .take(128)
        .take_while(|&&value| value == bytes[start])
        .count()
}

impl ByteBuffer {
    fn encode(bytes: &[u8]) -> io::Result<Self> {
        let rle = encode_rle(bytes)?;
        let (codec, stored) = if !rle.is_empty() && rle.len() < bytes.len() {
            (Codec::Rle, rle.as_slice())
        } else {
            (Codec::Raw, bytes)
        };
        Ok(Self {
            codec,
            decoded_bytes: bytes.len(),
            decoded_sha256: hex_encode(&crate::content_digest::sha256(bytes)?)?,
            data_hex: hex_encode(stored)?,
        })
    }

    fn decode(&self, maximum: usize) -> io::Result<Vec<u8>> {
        if self.decoded_bytes > maximum
            || !digest_valid(&self.decoded_sha256)
            || !self.data_hex.len().is_multiple_of(2)
        {
            return Err(bad(
                "compact window buffer exceeds bounds or has invalid hash/hex",
            ));
        }
        let encoded_bytes = self.data_hex.len() / 2;
        match self.codec {
            Codec::Raw if encoded_bytes != self.decoded_bytes => {
                return Err(bad("raw compact buffer length differs"));
            }
            Codec::Rle if encoded_bytes == 0 || encoded_bytes >= self.decoded_bytes => {
                return Err(bad("RLE compact buffer is empty or not smaller than raw"));
            }
            _ => (),
        }
        let mut encoded = zeros(encoded_bytes)?;
        hex::decode_to_slice(&self.data_hex, &mut encoded)
            .map_err(|_| bad("invalid compact buffer hexadecimal bytes"))?;
        let output = match self.codec {
            Codec::Raw => encoded,
            Codec::Rle => {
                let mut output = zeros(self.decoded_bytes)?;
                let mut input_at = 0;
                let mut output_at = 0usize;
                while input_at < encoded.len() {
                    let control = encoded[input_at];
                    input_at += 1;
                    let count = usize::from(control & 0x7f) + 1;
                    let end = output_at
                        .checked_add(count)
                        .filter(|&end| end <= output.len())
                        .ok_or_else(|| bad("RLE output exceeds declared length"))?;
                    if control & 0x80 != 0 {
                        let value = *encoded
                            .get(input_at)
                            .ok_or_else(|| bad("truncated RLE repeated packet"))?;
                        input_at += 1;
                        output[output_at..end].fill(value);
                    } else {
                        let literal_end = input_at
                            .checked_add(count)
                            .filter(|&end| end <= encoded.len())
                            .ok_or_else(|| bad("truncated RLE literal packet"))?;
                        output[output_at..end].copy_from_slice(&encoded[input_at..literal_end]);
                        input_at = literal_end;
                    }
                    output_at = end;
                }
                if output_at != output.len() {
                    return Err(bad("RLE decoded length differs"));
                }
                output
            }
        };
        if hex_encode(&crate::content_digest::sha256(&output)?)? != self.decoded_sha256 {
            return Err(bad("compact buffer decoded SHA-256 differs"));
        }
        Ok(output)
    }
}

/// Encode every byte losslessly. This does not validate or authenticate the
/// underlying observation; callers of persisted transport must use replay.
pub fn from_proof(proof: bitmap_window::Proof) -> io::Result<Proof> {
    let mut queries = Vec::new();
    queries
        .try_reserve_exact(proof.queries.len())
        .map_err(|_| unavailable())?;
    for query in proof.queries {
        queries.push(Query {
            code: query.code,
            input: ByteBuffer::encode(&query.input)?,
            bytes: ByteBuffer::encode(&query.bytes)?,
            native_error: query.native_error,
        });
    }
    Ok(Proof {
        schema_version: 1,
        encoding: ENCODING.into(),
        window_schema_version: proof.schema_version,
        window_encoding: proof.encoding,
        request: proof.request,
        template: ByteBuffer::encode(&proof.template)?,
        declared_volume_clusters: proof.declared_volume_clusters,
        window_bits: ByteBuffer::encode(&proof.window_bits)?,
        allocated_clusters: proof.allocated_clusters,
        window_sha256: proof.window_sha256,
        returned_bytes: proof.returned_bytes,
        whole_volume_complete: proof.whole_volume_complete,
        queries,
    })
}

/// Bound every decoded allocation and cumulative query bytes, then delegate all
/// native header/status/paging/bit checks to the existing independent replay.
pub fn replay(
    proof: &Proof,
    limits: bitmap_window::Limits,
) -> io::Result<bitmap_window::Observation> {
    if proof.schema_version != 1
        || proof.encoding != ENCODING
        || proof.window_schema_version != 1
        || proof.window_encoding != bitmap_window::ENCODING
        || proof.whole_volume_complete
        || !digest_valid(&proof.window_sha256)
        || proof.queries.is_empty()
        || proof.queries.len() > limits.max_pages
        || !matches!(proof.template.decoded_bytes, 8 | 16)
    {
        return Err(bad("compact bitmap-window proof schema or limits differ"));
    }
    let expected_window = usize::try_from(proof.request.clusters.div_ceil(8))
        .map_err(|_| bad("compact window length exceeds address space"))?;
    if proof.window_bits.decoded_bytes != expected_window
        || expected_window > limits.max_window_bytes
    {
        return Err(bad("compact window bits exceed requested range or limits"));
    }
    let maximum_page = limits.page_bytes.min(PAGE_BYTES);
    let mut returned = 0usize;
    for query in &proof.queries {
        if !(17..=maximum_page).contains(&query.bytes.decoded_bytes)
            || !matches!(query.input.decoded_bytes, 8 | 16)
        {
            return Err(bad("compact window query exceeds replay bounds"));
        }
        returned = returned
            .checked_add(query.bytes.decoded_bytes)
            .filter(|&count| count <= limits.max_returned_bytes)
            .ok_or_else(|| bad("compact window cumulative byte budget exceeded"))?;
    }
    if returned != proof.returned_bytes {
        return Err(bad("compact window returned-byte count differs"));
    }
    let template = proof.template.decode(16)?;
    let window_bits = proof.window_bits.decode(limits.max_window_bytes)?;
    let mut queries = Vec::new();
    queries
        .try_reserve_exact(proof.queries.len())
        .map_err(|_| unavailable())?;
    for query in &proof.queries {
        queries.push(IoctlQuery {
            code: query.code,
            input: query.input.decode(16)?,
            bytes: query.bytes.decode(maximum_page)?,
            native_error: query.native_error,
        });
    }
    bitmap_window::replay(
        &bitmap_window::Proof {
            schema_version: proof.window_schema_version,
            encoding: proof.window_encoding.clone(),
            request: proof.request,
            template,
            declared_volume_clusters: proof.declared_volume_clusters,
            window_bits,
            allocated_clusters: proof.allocated_clusters,
            window_sha256: proof.window_sha256.clone(),
            returned_bytes: proof.returned_bytes,
            whole_volume_complete: proof.whole_volume_complete,
            queries,
        },
        limits,
    )
}
