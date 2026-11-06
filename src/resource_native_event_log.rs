//! Lossless diagnostic encoding only; this never grants conversion authority.
//!
//! Encode on a cloned candidate state. Commit that state only after the whole
//! batch is flushed, synced and its exact EOF verified. References may point to
//! an earlier literal in the same batch, so partial batches must not commit.
use n2r_win32::NativeEvent;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io;

pub(super) const ENCODING: &str = "lossless-native-events-v1";
const INLINE_BYTES: usize = 64;
const CACHE_ENTRIES: usize = 128;

#[derive(Clone, Copy)]
struct CacheEntry {
    digest: [u8; 32],
    byte_length: u64,
    id: u64,
}

/// The fixed cache occupies under 8 KiB of the existing 5 MiB ledger RAM
/// reservation. It retains only digest/length/id metadata, never raw payloads.
/// Eviction loses only compression: the next occurrence emits a new literal.
#[derive(Clone)]
pub(super) struct NativeEventEncoder {
    cache: [Option<CacheEntry>; CACHE_ENTRIES],
    next_slot: usize,
    last_literal_id: u64,
}

impl Default for NativeEventEncoder {
    fn default() -> Self {
        Self {
            cache: [None; CACHE_ENTRIES],
            next_slot: 0,
            last_literal_id: 0,
        }
    }
}

const _: () = assert!(std::mem::size_of::<NativeEventEncoder>() <= 8 * 1024);

#[derive(Serialize)]
struct Literal<'a> {
    id: u64,
    byte_length: u64,
    sha256: String,
    bytes: &'a [u8],
}

#[derive(Serialize)]
struct Reference {
    id: u64,
    byte_length: u64,
    sha256: String,
}

#[derive(Serialize)]
#[serde(untagged)]
enum EncodedBytes<'a> {
    Raw(&'a [u8]),
    Literal { literal: Literal<'a> },
    Reference { r#ref: Reference },
}

/// Operation, status and event order remain unchanged. Short byte vectors keep
/// their original array representation; every long vector has a reconstructible
/// literal or a digest-and-length-checked reference to an earlier literal ID.
#[derive(Serialize)]
pub(super) struct EncodedNativeEvent<'a> {
    operation: &'a str,
    control_code: u32,
    input: EncodedBytes<'a>,
    succeeded: bool,
    native_error: Option<i32>,
    output: EncodedBytes<'a>,
}

impl NativeEventEncoder {
    pub(super) fn encode<'events>(
        &mut self,
        events: &'events [NativeEvent],
    ) -> io::Result<Vec<EncodedNativeEvent<'events>>> {
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(events.len())
            .map_err(io::Error::other)?;
        for event in events {
            // Input precedes output both in encoding and in serialized order.
            let input = self.bytes(&event.input)?;
            let output = self.bytes(&event.output)?;
            encoded.push(EncodedNativeEvent {
                operation: &event.operation,
                control_code: event.control_code,
                input,
                succeeded: event.succeeded,
                native_error: event.native_error,
                output,
            });
        }
        Ok(encoded)
    }

    fn bytes<'events>(&mut self, bytes: &'events [u8]) -> io::Result<EncodedBytes<'events>> {
        if bytes.len() <= INLINE_BYTES {
            return Ok(EncodedBytes::Raw(bytes));
        }
        let byte_length = u64::try_from(bytes.len()).map_err(io::Error::other)?;
        let digest: [u8; 32] = Sha256::digest(bytes).into();
        if let Some(entry) = self
            .cache
            .iter()
            .flatten()
            .find(|entry| entry.byte_length == byte_length && entry.digest == digest)
        {
            return Ok(EncodedBytes::Reference {
                r#ref: Reference {
                    id: entry.id,
                    byte_length,
                    sha256: hex::encode(digest),
                },
            });
        }
        let id = self
            .last_literal_id
            .checked_add(1)
            .ok_or_else(|| io::Error::other("native-event literal ID exhausted"))?;
        self.last_literal_id = id;
        self.cache[self.next_slot] = Some(CacheEntry {
            digest,
            byte_length,
            id,
        });
        self.next_slot = (self.next_slot + 1) % CACHE_ENTRIES;
        Ok(EncodedBytes::Literal {
            literal: Literal {
                id,
                byte_length,
                sha256: hex::encode(digest),
                bytes,
            },
        })
    }
}
