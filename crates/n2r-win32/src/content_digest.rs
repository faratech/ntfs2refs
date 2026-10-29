//! The file-content digest: XXH3-128 in canonical (big-endian) lowercase hex
//! (user decision, 2026-10-29). It compares a source stream with its inspected
//! and converted copies and detects accidental difference; it is not a
//! cryptographic hash and does not match Get-FileHash. Fields that carry it
//! keep their historical `*sha256` names; small fixed digests (residual tails,
//! images, metadata) stay SHA-256.
pub const ALGORITHM: &str = "xxh3-128";
pub const HEX_LEN: usize = 32;

/// Streaming content digest over exactly the bytes passed to `update`.
pub struct Hasher(Box<xxhash_rust::xxh3::Xxh3>);

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    pub fn new() -> Self {
        Self(Box::new(xxhash_rust::xxh3::Xxh3::new()))
    }

    pub fn update(&mut self, bytes: &[u8]) {
        self.0.update(bytes);
    }

    pub fn finish(&self) -> String {
        hex::encode(self.0.digest128().to_be_bytes())
    }
}

/// The content digest of `bytes`.
pub fn of(bytes: &[u8]) -> String {
    hex::encode(xxhash_rust::xxh3::xxh3_128(bytes).to_be_bytes())
}

/// Whether `value` has the content digest's lowercase hex form.
pub fn is_hex(value: &str) -> bool {
    value.len() == HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
