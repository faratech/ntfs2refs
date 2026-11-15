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

/// The SHA-256 of a piece of evidence held in memory: Windows' own
/// implementation where there is one and the piece is long enough for it to
/// pay, the compiled-in one otherwise. The digest is the same either way.
pub fn sha256(bytes: &[u8]) -> std::io::Result<[u8; 32]> {
    // Below this a call into the system costs more than it saves.
    #[cfg(windows)]
    if bytes.len() >= 512 {
        return crate::sha256_native::digest(bytes);
    }
    use sha2::Digest;
    Ok(sha2::Sha256::digest(bytes).into())
}

/// Whether `value` has the content digest's lowercase hex form.
pub fn is_hex(value: &str) -> bool {
    value.len() == HEX_LEN
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests elsewhere derive their expectations from `of`. This pins `of`
    // itself to the algorithm, so they cannot all drift together.
    #[test]
    fn the_digest_is_xxh3_128_in_canonical_hex() {
        // The published XXH3-128 value of the empty input with seed 0.
        assert_eq!(of(&[]), "99aa06d3014798d86001c324468d497f");
        assert_eq!(Hasher::new().finish(), of(&[]));

        let mut streamed = Hasher::new();
        streamed.update(b"a");
        streamed.update(b"bc");
        assert_eq!(streamed.finish(), of(b"abc"));
        assert_ne!(of(b"abc"), of(b"abd"));
    }

    #[test]
    fn the_evidence_digest_is_sha_256_at_every_length() {
        use sha2::Digest;
        // Either side of where the system's implementation takes over, and
        // several blocks.
        for length in [0usize, 1, 55, 56, 64, 511, 512, 513, 4096, 70_001] {
            let bytes: Vec<u8> = (0..length).map(|index| (index * 31 + 7) as u8).collect();
            let expected: [u8; 32] = sha2::Sha256::digest(&bytes).into();
            // Twice: the second call reuses the thread's hash object.
            assert_eq!(sha256(&bytes).unwrap(), expected, "length {length}");
            assert_eq!(sha256(&bytes).unwrap(), expected, "length {length}, again");
        }
    }

    #[test]
    fn only_the_32_character_lowercase_form_is_a_content_digest() {
        assert!(is_hex(&of(b"abc")));
        assert_eq!(of(b"abc").len(), HEX_LEN);
        // A SHA-256 in hex, an uppercase digest and a non-hex string are not.
        assert!(!is_hex(&"a".repeat(64)));
        assert!(!is_hex(&"A".repeat(HEX_LEN)));
        assert!(!is_hex(&"z".repeat(HEX_LEN)));
    }
}
