//! Fixed-width preparation and restoration of observed process-trust ACE profiles.
//!
//! This module only describes byte replacements. It never opens a filesystem,
//! grants native-write authority, or treats a placeholder as preserved security.
//! The ReFS 3.14 OID 0x530 profile uses the same descriptor-only ROL-3 hash as
//! NTFS security descriptors. Its layout and hash facts are recorded in
//! docs/research/user-report-reconciliation.md and the pinned structural
//! reference; no external implementation is incorporated here.
use crate::security_descriptor::{self, AclLayout, Layout};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{self, Result};

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
macro_rules! ensure {
    ($condition:expr, $message:literal $(,)?) => {
        if !$condition {
            return Err(invalid($message));
        }
    };
}

/// A hard allocation ceiling in addition to the owning row's admitted limit.
pub const MAX_DESCRIPTOR_BYTES: usize = security_descriptor::MAX_DESCRIPTOR_BYTES;
const TRUST_ACE_TYPE: u8 = 0x14;
// Native ReFS preserves the measured callback audit's valid file-access mask.
// Type 0x02 needs a compensating reserved bit that Windows strips on restore.
const AUDIT_ACE_TYPE: u8 = 0x0d;
const TRUST_ACE_BYTES: usize = 24;
const PPL_TRUST_ACE: [u8; TRUST_ACE_BYTES] = [
    0x14, 0x03, 0x18, 0x00, 0xa9, 0x01, 0x1f, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
    0x00, 0x02, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
];
const ZERO_TRUST_ACE: [u8; TRUST_ACE_BYTES] = [
    0x14, 0x03, 0x18, 0x00, 0xff, 0xff, 0xff, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];
const fn with_flags(mut ace: [u8; TRUST_ACE_BYTES], flags: u8) -> [u8; TRUST_ACE_BYTES] {
    ace[1] = flags;
    ace
}
// Exact source corpus SHA-256:
// fa7590b3538547d2742ad239bced1a4a5c86a2f3758ec77005d32473c6b1e7c5.
// These seven tuples admit byte-transform candidates only. Native callback
// mask/flag preservation and canonical raw restoration require qualification.
const OBSERVED_TRUST_ACES: [[u8; TRUST_ACE_BYTES]; 7] = [
    with_flags(PPL_TRUST_ACE, 0x00),
    with_flags(PPL_TRUST_ACE, 0x03),
    with_flags(PPL_TRUST_ACE, 0x10),
    with_flags(PPL_TRUST_ACE, 0x13),
    with_flags(ZERO_TRUST_ACE, 0x03),
    with_flags(ZERO_TRUST_ACE, 0x10),
    with_flags(ZERO_TRUST_ACE, 0x13),
];
fn observed_trust_ace(bytes: &[u8]) -> bool {
    OBSERVED_TRUST_ACES.iter().any(|profile| bytes == profile)
}
const ACE_PREFIX_BYTES: usize = 8;

/// Complete descriptor identities, retained for exact matching in the frozen
/// native table. Native creation and subsequent strict readback are separate
/// requirements; successfully preparing these bytes proves neither.
#[derive(Clone, Debug)]
pub struct TrustLabelPlaceholder {
    pub original: Vec<u8>,
    pub placeholder: Vec<u8>,
    pub descriptor_hash: u32,
    pub ace_offset: usize,
    pub placeholder_mask: u32,
}

/// A checked replacement relative to the start of a SECURITY_DESCRIPTOR_RELATIVE.
/// The complete expected descriptor must also match before a caller may use it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DescriptorBytePatch {
    pub offset: usize,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Clone, Debug, Serialize)]
pub struct DescriptorPatchPlan {
    pub descriptor_length: usize,
    pub descriptor_hash: u32,
    pub placeholder_sha256: String,
    pub original_sha256: String,
    pub patches: Vec<DescriptorBytePatch>,
}

/// Temporary native-constructor expectations. These bytes never replace the
/// original source domain or its digest and do not attest trust preservation.
#[derive(Debug)]
pub struct ConstructorSecurityViews {
    pub stored: Vec<u8>,
    pub api: Option<Vec<u8>>,
}

impl ConstructorSecurityViews {
    /// Derive the hash-preserving mask only from the stored descriptor. The
    /// API view can have different relative offsets or inherited projections;
    /// it receives that identical mask, retaining every other API-view byte.
    pub fn prepare(
        stored_original: &[u8],
        api_original: Option<&[u8]>,
        maximum_bytes: u64,
    ) -> Result<Option<Self>> {
        let stored = prepare_trust_label_placeholder(stored_original, maximum_bytes)?;
        let Some(stored) = stored else {
            if let Some(api) = api_original {
                let api_layout = layout(api, maximum_bytes)?;
                ensure!(
                    original_trust_ace(api, api_layout)?.is_none(),
                    "API process-trust label lacks the original stored label"
                );
            }
            return Ok(None);
        };
        let api = api_original
            .map(|original| -> Result<Vec<u8>> {
                let original_layout = layout(original, maximum_bytes)?;
                let at = original_trust_ace(original, original_layout)?.ok_or_else(|| {
                    invalid("original API view lacks an observed process-trust ACE")
                })?;
                let mut placeholder = original.to_vec();
                placeholder[at] = AUDIT_ACE_TYPE;
                placeholder[at + 4..at + 8].copy_from_slice(&stored.placeholder_mask.to_le_bytes());
                let temporary_layout = validate_placeholder(
                    &placeholder,
                    maximum_bytes,
                    at,
                    stored.placeholder_mask,
                    span(original, at, TRUST_ACE_BYTES)?,
                )?;
                ensure!(
                    original_layout == temporary_layout,
                    "constructor API placeholder changes descriptor layout"
                );
                Ok(placeholder)
            })
            .transpose()?;
        Ok(Some(Self {
            stored: stored.placeholder,
            api,
        }))
    }
}

/// One paid transient workspace reused across constructor rows, including the
/// independent stored/API validation windows and their bounded ACE indexes.
pub fn constructor_working_bytes(maximum_bytes: u64) -> Result<u64> {
    maximum_bytes
        .min(MAX_DESCRIPTOR_BYTES as u64)
        .checked_mul(16)
        .and_then(|bytes| bytes.checked_add(4096))
        .ok_or_else(|| invalid("constructor security workspace overflow"))
}

fn span(bytes: &[u8], offset: usize, length: usize) -> Result<&[u8]> {
    let end = offset
        .checked_add(length)
        .ok_or_else(|| invalid("SD range overflow"))?;
    bytes
        .get(offset..end)
        .ok_or_else(|| invalid("SD range exceeds descriptor"))
}

fn dword(bytes: &[u8], offset: usize) -> Result<u32> {
    let value = span(bytes, offset, 4)?;
    Ok(u32::from_le_bytes([value[0], value[1], value[2], value[3]]))
}

/// Descriptor-only NTFS/ReFS hash; not a collision-resistant identity.
pub fn descriptor_hash32(bytes: &[u8]) -> Result<u32> {
    ensure!(
        bytes.len().is_multiple_of(4),
        "unaligned security hash input"
    );
    let mut hash = 0u32;
    for word in bytes.chunks_exact(4) {
        let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        hash = hash.rotate_left(3).wrapping_add(value);
    }
    Ok(hash)
}

fn descriptor_sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn acl_aces(bytes: &[u8], acl: AclLayout) -> Result<Vec<(usize, usize)>> {
    let Some(offset) = acl.offset else {
        return Ok(Vec::new());
    };
    let end = offset
        .checked_add(acl.length)
        .ok_or_else(|| invalid("SD ACL overflow"))?;
    let mut at = offset
        .checked_add(8)
        .ok_or_else(|| invalid("SD ACE offset overflow"))?;
    let mut result = Vec::with_capacity(usize::from(acl.ace_count));
    for _ in 0..acl.ace_count {
        let header = span(bytes, at, 4)?;
        let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
        let next = at
            .checked_add(length)
            .ok_or_else(|| invalid("SD ACE range overflow"))?;
        ensure!(length >= 16 && next <= end, "SD ACE exceeds its ACL");
        result.push((at, length));
        at = next;
    }
    Ok(result)
}

/// Windows layout validation covers all supported ACE forms independently of
/// this transform. Disjointness additionally prevents a SACL replacement from
/// changing a DACL, SID, or aliased component through overlapping offsets.
fn layout(bytes: &[u8], maximum_bytes: u64) -> Result<Layout> {
    ensure!(
        bytes.len() <= MAX_DESCRIPTOR_BYTES && bytes.len() as u64 <= maximum_bytes,
        "ReFS SD exceeds its hard or admitted row bound"
    );
    let layout = security_descriptor::validate_with_limit(bytes, maximum_bytes)?;
    let mut components = Vec::with_capacity(4);
    for (kind, sid) in [(0u8, layout.owner), (1u8, layout.group)] {
        if let Some(sid) = sid {
            components.push((sid.offset, sid.offset + sid.length, kind));
        }
    }
    for (kind, acl) in [(2u8, layout.sacl), (3u8, layout.dacl)] {
        if let Some(offset) = acl.offset {
            components.push((offset, offset + acl.length, kind));
        }
    }
    for (index, &(start, end, kind)) in components.iter().enumerate() {
        for &(other_start, other_end, other_kind) in &components[index + 1..] {
            // An identical owner/group SID may be shared by relative SDs.
            let shared_sid = kind < 2 && other_kind < 2 && start == other_start && end == other_end;
            ensure!(
                shared_sid || end <= other_start || other_end <= start,
                "ReFS SD components overlap or alias ACL storage"
            );
        }
    }
    Ok(layout)
}

/// Return the unique observed trust ACE, refusing every other type-20 shape or
/// placement. Other already-validated ACE bytes remain uninterpreted and exact.
fn original_trust_ace(bytes: &[u8], layout: Layout) -> Result<Option<usize>> {
    for (at, _) in acl_aces(bytes, layout.dacl)? {
        ensure!(
            bytes[at] != TRUST_ACE_TYPE,
            "process-trust ACE occurs in DACL"
        );
    }
    let mut found = None;
    for (at, length) in acl_aces(bytes, layout.sacl)? {
        if bytes[at] == TRUST_ACE_TYPE {
            ensure!(
                length == TRUST_ACE_BYTES && observed_trust_ace(span(bytes, at, length)?),
                "process-trust ACE is outside the observed preservation profiles"
            );
            ensure!(
                found.is_none(),
                "multiple process-trust ACEs are unsupported"
            );
            found = Some(at);
        }
    }
    Ok(found)
}

/// Validate the placeholder on its own, including the exact targeted audit ACE
/// and the absence of any process-trust ACE that native creation could omit.
fn validate_placeholder(
    bytes: &[u8],
    maximum_bytes: u64,
    wanted_at: usize,
    wanted_mask: u32,
    original_ace: &[u8],
) -> Result<Layout> {
    ensure!(
        observed_trust_ace(original_ace),
        "placeholder original ACE is outside the observed profiles"
    );
    let layout = layout(bytes, maximum_bytes)?;
    let mut matched = false;
    for acl in [layout.dacl, layout.sacl] {
        for (at, length) in acl_aces(bytes, acl)? {
            ensure!(
                bytes[at] != TRUST_ACE_TYPE,
                "placeholder retains a process-trust ACE"
            );
            if at == wanted_at {
                let entry = span(bytes, at, length)?;
                ensure!(
                    acl == layout.sacl
                        && length == original_ace.len()
                        && entry[0] == AUDIT_ACE_TYPE
                        && entry[1..4] == original_ace[1..4]
                        && entry[8..] == original_ace[8..]
                        && dword(entry, 4)? == wanted_mask,
                    "placeholder audit ACE shape or placement differs"
                );
                matched = true;
            }
        }
    }
    ensure!(matched, "placeholder audit ACE is absent from SACL");
    Ok(layout)
}

/// Construct an ordinary audit-callback placeholder for an observed process-trust
/// profile. Every other byte is preserved, including offsets, ACL capacity,
/// control, SIDs, ACE order, opaque application data and descriptor padding.
///
/// The mask is solved from the actual prefix state. A fixed adjustment is wrong
/// when addition crosses a boundary that is moved by the following rotation.
/// Hash states become equal immediately after the ACE mask DWORD, so all suffix
/// bytes, the total hash and the existing SecurityId can remain unchanged.
/// A descriptor without process-trust ACEs returns None after validation.
pub fn prepare_trust_label_placeholder(
    original: &[u8],
    maximum_bytes: u64,
) -> Result<Option<TrustLabelPlaceholder>> {
    let original_layout = layout(original, maximum_bytes)?;
    let Some(at) = original_trust_ace(original, original_layout)? else {
        return Ok(None);
    };
    ensure!(
        at.is_multiple_of(4),
        "process-trust ACE is not DWORD aligned"
    );
    let prefix_hash = descriptor_hash32(&original[..at])?;
    let original_header = dword(original, at)?;
    let audit_header = (original_header & !0xff) | u32::from(AUDIT_ACE_TYPE);
    let original_state = prefix_hash.rotate_left(3).wrapping_add(original_header);
    let audit_state = prefix_hash.rotate_left(3).wrapping_add(audit_header);
    let original_mask = dword(original, at + 4)?;
    let matched_state = original_state.rotate_left(3).wrapping_add(original_mask);
    let placeholder_mask = matched_state.wrapping_sub(audit_state.rotate_left(3));
    let mut placeholder = original.to_vec();
    placeholder[at] = AUDIT_ACE_TYPE;
    placeholder[at + 4..at + 8].copy_from_slice(&placeholder_mask.to_le_bytes());
    let placeholder_layout = validate_placeholder(
        &placeholder,
        maximum_bytes,
        at,
        placeholder_mask,
        span(original, at, TRUST_ACE_BYTES)?,
    )?;
    ensure!(
        original_layout == placeholder_layout,
        "SD layout changed during preparation"
    );
    ensure!(
        original
            .iter()
            .zip(&placeholder)
            .enumerate()
            .all(|(offset, (a, b))| {
                a == b || offset == at || (at + 4..at + 8).contains(&offset)
            }),
        "placeholder changed bytes outside its ACE type and mask"
    );
    let descriptor_hash = descriptor_hash32(original)?;
    ensure!(
        descriptor_hash == descriptor_hash32(&placeholder)?,
        "process-trust placeholder changes the descriptor hash"
    );
    Ok(Some(TrustLabelPlaceholder {
        original: original.to_vec(),
        placeholder,
        descriptor_hash,
        ace_offset: at,
        placeholder_mask,
    }))
}

/// Plan restoration only when the entire frozen descriptor exactly matches its
/// independently validated expected placeholder. Hash equality alone never
/// admits a row. Native canonicalization must be resolved before this boundary.
/// This plan contains no filesystem addresses or write capability.
pub fn plan_trust_label_restoration(
    stored_placeholder: &[u8],
    original: &[u8],
    maximum_bytes: u64,
) -> Result<DescriptorPatchPlan> {
    let prepared = prepare_trust_label_placeholder(original, maximum_bytes)?
        .ok_or_else(|| invalid("restoration requires an observed process-trust ACE"))?;
    validate_placeholder(
        stored_placeholder,
        maximum_bytes,
        prepared.ace_offset,
        prepared.placeholder_mask,
        span(original, prepared.ace_offset, TRUST_ACE_BYTES)?,
    )?;
    ensure!(
        stored_placeholder == prepared.placeholder,
        "frozen native SD differs from the complete expected placeholder"
    );
    ensure!(
        stored_placeholder.len() == original.len()
            && descriptor_hash32(stored_placeholder)? == prepared.descriptor_hash,
        "restoration SD length or unchanged descriptor hash differs"
    );
    let at = prepared.ace_offset;
    let patch = DescriptorBytePatch {
        offset: at,
        before: span(stored_placeholder, at, ACE_PREFIX_BYTES)?.to_vec(),
        after: span(original, at, ACE_PREFIX_BYTES)?.to_vec(),
    };
    let mut restored = stored_placeholder.to_vec();
    restored[at..at + ACE_PREFIX_BYTES].copy_from_slice(&patch.after);
    let restored_layout = layout(&restored, maximum_bytes)?;
    ensure!(
        original_trust_ace(&restored, restored_layout)? == Some(at)
            && restored == original
            && descriptor_hash32(&restored)? == prepared.descriptor_hash,
        "restoration plan does not reproduce the complete original descriptor"
    );
    Ok(DescriptorPatchPlan {
        descriptor_length: original.len(),
        descriptor_hash: prepared.descriptor_hash,
        placeholder_sha256: descriptor_sha256(stored_placeholder),
        original_sha256: descriptor_sha256(original),
        patches: vec![patch],
    })
}
