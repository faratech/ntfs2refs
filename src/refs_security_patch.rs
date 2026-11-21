//! Fixed-length trust-label restoration in a frozen native ReFS image.
//!
//! This is a bounded read-only patch planner, not a ReFS allocator or writer.
//! It follows the checksum-bound Object Table copies and OID 0x530 from both
//! checkpoints, and changes only an exact previously prepared descriptor and
//! the checksums of its existing ancestors. The caller must own the actual
//! frozen native-image capability and apply the resulting old/new clusters
//! through the existing journal writer before strict native observation.
//!
//! Layout facts are shared with the existing bootstrap/node/object decoders
//! and pinned forefst structural documentation. No external implementation is
//! incorporated. Driver acceptance and boot qualification remain separate.
use crate::{
    refs_bootstrap::{AnchorProbe, crc32c, crc64_nvme},
    refs_containers::ContainerAddressView,
    refs_node::{self, NodeRowObservation},
    refs_security_descriptor::{self, TrustLabelPlaceholder},
};
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
};

const CLUSTER: usize = 4096;
const PAGE: usize = 4 * CLUSTER;
const SECURITY_OID: u64 = 0x530;
const MAX_DEPTH: u8 = 8;
const MAX_REPLACEMENTS: usize = 16_384;

#[derive(Debug, Serialize)]
pub struct SecurityClusterPatch {
    pub offset: u64,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

#[derive(Debug, Serialize)]
pub struct SecurityCheckpointBinding {
    pub lcn: u64,
    pub virtual_clock: u64,
    pub before_sha256: String,
    pub after_sha256: String,
    pub descriptor_matches: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct SecurityPatchPlan {
    pub profile: &'static str,
    pub image_bytes: u64,
    pub volume_bytes: u64,
    pub volume_serial: u64,
    pub vbr_sha256: String,
    pub volume_guid_bytes_hex: String,
    pub checkpoint_bindings: Vec<SecurityCheckpointBinding>,
    pub page_reads: u32,
    pub clusters: Vec<SecurityClusterPatch>,
    /// Always false: the held-image/journal owner supplies write authority.
    pub raw_write_authority: bool,
    /// Always false: the original descriptors still require native readback.
    pub native_security_preservation_qualified: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Tree {
    Objects(u64),
    Security,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum DescriptorMode {
    ExactBytes,
    NativeCanonical,
}

impl Tree {
    fn oid(self) -> u64 {
        match self {
            Self::Objects(oid) => oid,
            Self::Security => SECURITY_OID,
        }
    }
}

#[derive(Default)]
struct Counts {
    leaves: u64,
    last_object: Option<u64>,
    security_ref: Option<([u64; 4], u64)>,
    security_keys: BTreeSet<(u32, u32)>,
    matches: Vec<u32>,
}

struct TreeResult {
    checksum: u64,
    security_ref: Option<([u64; 4], u64)>,
    matches: Vec<u32>,
}

struct Walker<'a, R> {
    reader: &'a mut R,
    volume_clusters: u64,
    signature: u32,
    protected: BTreeSet<u64>,
    replacements: &'a [TrustLabelPlaceholder],
    replacement_by_hash: BTreeMap<u32, Vec<usize>>,
    replacement_by_semantics: BTreeMap<[u8; 32], Vec<usize>>,
    descriptor_mode: DescriptorMode,
    max_pages: u32,
    max_changed_clusters: u32,
    pages: u32,
    // Repeated visits from duplicate trees/checkpoints are allowed only for
    // exactly the same physical page order and table identity.
    owners: BTreeMap<u64, ([u64; 4], u64)>,
    patches: BTreeMap<u64, SecurityClusterPatch>,
}

fn u32le(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(bytes[at..at + 4].try_into().expect("bounded field"))
}

fn u64le(bytes: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(bytes[at..at + 8].try_into().expect("bounded field"))
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Index only. Equality is independently required through the existing strict
/// security comparator before a canonical descriptor can be accepted. Offsets,
/// descriptor padding and unused ACL capacity have no semantic representation;
/// every SID byte and every complete ordered ACE byte does.
fn semantic_identity(bytes: &[u8], maximum: u64) -> Result<[u8; 32]> {
    use n2r_win32::security_descriptor::{self, Presence};
    let layout = security_descriptor::validate_with_limit(bytes, maximum)?;
    let mut hash = Sha256::new();
    hash.update(b"n2r-native-sd-semantic-index-v1\0");
    hash.update(layout.control.to_le_bytes());
    hash.update([
        u8::from(layout.rm_control.is_some()),
        layout.rm_control.unwrap_or(0),
    ]);
    for sid in [layout.owner, layout.group] {
        hash.update([u8::from(sid.is_some())]);
        if let Some(sid) = sid {
            hash.update((sid.length as u64).to_le_bytes());
            hash.update(&bytes[sid.offset..sid.offset + sid.length]);
        }
    }
    for acl in [layout.dacl, layout.sacl] {
        let presence = match acl.presence {
            Presence::Absent => 0,
            Presence::Null => 1,
            Presence::Present => 2,
        };
        hash.update([presence, acl.revision.unwrap_or(0)]);
        hash.update(acl.ace_count.to_le_bytes());
        for (at, length) in acl_entries(bytes, acl)? {
            hash.update((length as u64).to_le_bytes());
            hash.update(&bytes[at..at + length]);
        }
    }
    Ok(hash.finalize().into())
}

fn acl_entries(
    bytes: &[u8],
    acl: n2r_win32::security_descriptor::AclLayout,
) -> Result<Vec<(usize, usize)>> {
    let Some(start) = acl.offset else {
        return Ok(Vec::new());
    };
    let end = start
        .checked_add(acl.length)
        .context("canonical ACL end overflow")?;
    let mut at = start
        .checked_add(8)
        .context("canonical ACE start overflow")?;
    let mut entries = Vec::with_capacity(usize::from(acl.ace_count));
    for _ in 0..acl.ace_count {
        let header = bytes
            .get(at..at + 4)
            .context("canonical ACE header exceeds SD")?;
        let length = usize::from(u16::from_le_bytes(header[2..4].try_into()?));
        let next = at
            .checked_add(length)
            .context("canonical ACE end overflow")?;
        ensure!(
            length >= 16 && next <= end && next <= bytes.len(),
            "canonical ACE exceeds its ACL"
        );
        entries.push((at, length));
        at = next;
    }
    Ok(entries)
}

/// Rebuild the original in the native descriptor's actual packing. The source
/// SACL ordinal is preserved; the unique prepared ACE prefix is the only byte
/// range changed. A different native prefix-hash carry refuses the operation,
/// rather than choosing another mask or changing any SecurityId.
fn canonical_original(stored: &[u8], expected: &TrustLabelPlaceholder) -> Result<Vec<u8>> {
    use n2r_win32::security_descriptor;
    let maximum = refs_security_descriptor::MAX_DESCRIPTOR_BYTES as u64;
    ensure!(
        crate::ntfs_attestation::same_security_with_limit(stored, &expected.placeholder, maximum)?,
        "native placeholder semantics differ from their source expectation"
    );
    let source_layout = security_descriptor::validate_with_limit(&expected.original, maximum)?;
    let source_aces = acl_entries(&expected.original, source_layout.sacl)?;
    let ordinal = source_aces
        .iter()
        .position(|(at, _)| *at == expected.ace_offset)
        .context("source trust-label SACL ordinal absent")?;
    let native_layout = security_descriptor::validate_with_limit(stored, maximum)?;
    let native_aces = acl_entries(stored, native_layout.sacl)?;
    let &(at, length) = native_aces
        .get(ordinal)
        .context("native placeholder SACL ordinal absent")?;
    let &(source_at, source_length) = source_aces.get(ordinal).context("source ACE absent")?;
    ensure!(
        length == 24
            && source_length == 24
            && stored[at] == 0x0d
            && expected.original[source_at] == 0x14
            && stored[at + 8..at + length]
                == expected.original[source_at + 8..source_at + source_length],
        "native placeholder ACE shape or ordinal differs"
    );
    let mut original = stored.to_vec();
    original[at..at + 8].copy_from_slice(&expected.original[source_at..source_at + 8]);
    ensure!(
        crate::ntfs_attestation::same_security_with_limit(&original, &expected.original, maximum)?,
        "native restored descriptor semantics differ from exact source security"
    );
    ensure!(
        crate::ntfs_security::ntfs_hash(stored)? == crate::ntfs_security::ntfs_hash(&original)?,
        "native canonical trust-label restoration would change its SecurityId"
    );
    let recompiled = refs_security_descriptor::prepare_trust_label_placeholder(&original, maximum)?
        .context("native canonical original has no measured trust-label ACE")?;
    ensure!(
        recompiled.placeholder == stored,
        "native canonical placeholder cannot be reproduced exactly with the source mask"
    );
    Ok(original)
}

fn reference(bytes: &[u8]) -> Result<([u64; 4], u64)> {
    ensure!(
        bytes.len() == 48 && bytes[32..40] == [0, 0, 2, 8, 8, 0, 0, 0],
        "trust-label ancestor is not the supported 48-byte CRC64 reference"
    );
    Ok((
        std::array::from_fn(|i| u64le(bytes, i * 8)),
        u64le(bytes, 40),
    ))
}

fn value_range(row: &NodeRowObservation) -> Result<std::ops::Range<usize>> {
    ensure!(
        row.reserved_at_8 == 0 && row.reserved_at_14 == 0 && !row.key_value_overlap,
        "trust-label row has unsupported reserved fields or overlapping key/value"
    );
    let start = row
        .page_offset
        .checked_add(usize::from(row.value_offset))
        .context("trust-label value offset overflow")?;
    let end = start
        .checked_add(usize::from(row.value_length))
        .context("trust-label value length overflow")?;
    ensure!(end <= PAGE, "trust-label value exceeds its page");
    Ok(start..end)
}

fn index_value_range(
    row: &NodeRowObservation,
    rows: &[NodeRowObservation],
    oid: u64,
    level: u8,
) -> Result<std::ops::Range<usize>> {
    let row_count = rows.len();
    if row.reserved_at_8 == 0 {
        return value_range(row);
    }
    // Native 3.14 Object Tables and OID 0x530 end an index page with one
    // child-reference row whose flag word is 2. In the last page of an index
    // level that row has no key (64 bytes: header, then the reference). In any
    // other page of the level it keeps its separator key like the rows before
    // it (header, key, reference); that form first appeared when the Object
    // Table of a full Windows volume grew a second index level. Either way
    // the value is the 48-byte reference, which the caller follows only after
    // checking the child's CRC, level and table. This is an index record, not
    // a leaf or a generic allowance for nonzero reserved fields. The marker
    // word of its index entry is not interpreted, here or for any other row:
    // it was 0 on small trees and 0xffff on both forms on the full volume.
    let keyless = row.key_length == 0 && row.value_offset == 16 && row.size == 64;
    let keyed = row.key_length != 0
        && u32::from(row.value_offset) == 16 + u32::from(row.key_length)
        && row.size == u32::from(row.value_offset) + 48;
    ensure!(
        row.index.checked_add(1) == Some(row_count)
            && row.key_offset == 16
            && row.reserved_at_8 == 2
            && row.value_length == 48
            && row.reserved_at_14 == 0
            && !row.key_value_overlap
            && (keyless || keyed),
        "unsupported native trust-label index boundary row: table OID 0x{oid:x}, index level {level}, row {} of {row_count}: marker {}, size {}, key offset {} length {}, flags {}, value offset {} length {}, reserved {}, key/value overlap {}; every row of the page as index:flags/key length/value length/size: {}",
        row.index,
        row.marker,
        row.size,
        row.key_offset,
        row.key_length,
        row.reserved_at_8,
        row.value_offset,
        row.value_length,
        row.reserved_at_14,
        row.key_value_overlap,
        rows.iter()
            .take(64)
            .map(|each| format!(
                "{}:{}/{}/{}/{}",
                each.index, each.reserved_at_8, each.key_length, each.value_length, each.size
            ))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let start = row
        .page_offset
        .checked_add(usize::from(row.value_offset))
        .context("index value offset overflow")?;
    let end = start
        .checked_add(48)
        .context("index value length overflow")?;
    ensure!(end <= PAGE, "index value outside authenticated page");
    Ok(start..end)
}

impl<R: Read + Seek> Walker<'_, R> {
    fn read_page(&mut self, physical: [u64; 4]) -> Result<Vec<u8>> {
        ensure!(
            self.pages < self.max_pages,
            "trust-label graph page budget exhausted"
        );
        self.pages += 1;
        let mut bytes = vec![0; PAGE];
        for lcn in physical {
            ensure!(
                lcn < self.volume_clusters,
                "trust-label page outside volume"
            );
        }
        if physical[1] == physical[0] + 1
            && physical[2] == physical[0] + 2
            && physical[3] == physical[0] + 3
        {
            self.reader
                .seek(SeekFrom::Start(physical[0] * CLUSTER as u64))?;
            self.reader.read_exact(&mut bytes)?;
        } else {
            for (i, lcn) in physical.into_iter().enumerate() {
                self.reader.seek(SeekFrom::Start(lcn * CLUSTER as u64))?;
                self.reader
                    .read_exact(&mut bytes[i * CLUSTER..(i + 1) * CLUSTER])?;
            }
        }
        Ok(bytes)
    }

    fn retain(&mut self, slots: [u64; 4], before: &[u8], after: &[u8]) -> Result<()> {
        for (i, lcn) in slots.into_iter().enumerate() {
            let old = &before[i * CLUSTER..(i + 1) * CLUSTER];
            let new = &after[i * CLUSTER..(i + 1) * CLUSTER];
            if old == new {
                continue;
            }
            let offset = lcn * CLUSTER as u64;
            if let Some(prior) = self.patches.get(&offset) {
                ensure!(
                    prior.before == old && prior.after == new,
                    "shared trust-label graph page requires inconsistent replacements"
                );
            } else {
                ensure!(
                    self.patches.len() < self.max_changed_clusters as usize,
                    "trust-label changed-cluster budget exhausted"
                );
                self.patches.insert(
                    offset,
                    SecurityClusterPatch {
                        offset,
                        before: old.to_vec(),
                        after: new.to_vec(),
                    },
                );
            }
        }
        Ok(())
    }

    fn tree(
        &mut self,
        kind: Tree,
        slots: [u64; 4],
        checksum: u64,
        map: &ContainerAddressView<'_>,
    ) -> Result<TreeResult> {
        let mut counts = Counts {
            matches: vec![0; self.replacements.len()],
            ..Counts::default()
        };
        let mut visited = BTreeSet::new();
        let (checksum, expected_rows) = self.page(
            kind,
            slots,
            checksum,
            None,
            0,
            map,
            &mut visited,
            &mut counts,
        )?;
        let expected_rows = expected_rows.context("trust-label tree root count absent")?;
        // The security table's header count is exact. The Object Table's is
        // not once the table is large: on an untouched Windows-sized shadow
        // the driver's own tree held 6159 ordered, CRC-valid leaf rows under a
        // header count of 6158. Every page here is CRC-checked and its keys
        // are strictly ordered, so a walk cannot invent rows; what it must not
        // do is miss any the header knows about.
        let count_acceptable = match kind {
            Tree::Objects(_) => counts.leaves >= expected_rows,
            Tree::Security => counts.leaves == expected_rows,
        };
        ensure!(
            count_acceptable,
            "trust-label tree leaf count differs from its root descriptor: table OID 0x{:x}, leaf rows walked {}, root descriptor count {}, pages read so far {}",
            kind.oid(),
            counts.leaves,
            expected_rows,
            self.pages
        );
        if matches!(kind, Tree::Objects(_)) {
            ensure!(
                counts.security_ref.is_some(),
                "OID 0x530 absent from Object Table"
            );
        }
        Ok(TreeResult {
            checksum,
            security_ref: counts.security_ref,
            matches: counts.matches,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn page(
        &mut self,
        kind: Tree,
        slots: [u64; 4],
        checksum: u64,
        expected_level: Option<u8>,
        depth: u8,
        map: &ContainerAddressView<'_>,
        visited: &mut BTreeSet<u64>,
        counts: &mut Counts,
    ) -> Result<(u64, Option<u64>)> {
        ensure!(depth <= MAX_DEPTH, "trust-label graph depth exceeded");
        let mut physical = [0; 4];
        for (i, vlcn) in slots.into_iter().enumerate() {
            ensure!(
                vlcn != 0 && vlcn & 0x4000 == 0 && !slots[..i].contains(&vlcn),
                "trust-label virtual page has zero, repeated or reserved slot"
            );
            let (base, _) = map
                .lookup(vlcn >> 15)
                .context("trust-label container absent")?;
            let lcn = base
                .checked_add(vlcn & 0x3fff)
                .context("trust-label translation overflow")?;
            ensure!(
                lcn < self.volume_clusters
                    && !self.protected.contains(&lcn)
                    && !physical[..i].contains(&lcn)
                    && visited.insert(lcn),
                "trust-label page aliases a tree, bootstrap or container page"
            );
            physical[i] = lcn;
        }
        for lcn in physical {
            if let Some(prior) = self.owners.get(&lcn) {
                ensure!(
                    *prior == (physical, kind.oid()),
                    "trust-label physical page alias differs"
                );
            } else {
                self.owners.insert(lcn, (physical, kind.oid()));
            }
        }
        let before = self.read_page(physical)?;
        ensure!(
            crc64_nvme(&before) == checksum
                && &before[..4] == b"MSB+"
                && u32le(&before, 4) == 2
                && u32le(&before, 8) == 0
                && u32le(&before, 12) == self.signature
                && u64le(&before, 0x40) == 0
                && u64le(&before, 0x48) == kind.oid()
                && (0..4).all(|i| u64le(&before, 0x20 + i * 8) == slots[i]),
            "trust-label page CRC, signature, table or self-slots disagree"
        );
        let (level, rows, expected_rows) = if depth == 0 {
            let node = match kind {
                Tree::Objects(oid) => refs_node::inspect_system_root_node(&before, oid)?,
                Tree::Security => refs_node::inspect_object_root_node(&before, SECURITY_OID)?,
            };
            if matches!(kind, Tree::Objects(_)) {
                ensure!(node.schema_id == 0xe030, "Object Table schema differs");
            } else {
                ensure!(
                    node.schema_id == 0x140 && node.root_descriptor_auxiliary == 1,
                    "OID 0x530 native root descriptor differs from observed profile"
                );
            }
            (node.node_level, node.rows, Some(node.whole_table_row_count))
        } else {
            let node = match kind {
                Tree::Objects(oid) => refs_node::inspect_system_child_node(&before, oid)?,
                Tree::Security => refs_node::inspect_object_child_node(&before, SECURITY_OID)?,
            };
            (node.node_level, node.rows, None)
        };
        ensure!(
            expected_level.is_none_or(|expected| expected == level)
                && level <= MAX_DEPTH
                && (!rows.is_empty() || depth == 0),
            "trust-label child level or empty non-root differs"
        );
        let mut after = before.clone();
        for row in &rows {
            let span = if level == 0 {
                value_range(row)?
            } else {
                index_value_range(row, &rows, kind.oid(), level)?
            };
            if level != 0 {
                let (child_slots, child_crc) = reference(&before[span.clone()])?;
                let (new_crc, _) = self.page(
                    kind,
                    child_slots,
                    child_crc,
                    Some(level - 1),
                    depth + 1,
                    map,
                    visited,
                    counts,
                )?;
                after[span.start + 40..span.start + 48].copy_from_slice(&new_crc.to_le_bytes());
                continue;
            }
            counts.leaves = counts
                .leaves
                .checked_add(1)
                .context("trust-label row count overflow")?;
            match kind {
                Tree::Objects(_) => {
                    let object = crate::refs_object_refs::decode_object_leaf_row(row)?;
                    ensure!(
                        counts
                            .last_object
                            .is_none_or(|prior| prior < object.object_id),
                        "Object Table leaf keys are duplicated or out of order"
                    );
                    counts.last_object = Some(object.object_id);
                    if object.object_id != SECURITY_OID {
                        continue;
                    }
                    ensure!(
                        object.trailer.is_none() && counts.security_ref.is_none(),
                        "OID 0x530 has a trailer or duplicate row"
                    );
                    counts.security_ref = Some((object.virtual_lcn_slots, object.root_crc64_nvme));
                    let repaired = self.tree(
                        Tree::Security,
                        object.virtual_lcn_slots,
                        object.root_crc64_nvme,
                        map,
                    )?;
                    after[span.start + 0x48..span.start + 0x50]
                        .copy_from_slice(&repaired.checksum.to_le_bytes());
                    counts.matches = repaired.matches;
                }
                Tree::Security => self.security_row(row, &before, &mut after, counts)?,
            }
        }
        self.retain(physical, &before, &after)?;
        Ok((crc64_nvme(&after), expected_rows))
    }

    fn security_row(
        &self,
        row: &NodeRowObservation,
        before: &[u8],
        after: &mut [u8],
        counts: &mut Counts,
    ) -> Result<()> {
        let span = value_range(row)?;
        let key_at = row
            .page_offset
            .checked_add(usize::from(row.key_offset))
            .context("security key offset overflow")?;
        let key = before
            .get(key_at..key_at + usize::from(row.key_length))
            .context("security key outside page")?;
        let value = &before[span.clone()];
        ensure!(
            key.len() == 16
                && value.len() >= 32
                && u32le(key, 4) == 0
                && u32le(key, 0) as usize == value.len()
                && u32le(value, 8) as usize == value.len()
                && u32le(key, 8) == u32le(value, 4)
                && u32le(value, 4) > 0
                && u32le(key, 12) == u32le(value, 0),
            "OID 0x530 key or descriptor wrapper differs from fixed profile"
        );
        ensure!(
            counts.security_keys.insert((u32le(key, 8), u32le(key, 12))),
            "OID 0x530 contains a duplicate SecurityId"
        );
        let sd = &value[12..];
        ensure!(
            crate::ntfs_security::ntfs_hash(sd)? == u32le(value, 0),
            "OID 0x530 descriptor hash differs from its SecurityId"
        );
        let semantic_key = if self.descriptor_mode == DescriptorMode::NativeCanonical {
            Some(semantic_identity(sd, PAGE as u64)?)
        } else {
            None
        };
        let candidates = match semantic_key {
            Some(key) => self.replacement_by_semantics.get(&key),
            None => self.replacement_by_hash.get(&u32le(value, 0)),
        };
        let mut matched_original: Option<Vec<u8>> = None;
        for &i in candidates.into_iter().flatten() {
            let replacement = &self.replacements[i];
            if self.descriptor_mode == DescriptorMode::ExactBytes && sd != replacement.placeholder {
                continue;
            }
            let original = match self.descriptor_mode {
                DescriptorMode::ExactBytes => replacement.original.clone(),
                DescriptorMode::NativeCanonical => canonical_original(sd, replacement)?,
            };
            if let Some(prior) = &matched_original {
                ensure!(
                    prior == &original,
                    "deduplicated source descriptors require different native restorations"
                );
            } else {
                matched_original = Some(original);
            }
            counts.matches[i] = counts.matches[i]
                .checked_add(1)
                .context("trust-label match count overflow")?;
        }
        if let Some(original) = matched_original {
            let patch = refs_security_descriptor::plan_trust_label_restoration(
                sd,
                &original,
                sd.len() as u64,
            )?;
            ensure!(
                patch.descriptor_hash == u32le(value, 0),
                "restored SecurityId would change"
            );
            for change in patch.patches {
                let at = span.start + 12 + change.offset;
                ensure!(
                    before[at..at + change.before.len()] == change.before,
                    "trust-label expected original prefix differs"
                );
                after[at..at + change.after.len()].copy_from_slice(&change.after);
            }
            ensure!(
                &after[span.start + 12..span.end] == original,
                "trust-label restored descriptor differs from the exact checked original"
            );
        }
        Ok(())
    }
}

fn checkpoint_reference(
    bytes: &[u8],
    checkpoint: &AnchorProbe,
    index: usize,
) -> Result<(usize, [u64; 4], u64)> {
    let root = checkpoint
        .checkpoint
        .as_ref()
        .context("checkpoint fields absent")?
        .roots
        .get(index)
        .context("checkpoint root absent")?;
    let at = root.descriptor_offset;
    let descriptor = bytes
        .get(at..at + 48)
        .context("checkpoint root out of bounds")?;
    ensure!(
        sha(descriptor) == root.descriptor_sha256,
        "checkpoint descriptor bytes changed"
    );
    let (slots, crc) = reference(descriptor)?;
    ensure!(slots == root.lcn_slots, "checkpoint root slots changed");
    Ok((at, slots, crc))
}

/// Plan only on a stable, already isolated *native target volume* at offset
/// zero. `expected_vbr_sha256` and `expected_volume_serial` must be obtained from
/// the caller's held native-image identity. They are checked in addition to
/// fresh same-handle bootstrap/container authentication and exact SD bytes.
/// Unknown layouts, missing descriptors, duplicate IDs, aliases, and budgets
/// fail before any output plan is returned. No `Write` implementation is used.
pub fn plan_native_trust_label_restoration<R: Read + Seek>(
    reader: &mut R,
    image_bytes: u64,
    expected_vbr_sha256: &str,
    expected_volume_serial: u64,
    replacements: &[TrustLabelPlaceholder],
    max_page_reads: u32,
    max_changed_clusters: u32,
) -> Result<SecurityPatchPlan> {
    plan_profile(
        reader,
        image_bytes,
        expected_vbr_sha256,
        expected_volume_serial,
        replacements,
        max_page_reads,
        max_changed_clusters,
        DescriptorMode::ExactBytes,
    )
}

/// Native creation may repack only offsets and padding. This explicit mode
/// matches every source expectation with the unchanged strict semantic
/// comparator, restores the measured ACE in the actual native packing, and
/// requires that the native old/new descriptor hash and SecurityId stay exact.
/// Semantically deduplicated source descriptors all bind to the same row; none
/// can be ignored or selected arbitrarily. The exact-byte planner above keeps
/// its original admission rules.
pub fn plan_native_canonical_trust_label_restoration<R: Read + Seek>(
    reader: &mut R,
    image_bytes: u64,
    expected_vbr_sha256: &str,
    expected_volume_serial: u64,
    replacements: &[TrustLabelPlaceholder],
    max_page_reads: u32,
    max_changed_clusters: u32,
) -> Result<SecurityPatchPlan> {
    plan_profile(
        reader,
        image_bytes,
        expected_vbr_sha256,
        expected_volume_serial,
        replacements,
        max_page_reads,
        max_changed_clusters,
        DescriptorMode::NativeCanonical,
    )
}

#[allow(clippy::too_many_arguments)]
fn plan_profile<R: Read + Seek>(
    reader: &mut R,
    image_bytes: u64,
    expected_vbr_sha256: &str,
    expected_volume_serial: u64,
    replacements: &[TrustLabelPlaceholder],
    max_page_reads: u32,
    max_changed_clusters: u32,
    descriptor_mode: DescriptorMode,
) -> Result<SecurityPatchPlan> {
    ensure!(
        !replacements.is_empty()
            && replacements.len() <= MAX_REPLACEMENTS
            && (1..=65_536).contains(&max_page_reads)
            && (1..=16_384).contains(&max_changed_clusters),
        "trust-label replacement or resource bounds unsupported"
    );
    let mut replacement_keys = BTreeSet::new();
    let mut replacement_by_hash: BTreeMap<u32, Vec<usize>> = BTreeMap::new();
    let mut replacement_by_semantics: BTreeMap<[u8; 32], Vec<usize>> = BTreeMap::new();
    for (index, replacement) in replacements.iter().enumerate() {
        let maximum = match descriptor_mode {
            DescriptorMode::ExactBytes => PAGE as u64,
            DescriptorMode::NativeCanonical => {
                refs_security_descriptor::MAX_DESCRIPTOR_BYTES as u64
            }
        };
        let patch = refs_security_descriptor::plan_trust_label_restoration(
            &replacement.placeholder,
            &replacement.original,
            maximum,
        )?;
        ensure!(
            patch.descriptor_hash == replacement.descriptor_hash
                && (descriptor_mode == DescriptorMode::NativeCanonical
                    || replacement_keys.insert(sha(&replacement.placeholder))),
            "trust-label replacement identity is invalid or duplicated"
        );
        replacement_by_hash
            .entry(patch.descriptor_hash)
            .or_default()
            .push(index);
        if descriptor_mode == DescriptorMode::NativeCanonical {
            let key = semantic_identity(&replacement.placeholder, maximum)?;
            let entries = replacement_by_semantics.entry(key).or_default();
            if let Some(&prior) = entries.first() {
                ensure!(
                    crate::ntfs_attestation::same_security_with_limit(
                        &replacements[prior].placeholder,
                        &replacement.placeholder,
                        maximum
                    )? && crate::ntfs_attestation::same_security_with_limit(
                        &replacements[prior].original,
                        &replacement.original,
                        maximum
                    )?,
                    "deduplicated source security expectations disagree"
                );
            }
            entries.push(index);
        }
    }
    reader.seek(SeekFrom::Start(0))?;
    let mut vbr = [0; 512];
    reader.read_exact(&mut vbr)?;
    let vbr_sha256 = sha(&vbr);
    ensure!(
        vbr_sha256 == expected_vbr_sha256,
        "native target VBR identity differs"
    );
    let inspected = crate::refs_inspect::inspect_with_resource_profile(
        reader,
        image_bytes,
        crate::ntfs_admission::ResourceProfile::ExperimentalStreamingTreeV2,
    )?;
    let geometry = &inspected.geometry;
    ensure!(
        geometry.major_version == 3
            && geometry.minor_version == 14
            && geometry.bytes_per_sector == 512
            && geometry.bytes_per_cluster == CLUSTER as u32
            && geometry.image_bytes == image_bytes
            && geometry.volume_bytes == image_bytes
            && geometry.volume_serial == expected_volume_serial
            && inspected.backup_header_status == crate::refs_inspect::BackupHeaderStatus::Matching,
        "native target image does not match exact ReFS 3.14/4KiB profile"
    );
    let bootstrap = inspected
        .bootstrap
        .as_ref()
        .context("native bootstrap absent")?;
    ensure!(
        bootstrap.vbr_checksum_matches
            && bootstrap.checkpoints.len() == 2
            && bootstrap
                .checkpoints
                .iter()
                .all(|cp| cp.rejection.is_none()
                    && cp.self_checksum.as_ref().is_some_and(|c| c.matches)),
        "both native checkpoints must be structurally and checksum accepted"
    );
    let superblocks: Vec<_> = bootstrap
        .superblocks
        .iter()
        .filter(|s| s.rejection.is_none() && s.self_checksum.as_ref().is_some_and(|c| c.matches))
        .collect();
    ensure!(!superblocks.is_empty(), "accepted native superblock absent");
    let guid = superblocks[0]
        .superblock
        .as_ref()
        .context("native SUPB fields absent")?
        .volume_guid_bytes_hex
        .clone();
    ensure!(
        superblocks.iter().all(|s| s
            .superblock
            .as_ref()
            .is_some_and(|f| f.volume_guid_bytes_hex == guid)),
        "native SUPB volume GUIDs differ"
    );
    let mut protected = BTreeSet::from([0]);
    for anchor in bootstrap.superblocks.iter().chain(&bootstrap.checkpoints) {
        let clusters = anchor.bytes_read.div_ceil(CLUSTER) as u64;
        protected.extend(anchor.lcn..anchor.lcn + clusters);
    }
    let containers = bootstrap
        .container_tables
        .as_ref()
        .context("native container maps absent")?;
    for tree in &containers.trees {
        ensure!(
            tree.walk_finished
                && tree.rejection.is_none()
                && tree.root_count_matches == Some(true)
                && tree
                    .pages
                    .iter()
                    .all(|p| p.checksum_matches && p.header_matches && p.rejection.is_none()),
            "native container proof incomplete"
        );
        for page in &tree.pages {
            protected.extend(page.lcn_slots);
        }
        if let Some(compact) = &tree.compact {
            protected.extend(compact.page_lcns.iter().copied());
        }
    }
    let virtual_roots = bootstrap
        .virtual_roots
        .as_ref()
        .context("native virtual roots absent")?;
    let signature = bootstrap.checkpoints[0]
        .header
        .as_ref()
        .context("checkpoint header absent")?
        .volume_signature;
    let mut walker = Walker {
        reader,
        volume_clusters: image_bytes / CLUSTER as u64,
        signature,
        protected,
        replacements,
        replacement_by_hash,
        replacement_by_semantics,
        descriptor_mode,
        max_pages: max_page_reads,
        max_changed_clusters,
        pages: 0,
        owners: BTreeMap::new(),
        patches: BTreeMap::new(),
    };
    let mut checkpoint_bindings = Vec::new();
    for checkpoint in &bootstrap.checkpoints {
        let fields = checkpoint
            .checkpoint
            .as_ref()
            .context("checkpoint fields absent")?;
        let header = checkpoint
            .header
            .as_ref()
            .context("checkpoint header absent")?;
        ensure!(
            header.volume_signature == signature
                && fields.header_clock_matches
                && fields.major_version == 3
                && fields.minor_version == 14
                && fields.reference_size == 48
                && fields.roots.len() == 13,
            "native checkpoint identity/profile differs"
        );
        let binding = virtual_roots
            .checkpoint_maps
            .iter()
            .find(|m| m.checkpoint_lcn == checkpoint.lcn)
            .context("checkpoint map binding absent")?;
        ensure!(
            binding.checkpoint_sha256 == checkpoint.sha256
                && binding.rejection.is_none()
                && binding.both_complete_count_matching_maps_agree,
            "native checkpoint does not have two agreeing authenticated maps"
        );
        let tree = containers
            .trees
            .iter()
            .find(|t| t.checkpoint_lcn == checkpoint.lcn && t.root_index == 7)
            .context("native root-seven map absent")?;
        let map = tree.address_view(walker.volume_clusters)?;
        let physical = std::array::from_fn(|i| checkpoint.lcn + i as u64);
        let before = walker.read_page(physical)?;
        ensure!(
            sha(&before) == checkpoint.sha256,
            "native checkpoint changed during planning"
        );
        let mut after = before.clone();
        let mut results = Vec::new();
        for (index, oid) in [(0, 2), (5, 4)] {
            let (at, slots, crc) = checkpoint_reference(&before, checkpoint, index)?;
            let repaired = walker.tree(Tree::Objects(oid), slots, crc, &map)?;
            after[at + 40..at + 48].copy_from_slice(&repaired.checksum.to_le_bytes());
            results.push(repaired);
        }
        ensure!(
            results[0].security_ref == results[1].security_ref
                && results[0].matches == results[1].matches,
            "Object Table security references or descriptor matches disagree"
        );
        let self_crc = checkpoint
            .self_checksum
            .as_ref()
            .context("checkpoint self CRC absent")?;
        ensure!(
            self_crc.coverage_bytes == CLUSTER
                && self_crc.descriptor_length == 48
                && self_crc.descriptor_offset + 48 <= CLUSTER,
            "checkpoint self CRC coverage differs"
        );
        let mut covered = after[..CLUSTER].to_vec();
        covered[self_crc.descriptor_offset..self_crc.descriptor_offset + 48].fill(0);
        let computed = crc32c(&covered);
        after[self_crc.descriptor_offset + 40..self_crc.descriptor_offset + 44]
            .copy_from_slice(&computed.to_le_bytes());
        walker.retain(physical, &before, &after)?;
        checkpoint_bindings.push(SecurityCheckpointBinding {
            lcn: checkpoint.lcn,
            virtual_clock: fields.virtual_clock,
            before_sha256: checkpoint.sha256.clone(),
            after_sha256: sha(&after),
            descriptor_matches: results.remove(0).matches,
        });
    }
    let newest = checkpoint_bindings
        .iter()
        .max_by_key(|c| c.virtual_clock)
        .context("native checkpoints absent")?;
    ensure!(
        checkpoint_bindings
            .iter()
            .filter(|c| c.virtual_clock == newest.virtual_clock)
            .count()
            == 1
            && newest.descriptor_matches.iter().all(|count| *count == 1),
        "highest-clock native checkpoint must contain each exact placeholder exactly once"
    );
    ensure!(
        !walker.patches.is_empty(),
        "trust-label graph produced no replacements"
    );
    // Verify every retained old cluster again while the same read-only image
    // capability is held; the journal owner must also enforce old bytes at apply.
    let mut current = [0; CLUSTER];
    for patch in walker.patches.values() {
        walker.reader.seek(SeekFrom::Start(patch.offset))?;
        walker.reader.read_exact(&mut current)?;
        ensure!(
            current.as_slice() == patch.before,
            "native image changed before patch-plan closure"
        );
    }
    Ok(SecurityPatchPlan {
        profile: match descriptor_mode {
            DescriptorMode::ExactBytes => {
                "native ReFS3.14/4KiB fixed-length OID0x530 trust-label patch v1"
            }
            DescriptorMode::NativeCanonical => {
                "native ReFS3.14/4KiB canonical OID0x530 trust-label patch v1"
            }
        },
        image_bytes,
        volume_bytes: geometry.volume_bytes,
        volume_serial: geometry.volume_serial,
        vbr_sha256,
        volume_guid_bytes_hex: guid,
        checkpoint_bindings,
        page_reads: walker.pages,
        clusters: walker.patches.into_values().collect(),
        raw_write_authority: false,
        native_security_preservation_qualified: false,
    })
}

#[cfg(test)]
mod index_row_tests {
    use super::*;

    fn row(index: usize, flags: u16, key_length: u16, marker: u16) -> NodeRowObservation {
        let value_offset = 16 + key_length;
        NodeRowObservation {
            index,
            index_entry_offset: 0,
            relative_offset: 0,
            page_offset: 1000,
            marker,
            size: u32::from(value_offset) + 48,
            key_offset: 16,
            key_length,
            reserved_at_8: flags,
            value_offset,
            value_length: 48,
            reserved_at_14: 0,
            key_value_overlap: false,
            row_bytes_hex: String::new(),
            row_sha256: String::new(),
            key_sha256: String::new(),
            value_sha256: String::new(),
        }
    }

    #[test]
    fn the_last_row_of_an_index_page_may_be_keyless_or_keep_its_key() {
        // The last page of a level: keyed separators, then a keyless row.
        let last_page = [row(0, 0, 16, 0), row(1, 0, 16, 0), row(2, 2, 0, 0)];
        assert_eq!(
            index_value_range(&last_page[0], &last_page, 2, 1).unwrap(),
            1032..1080
        );
        assert_eq!(
            index_value_range(&last_page[2], &last_page, 2, 1).unwrap(),
            1016..1064
        );
        // The same keyless row as the full Windows volume's Object Table has it.
        let last_page = [row(0, 0, 16, 0), row(1, 2, 0, 65535)];
        assert_eq!(
            index_value_range(&last_page[1], &last_page, 2, 1).unwrap(),
            1016..1064
        );
        // Any other page of the level, as on the full Windows volume: the
        // flagged last row has a key like the rest.
        let inner_page = [row(0, 0, 16, 0), row(1, 0, 16, 0), row(2, 2, 16, 65535)];
        assert_eq!(
            index_value_range(&inner_page[2], &inner_page, 2, 1).unwrap(),
            1032..1080
        );
    }

    #[test]
    fn a_flagged_index_row_anywhere_else_or_of_another_shape_is_refused() {
        let misplaced = [row(0, 2, 16, 0), row(1, 0, 16, 0)];
        let error = index_value_range(&misplaced[0], &misplaced, 2, 1)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("row 0 of 2") && error.contains("flags 2"),
            "{error}"
        );

        let mut padded = [row(0, 0, 16, 0), row(1, 2, 16, 65535)];
        padded[1].size += 8;
        assert!(index_value_range(&padded[1], &padded, 2, 1).is_err());

        let other_flag = [row(0, 0, 16, 0), row(1, 4, 16, 0)];
        assert!(index_value_range(&other_flag[1], &other_flag, 2, 1).is_err());

        let mut short_value = [row(0, 0, 16, 0), row(1, 2, 0, 0)];
        short_value[1].value_length = 40;
        assert!(index_value_range(&short_value[1], &short_value, 2, 1).is_err());
    }
}
