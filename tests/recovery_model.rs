//! NON-PRODUCTION protocol model: this file opens no file or device.
//!
//! Tiny sectors make tear positions/orderings exhaustively enumerable. Successful
//! flushes are assumed durable; a failed/unflushed write may persist any prefix,
//! in any order. Real storage may behave differently. These tests neither define
//! ReFS's commit protocol nor qualify a production journal, Windows flush calls,
//! firmware, hardware, metadata layout, mount exclusion, or crash recovery.
//!
//! A trusted conversion manifest supplies the immutable journal digest. Its own
//! durable storage/authentication is outside this model. SHA-256 collisions and
//! corruption of already-flushed storage are outside the tested failure model.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const SECTOR: usize = 8;
type Hash = [u8; 32];
type ModelResult<T> = Result<T, &'static str>;
fn hash(bytes: &[u8]) -> Hash {
    Sha256::digest(bytes).into()
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Replacement {
    sector: usize,
    before: Vec<u8>,
    after: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Journal {
    version: u32,
    source: Hash,
    image_bytes: usize,
    writes: Vec<Replacement>,
}
impl Journal {
    fn encode(&self) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(self).unwrap();
        bytes.extend_from_slice(&hash(&bytes));
        bytes
    }
    fn decode(bytes: &[u8], ticket: Hash) -> ModelResult<Self> {
        if bytes.len() < 32 || hash(bytes) != ticket {
            return Err("journal identity mismatch");
        }
        let (payload, checksum) = bytes.split_at(bytes.len() - 32);
        if hash(payload).as_slice() != checksum {
            return Err("torn journal");
        }
        let journal: Self = serde_json::from_slice(payload).map_err(|_| "invalid journal")?;
        if journal.version != 1
            || journal.image_bytes == 0
            || !journal.image_bytes.is_multiple_of(SECTOR)
        {
            return Err("invalid journal geometry");
        }
        let mut sectors = Vec::new();
        for write in &journal.writes {
            if write.sector >= journal.image_bytes / SECTOR
                || write.before.len() != SECTOR
                || write.after.len() != SECTOR
                || sectors.contains(&write.sector)
            {
                return Err("invalid/overlapping write plan");
            }
            sectors.push(write.sector);
        }
        Ok(journal)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingWrite {
    sector: usize,
    bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
struct Medium {
    image: Vec<u8>,
    journal: Vec<u8>,
    queued: Vec<PendingWrite>,
    pending_journal: Vec<u8>,
    handoff: Vec<u8>,
    pending_handoff: Vec<u8>,
}
#[derive(Clone, Copy, Debug)]
enum Recovery {
    Resume,
    Rollback,
}

impl Medium {
    fn new(image: Vec<u8>) -> Self {
        Self {
            image,
            journal: Vec::new(),
            queued: Vec::new(),
            pending_journal: Vec::new(),
            handoff: Vec::new(),
            pending_handoff: Vec::new(),
        }
    }
    fn stage_journal(&mut self, journal: &Journal, budget: usize) -> ModelResult<Hash> {
        let encoded = journal.encode();
        if encoded.len() > budget {
            return Err("insufficient journal capacity");
        }
        if !self.journal.is_empty() || !self.pending_journal.is_empty() || !self.queued.is_empty() {
            return Err("transaction already started");
        }
        if journal.source != hash(&self.image) || journal.image_bytes != self.image.len() {
            return Err("source identity mismatch");
        }
        let ticket = hash(&encoded);
        Journal::decode(&encoded, ticket)?;
        for write in &journal.writes {
            if self.sector(write.sector) != write.before {
                return Err("preimage mismatch");
            }
        }
        self.pending_journal = encoded;
        Ok(ticket)
    }
    fn flush_journal(&mut self) {
        self.journal.clone_from(&self.pending_journal);
        self.pending_journal.clear();
    }
    fn sector(&self, index: usize) -> &[u8] {
        &self.image[index * SECTOR..(index + 1) * SECTOR]
    }
    fn validate_source(&self, journal: &Journal) -> ModelResult<()> {
        if self.image.len() != journal.image_bytes {
            return Err("source length changed");
        }
        let mut normalized = self.image.clone();
        for write in &journal.writes {
            // A before/after byte mixture can result from a torn conversion or
            // recovery write. Third values must never be silently overwritten.
            if self
                .sector(write.sector)
                .iter()
                .zip(write.before.iter().zip(&write.after))
                .any(|(actual, (before, after))| actual != before && actual != after)
            {
                return Err("foreign change in a managed sector");
            }
            normalized[write.sector * SECTOR..(write.sector + 1) * SECTOR]
                .copy_from_slice(&write.before);
        }
        if hash(&normalized) != journal.source {
            return Err("foreign change outside the write plan");
        }
        Ok(())
    }
    fn queue_conversion(&mut self, ticket: Hash, index: usize) -> ModelResult<()> {
        if !self.handoff.is_empty() {
            return Err("handoff started");
        }
        let journal = Journal::decode(&self.journal, ticket)?;
        self.validate_source(&journal)?;
        let write = journal.writes.get(index).ok_or("unknown write")?;
        if self
            .queued
            .iter()
            .any(|pending| pending.sector == write.sector)
        {
            return Err("duplicate pending write");
        }
        self.queued.push(PendingWrite {
            sector: write.sector,
            bytes: write.after.clone(),
        });
        Ok(())
    }
    fn flush_data(&mut self) {
        for write in self.queued.drain(..) {
            self.image[write.sector * SECTOR..(write.sector + 1) * SECTOR]
                .copy_from_slice(&write.bytes);
        }
    }
    fn queue_recovery(&mut self, ticket: Hash, mode: Recovery) -> ModelResult<()> {
        if !self.handoff.is_empty() {
            return Err("recovery window closed");
        }
        if !self.queued.is_empty() {
            return Err("recovery requires a quiescent device");
        }
        let journal = Journal::decode(&self.journal, ticket)?;
        self.validate_source(&journal)?;
        let mut writes = Vec::new();
        for write in &journal.writes {
            let bytes = match mode {
                Recovery::Resume => &write.after,
                Recovery::Rollback => &write.before,
            };
            if self.sector(write.sector) != bytes {
                writes.push(PendingWrite {
                    sector: write.sector,
                    bytes: bytes.clone(),
                });
            }
        }
        self.queued = writes;
        Ok(())
    }
    fn start_handoff(&mut self, ticket: Hash) -> ModelResult<()> {
        let journal = Journal::decode(&self.journal, ticket)?;
        self.validate_source(&journal)?;
        if !self.queued.is_empty()
            || journal
                .writes
                .iter()
                .any(|write| self.sector(write.sector) != write.after)
        {
            return Err("target not durably complete");
        }
        let mut marker = b"HANDOFF".to_vec();
        marker.extend_from_slice(&ticket);
        if !self.handoff.is_empty() && self.handoff != marker {
            return Err("incomplete handoff marker requires external recovery");
        }
        self.pending_handoff = marker;
        Ok(())
    }
    fn flush_handoff(&mut self) {
        self.handoff.clone_from(&self.pending_handoff);
        self.pending_handoff.clear();
    }
    fn writable_mount_allowed(&self, ticket: Hash) -> bool {
        let mut marker = b"HANDOFF".to_vec();
        marker.extend_from_slice(&ticket);
        self.handoff == marker && self.pending_handoff.is_empty() && self.queued.is_empty()
    }
    fn crash(
        mut self,
        order: &[usize],
        cuts: &[usize],
        journal_prefix: usize,
        handoff_prefix: usize,
    ) -> Self {
        // Unflushed writes can reach stable storage without a completed flush.
        for &index in order {
            let write = &self.queued[index];
            let count = cuts[index];
            assert!(count <= SECTOR);
            let offset = write.sector * SECTOR;
            self.image[offset..offset + count].copy_from_slice(&write.bytes[..count]);
        }
        if !self.pending_journal.is_empty() {
            self.journal = self.pending_journal[..journal_prefix].to_vec();
        }
        if !self.pending_handoff.is_empty() {
            self.handoff = self.pending_handoff[..handoff_prefix].to_vec();
        }
        self.queued.clear();
        self.pending_journal.clear();
        self.pending_handoff.clear();
        self
    }
}

fn fixture() -> (Vec<u8>, Vec<u8>, Journal) {
    let source: Vec<u8> = (0..SECTOR * 8).map(|i| (i % 127) as u8).collect();
    let writes = [1, 4, 6]
        .into_iter()
        .map(|sector| Replacement {
            sector,
            before: source[sector * SECTOR..(sector + 1) * SECTOR].to_vec(),
            after: vec![200 + sector as u8; SECTOR],
        })
        .collect::<Vec<_>>();
    let mut target = source.clone();
    for write in &writes {
        target[write.sector * SECTOR..(write.sector + 1) * SECTOR].copy_from_slice(&write.after);
    }
    let journal = Journal {
        version: 1,
        source: hash(&source),
        image_bytes: source.len(),
        writes,
    };
    (source, target, journal)
}
fn prepared() -> (Medium, Hash, Vec<u8>, Vec<u8>) {
    let (source, target, journal) = fixture();
    let mut medium = Medium::new(source.clone());
    let ticket = medium.stage_journal(&journal, usize::MAX).unwrap();
    medium.flush_journal();
    (medium, ticket, source, target)
}
fn recover_and_check(mut medium: Medium, ticket: Hash, mode: Recovery, expected: &[u8]) {
    medium.queue_recovery(ticket, mode).unwrap();
    medium.flush_data();
    assert_eq!(medium.image, expected);
    medium.queue_recovery(ticket, mode).unwrap();
    assert!(medium.queued.is_empty());
}

fn permutations(values: Vec<usize>) -> Vec<Vec<usize>> {
    if values.is_empty() {
        return vec![Vec::new()];
    }
    let mut result = Vec::new();
    for index in 0..values.len() {
        let mut rest = values.clone();
        let first = rest.remove(index);
        for mut tail in permutations(rest) {
            tail.insert(0, first);
            result.push(tail);
        }
    }
    result
}
fn check_every_data_crash(medium: &Medium, ticket: Hash, source: &[u8], target: &[u8]) {
    let count = medium.queued.len();
    for order in permutations((0..count).collect()) {
        // Zero-length prefixes also enumerate every dropped-write subset.
        for mut number in 0..(SECTOR + 1).pow(count as u32) {
            let mut cuts = vec![0; count];
            for cut in &mut cuts {
                *cut = number % (SECTOR + 1);
                number /= SECTOR + 1;
            }
            let crashed = medium.clone().crash(&order, &cuts, 0, 0);
            recover_and_check(crashed.clone(), ticket, Recovery::Resume, target);
            recover_and_check(crashed, ticket, Recovery::Rollback, source);
        }
    }
}

#[test]
fn journal_capacity_and_source_validation_precede_any_mutation() {
    let (source, _, journal) = fixture();
    let mut medium = Medium::new(source);
    let initial = medium.clone();
    assert!(
        medium
            .stage_journal(&journal, journal.encode().len() - 1)
            .is_err()
    );
    assert_eq!(medium, initial);
    let mut stale = journal.clone();
    stale.source = [0; 32];
    assert!(medium.stage_journal(&stale, usize::MAX).is_err());
    assert_eq!(medium, initial);
    let mut bad = journal.clone();
    bad.writes[0].before[0] ^= 1;
    assert!(medium.stage_journal(&bad, usize::MAX).is_err());
    assert_eq!(medium, initial);
    let mut overlap = journal.clone();
    overlap.writes.push(overlap.writes[0].clone());
    assert!(medium.stage_journal(&overlap, usize::MAX).is_err());
    assert_eq!(medium, initial);
}

#[test]
fn every_torn_journal_prefix_leaves_source_intact_and_blocks_data_writes() {
    let (source, target, journal) = fixture();
    let mut medium = Medium::new(source.clone());
    let ticket = medium.stage_journal(&journal, usize::MAX).unwrap();
    assert!(medium.queue_conversion(ticket, 0).is_err());
    for prefix in 0..=medium.pending_journal.len() {
        let mut crashed = medium.clone().crash(&[], &[], prefix, 0);
        assert_eq!(crashed.image, source);
        if prefix != journal.encode().len() {
            assert!(crashed.queue_conversion(ticket, 0).is_err());
            assert!(crashed.queue_recovery(ticket, Recovery::Resume).is_err());
            assert!(crashed.queued.is_empty());
        } else {
            recover_and_check(crashed.clone(), ticket, Recovery::Resume, &target);
            recover_and_check(crashed, ticket, Recovery::Rollback, &source);
        }
    }
}

#[test]
fn every_issue_and_flush_boundary_recovers_in_either_direction() {
    let (mut medium, ticket, source, target) = prepared();
    check_every_data_crash(&medium, ticket, &source, &target);
    for index in 0..3 {
        medium.queue_conversion(ticket, index).unwrap();
        check_every_data_crash(&medium, ticket, &source, &target);
        medium.flush_data();
        check_every_data_crash(&medium, ticket, &source, &target);
    }
    assert_eq!(medium.image, target);
}

#[test]
fn all_pending_write_orders_subsets_and_sector_tear_positions_recover() {
    let (mut medium, ticket, source, target) = prepared();
    for index in 0..3 {
        medium.queue_conversion(ticket, index).unwrap();
    }
    // 3! orders * 9^3 prefix combinations = 4,374 crash outcomes, with
    // independent resume and rollback checks for each outcome.
    check_every_data_crash(&medium, ticket, &source, &target);
}

#[test]
fn interrupted_resume_and_rollback_remain_restartable_and_idempotent() {
    let (mut medium, ticket, source, target) = prepared();
    for index in 0..3 {
        medium.queue_conversion(ticket, index).unwrap();
    }
    let interrupted = medium.crash(&[2, 0, 1], &[3, 1, 5], 0, 0);
    for mode in [Recovery::Resume, Recovery::Rollback] {
        let mut recovery = interrupted.clone();
        recovery.queue_recovery(ticket, mode).unwrap();
        check_every_data_crash(&recovery, ticket, &source, &target);
    }
}

#[test]
fn foreign_changes_and_mutated_journals_are_refused_without_target_changes() {
    let (medium, ticket, _, _) = prepared();
    for offset in [0, SECTOR] {
        let mut changed = medium.clone();
        changed.image[offset] = 99;
        let before = changed.clone();
        assert!(changed.queue_recovery(ticket, Recovery::Resume).is_err());
        assert_eq!(changed, before);
        assert!(changed.queue_recovery(ticket, Recovery::Rollback).is_err());
        assert_eq!(changed, before);
    }
    let mut changed = medium.clone();
    changed.image.pop();
    let before = changed.clone();
    assert!(changed.queue_recovery(ticket, Recovery::Rollback).is_err());
    assert_eq!(changed, before);
    let mut changed = medium.clone();
    changed.journal[0] ^= 1;
    let before = changed.clone();
    assert!(changed.queue_recovery(ticket, Recovery::Resume).is_err());
    assert_eq!(changed, before);
    // Re-encoding a different plan gives a valid internal checksum but must
    // still fail against the original immutable manifest's journal digest.
    let mut journal = Journal::decode(&medium.journal, ticket).unwrap();
    journal.writes[0].after[0] = 100;
    let mut changed = medium;
    changed.journal = journal.encode();
    let before = changed.clone();
    assert!(changed.queue_recovery(ticket, Recovery::Resume).is_err());
    assert_eq!(changed, before);
}

#[test]
fn any_persisted_handoff_marker_closes_rollback_before_a_writable_mount() {
    let (mut medium, ticket, source, target) = prepared();
    assert!(medium.start_handoff(ticket).is_err());
    medium.queue_recovery(ticket, Recovery::Resume).unwrap();
    assert!(medium.start_handoff(ticket).is_err());
    medium.flush_data();
    medium.start_handoff(ticket).unwrap();
    assert!(!medium.writable_mount_allowed(ticket));
    for prefix in 0..=medium.pending_handoff.len() {
        let mut crashed = medium.clone().crash(&[], &[], 0, prefix);
        if prefix == 0 {
            // The mount was never allowed before the marker flush completed.
            assert!(!crashed.writable_mount_allowed(ticket));
            recover_and_check(crashed, ticket, Recovery::Rollback, &source);
        } else {
            let before = crashed.clone();
            assert!(crashed.queue_recovery(ticket, Recovery::Rollback).is_err());
            assert_eq!(crashed, before);
            assert!(crashed.queue_recovery(ticket, Recovery::Resume).is_err());
            assert_eq!(crashed, before);
            assert_eq!(
                crashed.writable_mount_allowed(ticket),
                prefix == medium.pending_handoff.len()
            );
        }
    }
    medium.flush_handoff();
    assert!(medium.writable_mount_allowed(ticket));
    assert_eq!(medium.image, target);
    medium.start_handoff(ticket).unwrap();
    medium.flush_handoff(); // Idempotent finalization.
    // Native filesystem activity is permitted only after this boundary. The
    // journal must never restore earlier NTFS bytes over these new writes.
    medium.image[0] = 250;
    let before = medium.clone();
    assert!(medium.queue_recovery(ticket, Recovery::Rollback).is_err());
    assert_eq!(medium, before);
}
